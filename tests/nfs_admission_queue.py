#!/usr/bin/env python3
"""Real TCP lease retention while both NFS executor workers are occupied."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
import os
from pathlib import Path
import signal
import struct
import threading
import time
import traceback

from m7_integration import Client, op
from pynfs_acceptance import fixture
import xdrlib3 as xdr


def receive_replies(client, count):
    def read(size):
        data = b''
        while len(data) < size:
            part = client.sock.recv(size - len(data))
            assert part, 'connection closed with outstanding RPCs'
            data += part
        return data
    replies = {}
    for _ in range(count):
        data = b''
        while True:
            marker, = struct.unpack('>I', read(4))
            data += read(marker & 0x7fffffff)
            if marker >> 31: break
        response = xdr.Unpacker(data)
        xid = response.unpack_uint()
        assert response.unpack_uint() == 1 and response.unpack_uint() == 0
        assert response.unpack_uint() == 0 and response.unpack_bytes() == b''
        assert response.unpack_uint() == 0 and xid not in replies
        replies[xid] = client.decode4(data[response.get_position():])
    return replies


class ObservedSocket:
    def __init__(self, sock):
        self.sock = sock
        self.sent = threading.Event()
        self.sent_at = None

    def sendall(self, data):
        self.sock.sendall(data)
        self.sent_at = time.monotonic()
        self.sent.set()

    def __getattr__(self, name):
        return getattr(self.sock, name)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--sanitizers', action='store_true')
    args = p.parse_args()
    report = dict(status='failed', checks=[], recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    f = None
    clients = []
    stopped = None
    pool = ThreadPoolExecutor(max_workers=3)
    try:
        assert os.name == 'posix', 'This fixture uses SIGSTOP only on its own disposable Linux file worker'
        f, port = fixture(args.bin, 1024 if args.sanitizers else 256)
        f.stop()
        config = json.loads((f.state / 'config.json').read_text())
        config['nfs_lease_seconds'] = 5
        (f.state / 'config.json').write_text(json.dumps(config))
        f.start()
        for _ in range(3):
            c = Client(port)
            clients.append(c)
            c.session()
        blocker, waiting, queued = clients
        root = blocker.root()
        blocker_state, handle = blocker.open(root, b'arrival-queue', create=True)
        write = blocker.compound([op.putfh(handle), op.write(blocker_state, 0, 2, b'queue-data')])
        assert write.status == 0, write
        state, queued_handle = queued.open(queued.root(), b'arrival-queue')
        renewed = time.monotonic()
        # Read the process identity before suspension. A restarted worker must
        # fail this test rather than silently changing the fault being tested.
        identity = f.ctl('status')['file']['identity']
        file_pid = identity['pid']
        assert file_pid != os.getpid()
        for c in clients:
            c.sock = ObservedSocket(c.sock)
        time.sleep(max(0, renewed + 3.6 - time.monotonic()))
        os.kill(file_pid, signal.SIGSTOP)
        stopped = file_pid
        first = pool.submit(blocker.compound, [op.putfh(handle), op.read(blocker_state, 0, 10)])
        assert blocker.sock.sent.wait(1)
        time.sleep(.2)
        second = pool.submit(waiting.compound, [])
        assert waiting.sock.sent.wait(1)
        time.sleep(.2)
        third = pool.submit(queued.compound, [op.putfh(queued_handle), op.read(state, 0, 10)])
        assert queued.sock.sent.wait(1)
        sent = queued.sock.sent_at - renewed
        assert sent < 4.8, ('request was sent too late to test pre-expiry receipt', sent)
        # Let the original five-second lease pass while the first worker is in
        # file IPC, the second waits for the protocol mutex and the third queues.
        time.sleep(max(0, renewed + 5.5 - time.monotonic()))
        assert not first.done() and not second.done() and not third.done(), 'fault did not hold all requests'
        os.kill(file_pid, signal.SIGCONT)
        stopped = None
        results = [future.result(timeout=12) for future in (first, second, third)]
        elapsed = time.monotonic() - renewed
        # The deliberately delayed file grant may expire, but SEQUENCE must
        # still succeed. The queued client's fresh file grant must read its OPEN.
        assert all(r.resarray[0].opsequence.sr_status == 0 for r in results), results
        assert results[0].status in (0, 13), results[0]
        assert results[1].status == 0 and results[2].status == 0, results
        assert results[2].resarray[-1].opread.resok4.data == b'queue-data', results[2]
        assert elapsed > 5.2
        assert f.ctl('status')['file']['identity'] == identity
        report['timing_seconds'] = dict(queued_send_after_renewal=sent, completion_after_renewal=elapsed)
        report['checks'].append('complete TCP request reaches the bounded executor before lease expiry and retains OPEN beyond expiry while both workers are occupied')
        report['checks'].append('successful SEQUENCE renews after the delay; queued READ returns original data; suspended file worker was not replaced')
        print('PASS real TCP executor queue preserves the received-before-expiry OPEN', flush=True)
        pipeline = Client(port); clients.append(pipeline); pipeline.session()
        pipeline_state, pipeline_handle = pipeline.open(pipeline.root(), b'arrival-queue')
        renewed = time.monotonic()
        next_sequence = pipeline.seq + 1
        invalid = pipeline.compound([], packet_only=True, seq=next_sequence + 100)
        valid = pipeline.compound([op.putfh(pipeline_handle), op.read(pipeline_state, 0, 10)],
                                  packet_only=True, seq=next_sequence)
        frame = lambda packet: struct.pack('>I', 0x80000000 | len(packet)) + packet
        # The invalid request cannot renew this client's lease. Its executor
        # wait must not stop the reader from registering the following record.
        time.sleep(max(0, renewed + 3.6 - time.monotonic()))
        blocker.sock.sent.clear()
        os.kill(file_pid, signal.SIGSTOP); stopped = file_pid
        first = pool.submit(blocker.compound, [op.putfh(handle), op.read(blocker_state, 0, 10)])
        assert blocker.sock.sent.wait(1)
        time.sleep(.2)
        pipeline.sock.sendall(frame(invalid) + frame(valid))
        sent = time.monotonic() - renewed
        assert sent < 4.8
        pipelined = pool.submit(receive_replies, pipeline, 2)
        time.sleep(max(0, renewed + 5.5 - time.monotonic()))
        assert not first.done() and not pipelined.done()
        os.kill(file_pid, signal.SIGCONT); stopped = None
        first.result(timeout=12)
        results = pipelined.result(timeout=12)
        bad = results[struct.unpack_from('>I', invalid)[0]]
        good = results[struct.unpack_from('>I', valid)[0]]
        assert bad.status == 10063, bad
        assert good.status == 0, good
        assert good.resarray[-1].opread.resok4.data == b'queue-data', good
        assert f.ctl('status')['file']['identity'] == identity
        report['pipeline_timing_seconds'] = dict(sent_after_renewal=sent,
                                                completion_after_renewal=time.monotonic() - renewed)
        report['checks'].append('two records on one TCP connection are admitted before expiry while the first waits; failed SEQUENCE cannot renew the following READ')
        print('PASS pipelined TCP receipt retains OPEN behind a non-renewing invalid SEQUENCE', flush=True)
        flooded = Client(port); clients.append(flooded); flooded.session()
        packets = [flooded.compound([], packet_only=True, seq=flooded.seq + 100) for _ in range(17)]
        blocker.sock.sent.clear()
        os.kill(file_pid, signal.SIGSTOP); stopped = file_pid
        first = pool.submit(blocker.compound, [op.putfh(handle), op.read(blocker_state, 0, 10)])
        assert blocker.sock.sent.wait(1)
        time.sleep(.2)
        flooded.sock.sendall(b''.join(map(frame, packets)))
        flooded.sock.settimeout(3)
        try:
            assert flooded.sock.recv(1) == b'', 'overflow produced a reply while the protocol executor was blocked'
        except ConnectionResetError:
            pass
        os.kill(file_pid, signal.SIGCONT); stopped = None
        first.result(timeout=12)
        deadline = time.monotonic() + 5
        while True:
            probe = Client(port); clients.append(probe)
            try:
                probe.session()
                fresh_state, fresh_handle = probe.open(probe.root(), b'arrival-queue')
                result = probe.compound([op.putfh(fresh_handle), op.read(fresh_state, 0, 10)])
                assert result.status == 0 and result.resarray[-1].opread.resok4.data == b'queue-data', result
                break
            except (AssertionError, OSError):
                probe.close()
                if time.monotonic() >= deadline: raise
                time.sleep(.05)
        assert f.ctl('status')['file']['identity'] == identity
        report['checks'].append('blocked pipeline overflow closes only its transport, abandons queued admissions and recovers capacity for a fresh authenticated OPEN/READ')
        print('PASS bounded pipeline overflow drains queued requests and preserves service availability', flush=True)
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc()
        print(report['error'], flush=True)
    finally:
        if stopped is not None:
            try: os.kill(stopped, signal.SIGCONT)
            except ProcessLookupError: pass
        pool.shutdown(wait=True)
        for c in clients:
            c.close()
        if f:
            f.log.flush()
            report['server_log'] = (f.base / 'supervisor.log').read_text(errors='replace')[-65536:]
            f.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
