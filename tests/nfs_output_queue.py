#!/usr/bin/env python3
"""Linux TCP backpressure: callbacks overtake queued complete data replies."""
import argparse
import datetime
import json
from pathlib import Path
import socket
import struct
import time
import traceback
import xdrlib3 as xdr
from m7_integration import op, t3, t4
from nfs_backchannel_integration import CallbackClient
from pynfs_acceptance import fixture


def queued_bytes(port, peer):
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        row = line.split()
        if int(row[1].split(':')[1], 16) == port and int(row[2].split(':')[1], 16) == peer:
            assert row[3] == '01', ('transport no longer established', row)
            return int(row[4].split(':')[0], 16)
    raise AssertionError('test TCP transport disappeared')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--sanitizers', action='store_true')
    args = p.parse_args()
    report = dict(status='failed', checks=[], recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    f = c = None
    try:
        f, port = fixture(args.bin, 1024 if args.sanitizers else 256)
        c = CallbackClient(port); c.establish(); c.path(True)
        assert c.compound([op.reclaim_complete(False)]).status == 0
        state, handle = c.open(c.root(), b'output-pressure', create=True)
        payload = bytes(range(256)) * 256
        assert c.compound([op.putfh(handle), op.write(state, 0, 2, payload)]).status == 0
        c.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
        peer = c.sock.getsockname()[1]
        reads = set()
        def send_read():
            packet = c.v3('READ', t3.READ3args(t3.nfs_fh3(handle), 0, len(payload)), 6, True)
            reads.add(struct.unpack_from('>I', packet)[0]); c.frame(packet)
        samples = []; stable = 0
        for _ in range(64):
            send_read(); time.sleep(.04)
            size = queued_bytes(port, peer)
            stable = stable + 1 if samples and size >= 131072 and abs(size - samples[-1]) < 1024 else 0
            samples.append(size)
            if stable >= 3: break
        assert stable >= 3, ('could not establish bounded TCP backpressure', samples)
        # Stop before exhausting the application queue. More completed data
        # responses now wait behind a partial frame in the single writer.
        for _ in range(3): send_read()
        time.sleep(.15)
        packet = c.compound([op.backchannel_ctl(c.program, [t4.callback_sec_parms4(0)])], packet_only=True)
        control = struct.unpack_from('>I', packet)[0]
        c.frame(packet); time.sleep(.1)
        c.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
        report['kernel_send_queue_samples'] = samples
        report['read_count'] = len(reads)
        callbacks = []
        deadline = time.monotonic() + 15
        def read(count):
            data = b''
            while len(data) < count:
                assert time.monotonic() < deadline, 'bounded drain deadline exceeded'
                c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
                part = c.sock.recv(count - len(data)); assert part, 'connection closed with pending frames'
                data += part
            return data
        while reads or control is not None:
            data = b''
            while True:
                marker, = struct.unpack('>I', read(4))
                assert 0 < marker & 0x7fffffff <= 262144
                data += read(marker & 0x7fffffff)
                if marker >> 31: break
            r = xdr.Unpacker(data); xid, direction = r.unpack_uint(), r.unpack_uint()
            if direction == 0:
                assert (r.unpack_uint(), r.unpack_uint(), r.unpack_uint()) == (2, c.program, 1)
                procedure = r.unpack_uint()
                assert r.unpack_uint() == 0 and r.unpack_bytes() == b''
                assert r.unpack_uint() == 0 and r.unpack_bytes() == b''
                callbacks.append(len(reads))
                if procedure == 0:
                    r.done(); c.probes.append(xid); c.acknowledge(xid)
                else:
                    assert procedure == 1
                    c.receive_sequence(xid, r)
                continue
            assert direction == 1 and r.unpack_uint() == 0
            assert r.unpack_uint() == 0 and r.unpack_bytes() == b'' and r.unpack_uint() == 0
            body = data[r.get_position():]
            if xid == control:
                assert c.decode4(body).status == 0; control = None
            else:
                assert xid in reads; reads.remove(xid)
                result = c.decode3('READ', body)
                assert result.status == 0 and result.resok.data == payload, result
        assert callbacks and callbacks[0] > 0, ('callback did not overtake queued data', callbacks)
        c.path(True)
        report['reads_remaining_at_callbacks'] = callbacks
        report['checks'].append('real TCP backpressure permits a callback before queued data replies, with intact payloads and a healthy path')
        report['status'] = 'passed'
        print('PASS real TCP output callback priority', flush=True)
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
    finally:
        if c: c.close()
        if f: f.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
