#!/usr/bin/env python3
"""A timely TCP callback reply delayed by file IPC must retain its probe."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
import os
from pathlib import Path
import signal
import socket
import time
import traceback

from m7_integration import Client, op
from nfs_admission_queue import ObservedSocket
from nfs_backchannel_integration import CallbackClient
from pynfs_acceptance import fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--sanitizers', action='store_true')
    args = parser.parse_args()
    report = dict(status='failed', checks=[], recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    f = None
    clients = []
    stopped = None
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        assert os.name == 'posix', 'Fault injection suspends only the disposable Linux file worker'
        f, port = fixture(args.bin, 1024 if args.sanitizers else 256)
        f.stop()
        config = json.loads((f.state / 'config.json').read_text())
        config['nfs_lease_seconds'] = 5
        (f.state / 'config.json').write_text(json.dumps(config))
        f.start()
        report['timing_seconds'] = {}
        for case in ('valid', 'malformed', 'wrong-xid', 'wrong-transport', 'late'):
            first_client = len(clients)
            blocker = Client(port); clients.append(blocker); blocker.session()
            state, handle = blocker.open(blocker.root(), ('callback-queue-' + case).encode(), create=True)
            callback = CallbackClient(port); clients.append(callback)
            callback.hold_sequence = True
            callback.establish(); callback.sequence_count(1)
            started = time.monotonic()
            identity = f.ctl('status')['file']['identity']
            file_pid = identity['pid']
            assert file_pid != os.getpid()
            blocker.sock = ObservedSocket(blocker.sock)
            time.sleep(max(0, started + 3.6 - time.monotonic()))
            os.kill(file_pid, signal.SIGSTOP); stopped = file_pid
            pending = pool.submit(blocker.compound, [op.putfh(handle), op.read(state, 0, 1)])
            assert blocker.sock.sent.wait(1)
            time.sleep(.2)
            if case == 'late':
                time.sleep(max(0, started + 5.2 - time.monotonic()))
            if case == 'malformed': callback.acknowledge_sequence(body=b'invalid')
            elif case == 'wrong-xid':
                xid, _, result = callback.sequences[-1]
                callback.acknowledge((xid + 100) & 0xffffffff, result)
            elif case == 'wrong-transport':
                alien = CallbackClient(port); clients.append(alien)
                xid, _, result = callback.sequences[-1]
                alien.acknowledge(xid, result)
            else: callback.acknowledge_sequence()
            sent = time.monotonic() - started
            assert sent >= 5.2 if case == 'late' else sent < 4.8, ('unexpected callback send time', case, sent)
            time.sleep(max(0, started + 5.5 - time.monotonic()))
            assert not pending.done(), 'file worker fault did not hold dispatch'
            os.kill(file_pid, signal.SIGCONT); stopped = None
            pending.result(timeout=12)
            if case == 'valid':
                flags = callback.flags()
                assert not flags & (1 | 512 | 1024), flags
                assert len(callback.sequences) == 1, 'timely successful callback was retried'
            else:
                # Unknown or late replies need not close a transport whose
                # client/session has already expired. Confirm reader teardown
                # before probing that session, so the probe cannot itself use
                # an in-flight unauthenticated arrival to renew its lease.
                if case != 'malformed':
                    try: callback.sock.shutdown(socket.SHUT_WR)
                    except OSError: pass
                callback.wait_closed()
                stale = Client(port); clients.append(stale)
                stale.sid, stale.seq = callback.sid, callback.seq
                result = stale.compound([])
                assert result.status == 10052, ('invalid callback renewed expired session', case, result)
            assert f.ctl('status')['file']['identity'] == identity
            report['timing_seconds'][case] = dict(sent_after_probe=sent, processed_after_probe=time.monotonic() - started)
            report['checks'].append('timely CB_SEQUENCE reply survives delayed dispatch without retry or disconnect' if case == 'valid' else case + ' callback reply cannot validate the path or renew an expired session')
            print('PASS callback queue ' + case, flush=True)
            for c in clients[first_client:]: c.close()
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
    finally:
        if stopped is not None:
            try: os.kill(stopped, signal.SIGCONT)
            except ProcessLookupError: pass
        pool.shutdown(wait=True)
        for c in clients: c.close()
        if f:
            f.log.flush()
            report['server_log'] = (f.base / 'supervisor.log').read_text(errors='replace')[-65536:]
            f.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
