#!/usr/bin/env python3
"""Real TCP NFS deadline responses and client retry after a paused file worker."""
import argparse
import datetime
import json
import os
from pathlib import Path
import signal
import threading
import time
import traceback
from m7_integration import Client, op, t3
from nfs_lease_lifetime import recovery_open
from pynfs_acceptance import fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--sanitizers', action='store_true')
    args = parser.parse_args()
    report = dict(status='failed', checks=[], recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    f = c = resume = None
    try:
        f, port = fixture(args.bin, 1024 if args.sanitizers else 256)
        c = Client(port); c.session(); root = c.root()
        identity = f.ctl('status')['file']['identity']
        pid = identity['pid']; assert pid != os.getpid()
        nfs_identity = f.ctl('status')['nfs']['identity']
        report['pause_outcomes'] = []

        def pause():
            pid = f.ctl('status')['file']['identity']['pid']
            assert pid != os.getpid()
            os.kill(pid, signal.SIGSTOP)
            def release():
                try:
                    os.kill(pid, signal.SIGCONT)
                    report['pause_outcomes'].append('resumed')
                except ProcessLookupError:
                    report['pause_outcomes'].append('worker terminated by watchdog')
            timer = threading.Timer(4.3, release)
            try: timer.start()
            except Exception:
                release()
                raise
            return timer

        attempts = report['open_attempts'] = []
        resume = pause()
        started = time.monotonic()
        state, handle = recovery_open(c, root, b'deadline-recovery', attempts)
        resume.join(); resume = None
        report['open_elapsed_seconds'] = time.monotonic() - started
        assert len(attempts) >= 2 and attempts[0]['status'] == 10008 and attempts[-1]['status'] == 0, attempts
        assert all(b['sequence'] == a['sequence'] + 1 for a, b in zip(attempts, attempts[1:])), attempts
        assert c.compound([op.putfh(handle), op.close(0, state)]).status == 0
        report['checks'].append('real file-worker stall returns DELAY; bounded client retries with fresh SEQUENCE values create and close the file')

        resume = pause()
        result = c.v3('GETATTR', t3.GETATTR3args(t3.nfs_fh3(handle)), 1)
        assert result.status == 10008, result
        resume.join(); resume = None
        statuses = report['v3_retries'] = []
        for attempt in range(5):
            result = c.v3('GETATTR', t3.GETATTR3args(t3.nfs_fh3(handle)), 1)
            statuses.append(result.status)
            if result.status == 0: break
            assert result.status == 10008 and attempt < 4, result
            time.sleep(min(2, .5 * 2**attempt))
        assert result.resok.obj_attributes.size == 0, result
        report['checks'].append('real file-worker stall returns NFSv3 JUKEBOX; a bounded new-transaction retry succeeds after recovery')
        assert f.ctl('status')['nfs']['identity'] == nfs_identity
        report['file_worker_replaced'] = f.ctl('status')['file']['identity'] != identity
        report['checks'].append('the same NFS worker and session remain usable across file-worker stalls or watchdog replacement')
        report['status'] = 'passed'
        for check in report['checks']: print('PASS ' + check, flush=True)
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
    finally:
        if resume: resume.join()
        if f:
            path = f.state / 'logs/nfs.jsonl'
            if path.exists():
                report['deadline_events'] = [json.loads(line) for line in path.read_text().splitlines()
                                             if 'deadline_exceeded' in line]
                report['nfs_events'] = [json.loads(line) for line in path.read_text().splitlines()]
        if c: c.close()
        if f: f.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
