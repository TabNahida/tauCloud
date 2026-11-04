#!/usr/bin/env python3
"""Exercise CB_NOTIFY_LOCK with the pinned, unmodified pynfs RPC/client stack."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]


def exercise(port):
    sys.path.insert(0, str(ROOT / 'build/pynfs/nfs4.1'))
    from nfs4client import NFS4Client
    from nfs4lib import check
    from nfs_ops import NFS4ops
    from rpc.security import AuthSys
    from xdrdef import nfs4_type as t
    op = NFS4ops()
    c = NFS4Client(b'127.0.0.1', port, minorversion=1)
    c.set_cred(AuthSys().init_cred(uid=1000, gid=1000, name=b'notify-lock-client'))
    try:
        a = c.new_client_session(b'holder-' + uuid.uuid4().hex.encode())
        b = c.new_client_session(b'waiter-' + uuid.uuid4().hex.encode())
        event = threading.Event(); received = []
        def notified(arg, env):
            received.append((arg.cnla_fh, arg.cnla_lock_owner.clientid, arg.cnla_lock_owner.owner))
            event.set()
        b.client.cb_pre_hook(13, notified)
        def opened(session, create):
            how = t.openflag4(1, t.createhow4(1, t.fattr4([], b''))) if create else t.openflag4(0)
            result = session.compound([op.putrootfh(), op.lookup(b'nfs'),
                        op.open(0, 3, 0, t.open_owner4(0, b'owner'), how, t.open_claim4(0, file=b'pynfs-notify')), op.getfh()])
            check(result)
            assert result.resarray[-2].rflags & 0x20
            return result.resarray[-2].stateid, result.resarray[-1].object
        sa, handle = opened(a, True); sb, same = opened(b, False); assert handle == same
        def lock(session, state, owner, kind, expected=0):
            locker = t.locker4(True, open_owner=t.open_to_lock_owner4(0, state, 0, t.lock_owner4(0, owner)))
            result = session.compound([op.putfh(handle), op.lock(kind, False, 0, 10, locker)])
            check(result, expected)
            return result.resarray[-1].lock_stateid if expected == 0 else None
        held = lock(a, sa, b'holding-lock', 2)
        lock(b, sb, b'waiting-lock', 4, 10010)
        check(a.compound([op.putfh(handle), op.locku(2, 0, held, 0, 10)]))
        assert event.wait(5), 'pynfs did not receive CB_NOTIFY_LOCK'
        assert received == [(handle, b.client.clientid, b'waiting-lock')], received
        acquired = lock(b, sb, b'waiting-lock', 4)
        check(b.compound([op.putfh(handle), op.locku(2, 0, acquired, 0, 10)]))
        check(a.compound([op.putfh(handle), op.close(0, sa)]))
        check(b.compound([op.putfh(handle), op.close(0, sb)]))
        print('pynfs CB_NOTIFY_LOCK and explicit LOCK acquisition passed', flush=True)
    finally:
        c.stop()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path); p.add_argument('--output', type=Path)
    p.add_argument('--sanitizers', action='store_true'); p.add_argument('--port', type=int)
    args = p.parse_args()
    if args.port:
        exercise(args.port); return
    from pynfs_acceptance import fixture
    f, port = fixture(args.bin, 1024 if args.sanitizers else 256)
    try:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--port', str(port)],
                                cwd=ROOT / 'build/pynfs/nfs4.1', stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.with_suffix('.log').write_text(result.stdout)
        print(result.stdout)
        report = dict(status='passed' if result.returncode == 0 else 'failed',
                      client='pinned linux-nfs/pynfs unmodified RPC and NFS4Client implementation',
                      scope='custom scenario; not the full upstream callback test suite',
                      checks=['CB_NOTIFY_LOCK decoded and acknowledged by pynfs; matching handle/client/owner; explicit retry acquires the lock'],
                      sanitizers=args.sanitizers)
        args.output.write_text(json.dumps(report, indent=2)+'\n')
        if result.returncode: raise SystemExit(result.returncode)
    finally:
        f.close()


if __name__ == '__main__': main()
