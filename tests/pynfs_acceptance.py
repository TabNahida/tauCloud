#!/usr/bin/env python3
"""Run upstream tests against a disposable export; retain failures and raw output."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from m3_integration import Fixture

ROOT = Path(__file__).resolve().parents[1]

def fixture(binary):
    f = Fixture(binary)
    try:
        f.stop()
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        cfg = json.loads((f.state / 'config.json').read_text())
        cfg['nfs_port'] = port
        (f.state / 'config.json').write_text(json.dumps(cfg))
        f.start()
        f.api('spaces', f.admin, dict(id='nfsdata', root='data', path='nfsdata', owner='alice', quota=2**31))
        f.api('shares', f.admin, dict(id='nfs', space='nfsdata', exposures={'nfs':'rw'}))
        f.api('groups', f.admin, dict(name='unix'))
        f.api('memberships', f.admin, dict(username='alice', group='unix'))
        (f.root / 'nfsdata/tmp').mkdir()
        (f.root / 'nfsdata/tree/dir').mkdir(parents=True)
        (f.root / 'nfsdata/tree/file').write_bytes(b'This is a test file.\n')
        f.api('nfs-exports', f.admin, dict(id='nfs', trust='loopback-auth-sys', anonymous='bob',
                                          uids={'1000':'alice'},
                                          gids={str(g):'unix' for g in (1000,3,17,100)}))
        return f, port
    except Exception:
        f.close()
        raise

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('selectors', nargs='+')
    args = p.parse_args()
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    f, port = fixture(args.bin)
    try:
        command = [sys.executable, '-u', 'testserver.py', f'127.0.0.1:{port}/nfs',
                   '--minorversion=1', '--uid=1000', '--gid=1000', '--noinit', '--nocleanup',
                   '--jsonout', str(args.output), '--verbose'] + args.selectors
        with args.output.with_suffix('.log').open('w') as log:
            result = subprocess.run(command, cwd=ROOT / 'build/pynfs/nfs4.1',
                                    stdout=log, stderr=subprocess.STDOUT, text=True, timeout=900)
        print(args.output.with_suffix('.log').read_text())
        # The upstream runner does not always communicate failed tests via its exit code.
        if not args.output.exists():
            return result.returncode or 1
        report = json.loads(args.output.read_text())
        print(json.dumps({k:v for k,v in report.items() if k != 'testcase'}, indent=2))
        return result.returncode or int(report.get('failures', 0) != 0 or report.get('errors', 0) != 0)
    finally:
        f.close()

if __name__ == '__main__':
    raise SystemExit(main())
