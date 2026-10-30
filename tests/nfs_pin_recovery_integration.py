#!/usr/bin/env python3
"""Recover durable NFS retention at interrupted link/create/remove boundaries."""
import argparse
import json
import os
from pathlib import Path
import sqlite3

from m7_integration import Client, op
from pynfs_acceptance import fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sanitizers', action='store_true')
    args = parser.parse_args()
    f, port = fixture(args.bin, 512 if args.sanitizers else 256)
    clients, checks = [], []
    try:
        c = Client(port); clients.append(c); c.session()
        root = c.root()
        handles = {}
        for name in ('before-unlink', 'before-link', 'after-reap'):
            state, handle = c.open(root, name.encode(), True, owner=name.encode())
            result = c.compound([op.putfh(handle), op.write(state, 0, 2, name.encode())])
            assert result.status == 0, result
            result = c.compound([op.putfh(root), op.remove(name.encode())])
            assert result.status == 0, result
            handles[name] = handle
        owner = c.owner
        c.close(); f.stop()
        with sqlite3.connect(f.state / 'file.nfs.db') as db:
            records = [(token, json.loads(body)) for token, body in db.execute('SELECT token,body FROM retained')]
            assert len(records) == 3
            for token, body in records:
                pin = f.root / 'nfsdata' / body['pin']
                original = f.root / 'nfsdata' / body['path']
                if body['path'] in ('before-unlink', 'before-link'):
                    os.link(pin, original)
                    if body['path'] == 'before-link':
                        pin.unlink()
                else:
                    body['reaping'] = True
                    db.execute('UPDATE retained SET body=? WHERE token=?', (json.dumps(body), token))
                    pin.unlink()
            db.commit()
        f.start()
        c = Client(port); clients.append(c); c.session(owner, reclaim=True)
        for name in ('before-unlink', 'before-link'):
            state, handle = c.open(handles[name], b'', claim=1, owner=name.encode())
            result = c.compound([op.putfh(handle), op.read(state, 0, 1024)])
            assert result.status == 0 and result.resarray[-1].opread.resok4.data == name.encode(), result
            assert (f.root / 'nfsdata' / name).read_bytes() == name.encode()
            result = c.compound([op.putfh(handle), op.close(0, state)])
            assert result.status == 0, result
        result = c.compound([op.reclaim_complete(False)])
        assert result.status == 0, result
        result = c.compound([op.putfh(handles['after-reap']), op.getattr([2])])
        assert result.status == 70, result
        assert not list((f.root / 'nfsdata').glob('.tc-nfs-*'))
        with sqlite3.connect(f.state / 'file.nfs.db') as db:
            assert db.execute('SELECT count(*) FROM retained').fetchone()[0] == 0
        checks.extend(['journal before private link creation preserves original file and handle',
                       'private link before unlink is rolled back without deleting original data',
                       'interrupted final reaping completes idempotently and leaves old handle STALE'])
        report = dict(status='passed', checks=checks)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    finally:
        for c in clients: c.close()
        f.close()


if __name__ == '__main__':
    main()
