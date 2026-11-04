#!/usr/bin/env python3
"""Advertised NFS lease, SEQUENCE renewal, expiry and lease-change recovery."""
import argparse
import datetime
import json
from pathlib import Path
import sqlite3
import struct
import time
import traceback

from m7_integration import Client, op, t4
from pynfs_acceptance import fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sanitizers', action='store_true')
    args = parser.parse_args()
    f, port = fixture(args.bin, 1024 if args.sanitizers else 256)
    clients = []
    report = dict(status='failed', checks=[], recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())

    def passed(text):
        report['checks'].append(text); print('PASS ' + text, flush=True)

    def client():
        c = Client(port); clients.append(c); c.session(); return c

    def call(c, operations, status=0):
        r = c.compound(operations)
        assert r.status == status, r
        return r

    def lease(c, root):
        r = call(c, [op.putfh(root), op.getattr([1 << 10])])
        attr = r.resarray[-1].opgetattr.resok4.obj_attributes
        assert attr.attrmask == [1 << 10], attr
        return struct.unpack('>I', attr.attr_vals)[0]

    def restart(seconds):
        for c in clients: c.close()
        clients.clear()
        f.stop()
        config = json.loads((f.state/'config.json').read_text())
        config['nfs_lease_seconds'] = seconds
        (f.state/'config.json').write_text(json.dumps(config))
        f.start()

    def opening(c, root, name):
        return [op.putfh(root), op.open(0, 3, 0, t4.open_owner4(c.cid, b'lease-owner'),
                t4.openflag4(1, t4.createhow4(0, t4.fattr4([], b''))), t4.open_claim4(0, file=name)), op.getfh()]

    try:
        c = client(); root = c.root()
        assert lease(c, root) == 60
        restart(5)
        c = client(); root = c.root()
        assert lease(c, root) == 5
        state, handle = c.open(root, b'lease-expiry', create=True)
        time.sleep(3)
        call(c, [op.putfh(handle), op.read(state, 0, 1)])
        time.sleep(3)
        call(c, [op.putfh(handle), op.read(state, 0, 1)])
        passed('default lease is 60 seconds; configured five-second lease is advertised and SEQUENCE renews OPEN beyond its initial expiry')
        time.sleep(5.3)
        call(c, [op.putfh(handle), op.read(state, 0, 1)], 10052)
        fresh = client()
        call(fresh, [op.putfh(handle), op.read(state, 0, 1)], 10025)
        r = call(fresh, opening(fresh, root, b'lease-expiry'))
        fresh_state = r.resarray[2].opopen.resok4.stateid
        call(fresh, [op.putfh(handle), op.close(0, fresh_state)])
        passed('idle session and OPEN expire at the advertised lease; another client opens the file while the expired stateid remains invalid')

        restart(9)
        owner = client(); root = owner.root()
        _, retained = owner.open(root, b'old-lease-recovery', create=True)
        restart(5)
        # Read persisted state without changing it. A second restart must not
        # lose the old advertised lease while its reclaim records remain.
        with sqlite3.connect(f.state/'nfs.db') as db:
            assert db.execute('SELECT seconds FROM lease_history WHERE id=1').fetchone() == (9,)
        restart(5)
        started = time.monotonic()
        with sqlite3.connect(f.state/'nfs.db') as db:
            assert db.execute('SELECT seconds FROM lease_history WHERE id=1').fetchone() == (9,)
        contender = client()
        assert lease(contender, root) == 5
        call(contender, opening(contender, root, b'after-grace'), 10013)
        # Keep the contender's five-second session live while testing the
        # inherited nine-second recovery window independently.
        while time.monotonic() - started < 6:
            time.sleep(1)
            call(contender, [op.putfh(retained), op.getattr([1 << 10])])
        call(contender, opening(contender, root, b'after-grace'), 10013)
        while time.monotonic() - started < 10:
            time.sleep(1)
            call(contender, [op.putfh(retained), op.getattr([1 << 10])])
        r = call(contender, opening(contender, root, b'after-grace'))
        call(contender, [op.putfh(r.resarray[3].opgetfh.resok4.object),
                         op.close(0, r.resarray[2].opopen.resok4.stateid)])
        with sqlite3.connect(f.state/'nfs.db') as db:
            assert db.execute('SELECT seconds FROM lease_history WHERE id=1').fetchone() == (5,)
        passed('reducing the lease preserves the old reclaim window across repeated restarts, then converges to the configured duration after grace')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        report['worker_logs'] = {role: path.read_text(errors='replace')[-12000:] for role in ('nfs', 'file')
            if (path := f.state/'logs'/(role+'.jsonl')).exists()}
    finally:
        for c in clients: c.close()
        f.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2)+'\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(main())
