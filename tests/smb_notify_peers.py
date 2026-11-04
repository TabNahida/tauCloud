#!/usr/bin/env python3
"""Pending notification boundaries for back-to-back mutations on other transports."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import struct
import traceback
import uuid

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import SMB2SetInfoRequest
from m5_integration import Fixture, create
from smb_notify_integration import notify, events


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true'); a = p.parse_args()
    f = None; clients = []; report = dict(status='failed', checks=[])
    def passed(text): report['checks'].append(text); print('PASS ' + text, flush=True)
    def connect(dialect):
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        c.connect(dialect=dialect); clients.append(c)
        s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=dialect >= 0x300, auth_protocol='ntlm')
        s.connect(); t = TreeConnect(s, '\\\\127.0.0.1\\smb'); t.connect()
        return c, s, t
    def change(c, s, t, handles, value):
        requests = []
        for h in handles:
            q = SMB2SetInfoRequest(); q['info_type'] = 1; q['file_info_class'] = 4
            q['file_id'] = h.file_id; q['buffer'] = struct.pack('<QQQQII', 0, 0, 0, 0, value, 0)
            # Separate frames already queued before waiting for either result.
            requests.append(c.send(q, s.session_id, t.tree_connect_id))
        for r in requests: c.receive(r, timeout=15)
    try:
        f = Fixture(a.bin, 512 if a.sanitizers else 256)
        ca, sa, ta = connect(0x311); cb, sb, tb = connect(0x210)
        da = create(ta, 'peer-a', options=1, access=0x120089)
        db = create(tb, 'peer-b', options=1, access=0x120089)
        ha = [create(tb, 'peer-a/'+name) for name in ('a', 'b')]
        hb = [create(ta, 'peer-b/'+name) for name in ('a', 'b')]
        for i in range(20):
            first = notify(da, 4); second = notify(da, 4)
            change(cb, sb, tb, ha, 2 if i % 2 == 0 else 4)
            result = events(ca, first)
            assert result == [(3, 'a')], (i, result)
            assert events(ca, second) == [(3, 'b')]
        passed('twenty back-to-back signed mutation pairs complete separate encrypted pending notifications on another transport without merging later frames')

        with ThreadPoolExecutor(max_workers=2) as pool:
            for i in range(12):
                qa = [notify(da, 4), notify(da, 4)]
                qb = [notify(db, 4), notify(db, 4)]
                value = 2 if i % 2 == 0 else 4
                left = pool.submit(change, ca, sa, ta, hb, value)
                right = pool.submit(change, cb, sb, tb, ha, value)
                left.result(timeout=20); right.result(timeout=20)
                for c, requests in ((ca, qa), (cb, qb)):
                    for request, name in zip(requests, ('a', 'b')):
                        result = events(c, request)
                        assert result == [(3, name)], (i, name, result)
        passed('twelve reciprocal signed/encrypted mutation rounds finish both transports and retain per-open FIFO without a cooperative-gate deadlock')
        with ThreadPoolExecutor(max_workers=1) as pool:
            for i in range(4):
                lost, _, lt = connect(0x311)
                watched = create(lt, 'peer-a', options=1, access=0x120089, disposition=1)
                notify(watched, 4); notify(watched, 4)
                write = pool.submit(change, cb, sb, tb, ha, 2 if i % 2 == 0 else 4)
                lost.disconnect(close=False)
                write.result(timeout=20); cb.echo(sid=sb.session_id)
        passed('subscriber disconnect during four concurrent mutation pairs preserves the writer and safely retires transport snapshots')
        for h in ha+hb: h.close()
        da.close(); db.close(); ca.disconnect(); cb.disconnect()
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush(); report['server_log'] = (f.base/'supervisor.log').read_text(errors='replace')[-14000:]
    finally:
        for c in clients:
            try: c.disconnect(close=False)
            except Exception: pass
        if f:
            try: f.close()
            except Exception: report['status'] = 'failed'; report['cleanup_error'] = traceback.format_exc()
        a.output.parent.mkdir(parents=True, exist_ok=True); a.output.write_text(json.dumps(report, indent=2)+'\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(main())
