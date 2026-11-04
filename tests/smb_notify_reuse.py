#!/usr/bin/env python3
"""Recursive directory watcher lifetime across deletion and name reuse."""
import argparse
import json
from pathlib import Path
import traceback
from smbprotocol.file_info import FileDispositionInformation
from m5_integration import Fixture, create, denied, setinfo
from smb_notify_integration import notify, events


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true'); a = p.parse_args()
    f = c = None; report = dict(status='failed', checks=[])
    def passed(text): report['checks'].append(text); print('PASS ' + text, flush=True)
    try:
        f = Fixture(a.bin, 512 if a.sanitizers else 256)
        c, s, t = f.connect()
        d = create(t, 'reuse-tree', options=1, access=0x120089)
        req = notify(d, 3, True); req.cancel()
        denied(lambda: c.receive(req, timeout=10), 0xc0000120)
        expected = []
        for i in range(110):
            create(t, 'reuse-tree/child', options=1).close()
            leaf = create(t, 'reuse-tree/child/leaf')
            delete = FileDispositionInformation(); delete['delete_pending'] = True
            setinfo(leaf, delete); leaf.close()
            child = create(t, 'reuse-tree/child', options=1, disposition=1)
            setinfo(child, delete); child.close()
            expected.extend([(1, 'child'), (1, 'child\\leaf'), (2, 'child\\leaf'), (2, 'child')])
        req = notify(d, interim=False)
        result = events(c, req, asynchronous=False)
        assert result == expected, (len(result), len(expected), result[:12], result[-12:])
        d.close()
        passed('110 recursive directory delete/recreate cycles retain all 440 events and release removed subtree watches without exhausting the pinned-directory bound')

        c.disconnect(); report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush(); report['server_log'] = (f.base/'supervisor.log').read_text(errors='replace')[-14000:]
    finally:
        if c:
            try: c.disconnect(close=False)
            except Exception: pass
        if f:
            try: f.close()
            except Exception: report['status'] = 'failed'; report['cleanup_error'] = traceback.format_exc()
        a.output.parent.mkdir(parents=True, exist_ok=True); a.output.write_text(json.dumps(report, indent=2)+'\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(main())
