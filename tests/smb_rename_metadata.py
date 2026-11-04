#!/usr/bin/env python3
"""Independent rename archive, deferred change time, close notifications and recovery."""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import signal
import sqlite3
import struct
import subprocess
import time
import traceback
import uuid
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import SMB2SetInfoRequest
from smbprotocol.file_info import FileRenameInformation
from m5_integration import Fixture, create, query, denied, setinfo
from m1_integration import wait
from smb_notify_integration import notify, events

BASE = 116444736000000000 + 1600000000*10000000


def attributes(h, value=0, times=(0, 0, 0, 0)):
    q = SMB2SetInfoRequest(); q['info_type'] = 1; q['file_info_class'] = 4
    q['file_id'] = h.file_id; q['buffer'] = struct.pack('<QQQQII', *times, value, 0)
    h.connection.receive(h.connection.send(q, h.tree_connect.session.session_id, h.tree_connect.tree_connect_id))


def basic(h):
    return struct.unpack_from('<QQQQI', query(h, 4))


def rename(h, path):
    q = FileRenameInformation(); q['file_name'] = path; setinfo(h, q)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true'); a = p.parse_args()
    f = None; clients = []; report = dict(status='failed', checks=[])
    def passed(s): report['checks'].append(s); print('PASS ' + s, flush=True)
    def connect(dialect=0x311):
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        c.connect(dialect=dialect)
        s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=dialect >= 0x300, auth_protocol='ntlm'); s.connect()
        t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect(); clients.append(c)
        return c, s, t
    def automatic(h):
        attributes(h, 2, (BASE, BASE+10, BASE+20, BASE+30))
        attributes(h, 0, (0, 0, 0, 2**64-2))
    try:
        f = Fixture(a.bin, 512 if a.sanitizers else 256)
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, s, t = connect(dialect); folder = f'rename-{dialect}'
            d = create(t, folder, options=1, access=0x120089)
            h = create(t, folder+'/old'); automatic(h); before = basic(h)
            req = notify(d, 4)
            rename(h, folder+'/new'); assert basic(h) == (*before[:4], 0x22)
            time.sleep(.05); assert req.response['status'].get_value() == 0x103
            h.close(); assert events(c, req) == [(3, 'new')]
            h = create(t, folder+'/new', disposition=1)
            after = basic(h); assert after[:3] == before[:3] and after[3] > before[3] and after[4] == 0x22
            h.close(); d.close(); c.disconnect()
        passed('four signed/encrypted dialects set archive immediately, preserve creation/access/write times and defer change time plus one attribute notification to close')

        c, s, t = connect(); d = create(t, 'freeze', options=1, access=0x120089)
        h = create(t, 'freeze/old'); attributes(h, 2, (BASE, BASE+10, BASE+20, BASE+30))
        req = notify(d, 4)
        rename(h, 'freeze/middle'); rename(h, 'freeze/new'); h.close()
        assert events(c, req) == [(3, 'new')]
        h = create(t, 'freeze/new', disposition=1)
        assert basic(h) == (BASE, BASE+10, BASE+20, BASE+30, 0x22); h.close()
        passed('explicit change time stays frozen across repeated rename and close while a real archive change is notified once at the final name')

        h = create(t, 'freeze/cancel'); automatic(h); attributes(h, 0x22)
        rename(h, 'freeze/cancelled')
        attributes(h, 0, (0, 0, 0, BASE+99))
        d.close(); d = create(t, 'freeze', options=1, access=0x120089, disposition=1)
        req = notify(d, 4); h.close()
        time.sleep(.1); assert req.response['status'].get_value() == 0x103
        req.cancel(); denied(lambda: c.receive(req, timeout=10), 0xc0000120)
        h = create(t, 'freeze/cancelled', disposition=1); assert basic(h)[3] == BASE+99; h.close()
        h = create(t, 'freeze/reenable'); attributes(h, 0x22, (0, 0, 0, BASE))
        rename(h, 'freeze/enabled'); attributes(h, 0, (0, 0, 0, 2**64-2))
        d.close(); d = create(t, 'freeze', options=1, access=0x120089, disposition=1)
        req = notify(d, 4); h.close(); assert events(c, req) == [(3, 'enabled')]
        h = create(t, 'freeze/enabled', disposition=1); assert basic(h)[3] > BASE; h.close()
        passed('explicit time after rename cancels its deferred update; -2 re-enables it without inventing archive changes')

        h = create(t, 'freeze/shared'); automatic(h); peer = create(t, 'freeze/shared', disposition=1)
        d.close(); d = create(t, 'freeze', options=1, access=0x120089, disposition=1)
        req = notify(d, 4); rename(h, 'freeze/shared-new')
        peer.close(); assert events(c, req) == [(3, 'shared-new')]
        assert basic(h)[3] == BASE+30
        h.close(); h = create(t, 'freeze/shared-new', disposition=1); assert basic(h)[3] > BASE+30; h.close()
        passed('another close flushes file-wide pending notifications while only the originating open completes its deferred timestamp')
        h = create(t, 'freeze/dir-old', options=1); automatic(h); before = basic(h)
        rename(h, 'freeze/dir-new'); assert not basic(h)[4] & 0x20; h.close()
        h = create(t, 'freeze/dir-new', options=1, disposition=1)
        after = basic(h)
        assert after[:3] == before[:3] and after[3] > before[3] and not after[4] & 0x20, (before, after)
        h.close(); d.close()
        passed('directory rename updates change time at close without applying a data-file archive bit')

        h = create(t, 'recovery-old'); automatic(h); rename(h, 'recovery-new')
        pid = f.ctl('status')['smb']['identity']['pid']
        if os.name == 'nt': subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True, check=True)
        else: os.kill(pid, signal.SIGKILL)
        wait(lambda: (x := f.ctl('status')['smb'])['status'] == 'running' and x['identity']['pid'] != pid)
        c, s, t = connect(); h = create(t, 'recovery-new', disposition=1)
        assert basic(h)[3] > BASE+30 and basic(h)[4] == 0x22; h.close(); c.disconnect()
        f.stop(); f.ctl('backup', '--output', str(f.base/'clean-backup'))
        # A durable but unfinished marker must not escape into a metadata backup.
        with closing(sqlite3.connect(f.state/'file.db')) as db, db:
            native, body = db.execute('SELECT native,body FROM smb_times LIMIT 1').fetchone()
            value = json.loads(body); value['rename_pending'] = {'lost':dict(change=True, notify=True, archive=False)}
            db.execute('UPDATE smb_times SET body=? WHERE native=?', (json.dumps(value), native))
        assert 'unfinished_jobs' in f.ctl('backup', '--output', str(f.base/'unfinished-backup'), ok=False)
        f.start(); f.stop(); f.ctl('backup', '--output', str(f.base/'recovered-backup'))
        passed('SMB process loss recovers durable rename metadata; offline backup refuses unresolved markers and succeeds after file-service restart recovery')
        # Recovery must not transfer a lost open's timestamps or attributes
        # to a host-created replacement at the same indexed path.
        with closing(sqlite3.connect(f.state/'file.db')) as db, db:
            native, body = db.execute("SELECT t.native,t.body FROM smb_times t JOIN objects o ON o.native=t.native WHERE o.path='recovery-new'").fetchone()
            value = json.loads(body); value['rename_pending'] = {'lost':dict(change=True, notify=True, archive=True)}
            db.execute('UPDATE smb_times SET body=? WHERE native=?', (json.dumps(value), native))
        target = f.root/'smbdata/recovery-new'
        target.unlink(); target.write_bytes(b'replacement')
        f.start(); c, s, t = connect(); h = create(t, 'recovery-new', disposition=1)
        assert basic(h)[0] != BASE and basic(h)[4] == 0x20 and h.read(0, 11) == b'replacement'
        h.close(); c.disconnect(); f.stop()
        with closing(sqlite3.connect(f.state/'file.db')) as db:
            assert not any(json.loads(row[0]).get('rename_pending') for row in db.execute('SELECT body FROM smb_times'))
        f.ctl('backup', '--output', str(f.base/'replacement-backup'))
        passed('recovery discards stale rename markers without transferring metadata to a replacement native incarnation')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush(); report['server_log'] = (f.base/'supervisor.log').read_text(errors='replace')[-12000:]
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
