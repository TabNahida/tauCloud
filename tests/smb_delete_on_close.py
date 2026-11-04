#!/usr/bin/env python3
"""Independent CREATE delete-on-close versus explicit disposition and recovery."""
import argparse
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import traceback
import uuid
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.file_info import FileDispositionInformation, FileRenameInformation
from m5_integration import Fixture, create, denied, query, setinfo
from m1_integration import wait
from smb_notify_integration import notify


def disposition(h, delete=True):
    q = FileDispositionInformation(); q['delete_pending'] = delete; setinfo(h, q)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    a = p.parse_args(); f = None; clients = []
    report = dict(status='failed', checks=[])
    def passed(s): report['checks'].append(s); print('PASS ' + s, flush=True)
    def connect(dialect=0x311):
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        c.connect(dialect=dialect)
        s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=dialect >= 0x300, auth_protocol='ntlm'); s.connect()
        t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect(); clients.append(c)
        return c, s, t
    try:
        f = Fixture(a.bin, 512 if a.sanitizers else 256)
        # Test the schema-6 upgrade with an actual pre-upgrade database backup.
        f.stop()
        for role in ('file', 'file_1', 'file_2', 'file_3'):
            with sqlite3.connect(f.state/(role+'.db')) as db:
                db.executescript('DROP TABLE smb_close_delete; PRAGMA user_version=6;')
        f.start()
        for role in ('file', 'file_1', 'file_2', 'file_3'):
            assert (f.state/(role+'.pre-v7.db')).exists()
            with sqlite3.connect(f.state/(role+'.db')) as db:
                assert db.execute('PRAGMA user_version').fetchone()[0] == 7
        passed('schema 6 upgrades to 7 with backups in every file worker')
        root = f.root/'smbdata'
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, s, t = connect(dialect); prefix = f'doc-{dialect}'
            h = create(t, prefix+'-file', options=0x1040)
            peer = create(t, prefix+'-file', disposition=1)
            assert not query(peer, 5)[20] # FileStandardInformation.DeletePending
            h.write(b'held'); assert peer.read(0, 4) == b'held'
            h.close(); assert query(peer, 5)[20]
            denied(lambda: create(t, prefix+'-file', disposition=1), 0xc0000056)
            assert peer.read(0, 4) == b'held'
            peer.close(); assert not (root/(prefix+'-file')).exists()
            # The directory may become nonempty after OPEN; close must not
            # recursively remove it or leave a latent delete intent.
            h = create(t, prefix+'-dir', options=0x1001)
            child = create(t, prefix+'-dir/child'); child.write(b'preserved'); child.close()
            denied(lambda: disposition(h), 0xc0000101)
            h.close(); assert (root/(prefix+'-dir/child')).read_bytes() == b'preserved'
            h = create(t, prefix+'-dir', disposition=1, options=0x1001)
            h.close(); assert (root/(prefix+'-dir/child')).exists()
            child = create(t, prefix+'-dir/child', disposition=1, options=0x1040); child.close()
            h = create(t, prefix+'-dir', disposition=1, options=1); h.close()
            assert (root/(prefix+'-dir')).exists()
            # Explicit disposition can be cleared, but it does not clear the
            # separate CREATE open mode that will be evaluated at close.
            h = create(t, prefix+'-explicit'); peer = create(t, prefix+'-explicit')
            disposition(h); assert query(peer, 5)[20]
            disposition(h, False); assert not query(peer, 5)[20]
            h.close(); peer.close(); assert (root/(prefix+'-explicit')).exists()
            h = create(t, prefix+'-mode', options=0x1040)
            disposition(h, False); h.close(); assert not (root/(prefix+'-mode')).exists()
            # An empty-directory close activates delete-pending and cancels
            # another open's pending watch, without unlinking that live open.
            h = create(t, prefix+'-watch', options=0x1001)
            peer = create(t, prefix+'-watch', disposition=1, options=1)
            request = notify(peer); h.close()
            denied(lambda: c.receive(request, timeout=10), 0xc0000056)
            assert (root/(prefix+'-watch')).exists()
            peer.close(); assert not (root/(prefix+'-watch')).exists()
            # Intent follows rename and is activated on this handle's close.
            h = create(t, prefix+'-old', options=0x1040)
            r = FileRenameInformation(); r['file_name'] = prefix+'-new'; setinfo(h, r)
            h.close(); assert not (root/(prefix+'-new')).exists()
            c.disconnect()
        passed('four signed/encrypted dialects: per-open mode, last-close unlink, nonempty directory preservation, explicit disposition, notifications and rename')
        c, s, t = connect()
        h = create(t, 'crash-file', options=0x1040); h.write(b'delete')
        empty = create(t, 'crash-empty', options=0x1001)
        full = create(t, 'crash-full', options=0x1001)
        child = create(t, 'crash-full/child'); child.write(b'keep'); child.close()
        before = f.ctl('status'); pid = before['smb']['identity']['pid']
        if os.name == 'nt': subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True, check=True)
        else: os.kill(pid, signal.SIGKILL)
        wait(lambda: (entry := f.ctl('status')['smb'])['status'] == 'running' and entry['identity']['pid'] != pid)
        wait(lambda: not (root/'crash-file').exists() and not (root/'crash-empty').exists())
        assert (root/'crash-full/child').read_bytes() == b'keep'
        after = f.ctl('status')
        assert all(after[r]['identity']['pid'] == before[r]['identity']['pid'] for r in ('api', 'file', 'identity'))
        c, s, t = connect(); h = create(t, 'crash-full', disposition=1, options=1); h.close()
        passed('killed SMB worker recovers durable intents, deletes files/empty directories and preserves nonempty directories without restarting other services')
        # Backup must refuse unresolved destructive intents, as it already
        # refuses shared pending deletion. A completed state remains portable.
        c.disconnect(); f.stop()
        backup = f.base/'backup-doc'; f.ctl('backup', '--output', str(backup))
        with sqlite3.connect(backup/'file.db') as db:
            assert db.execute('PRAGMA user_version').fetchone()[0] == 7
        with sqlite3.connect(f.state/'file.db') as db:
            db.execute("INSERT INTO smb_close_delete VALUES('abandoned', 'smbdata', 'missing', 'obsolete', 0, '')")
        rejected = f.ctl('backup', '--output', str(f.base/'backup-unfinished'), ok=False)
        assert 'unfinished_jobs' in rejected
        assert not (f.base/'backup-unfinished').exists()
        f.start(); f.stop()
        f.ctl('backup', '--output', str(f.base/'backup-recovered'))
        passed('offline metadata backup accepts schema 7, refuses unresolved close intents and succeeds after recovery')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush(); report['server_log'] = (f.base/'supervisor.log').read_text(errors='replace')[-10000:]
    finally:
        for c in clients:
            try: c.disconnect(close=False)
            except Exception: pass
        if f: f.close()
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(report, indent=2)+'\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(main())
