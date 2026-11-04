#!/usr/bin/env python3
"""SET_SECURITY archive, deferred/frozen timestamps, notifications and recovery."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import traceback
import uuid

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from m5_integration import Fixture, create as open_smb, denied
from m1_integration import wait
from smb_notify_integration import notify, events
from smb_rename_metadata import BASE, attributes, basic, rename
from smb_security_integration import get_sd, set_sd


def create(tree, name, access=0x1f01ff, **kwargs):
    # Include WRITE_DAC for the security mutation scenarios.
    return open_smb(tree, name, access=access, **kwargs)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', required=True); p.add_argument('--output', required=True, type=Path)
    a = p.parse_args(); f = None; clients = []; report = dict(status='failed', checks=[])
    def passed(message):
        report['checks'].append(message); print('PASS '+message, flush=True)
    def connect(dialect=0x311):
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        clients.append(c); c.connect(dialect=dialect)
        s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=dialect >= 0x300, auth_protocol='ntlm')
        s.connect(); t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect()
        return c, t
    def prepare(h, automatic=True, archive=False):
        attributes(h, 0x22 if archive else 2, (BASE, BASE+10, BASE+20, BASE+30))
        if automatic: attributes(h, 0, (0, 0, 0, 2**64-2))
        return basic(h)
    def watch(t, folder, mask):
        d = create(t, folder, options=1, access=0x120089, disposition=1)
        return d, notify(d, mask)
    def still_pending(request):
        time.sleep(.1)
        assert request.response['status'].get_value() == 0x103
    def cancel(c, request):
        still_pending(request); request.cancel()
        denied(lambda: c.receive(request, timeout=10), 0xc0000120)
    try:
        f = Fixture(a.bin, memory=1024)
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, t = connect(dialect); folder = f'security-meta-{dialect:x}'
            create(t, folder, options=1).close()
            for frozen in (False, True):
                name = 'frozen' if frozen else 'automatic'
                h = create(t, folder+'/'+name); before = prepare(h, not frozen)
                sd = get_sd(h); d, req = watch(t, folder, 4); sec, sr = watch(t, folder, 0x100)
                set_sd(h, sd)
                assert events(c, sr) == [(3, name)]
                assert basic(h) == (*before[:4], 0x22)
                still_pending(req); h.close(); assert events(c, req) == [(3, name)]
                h = create(t, folder+'/'+name, disposition=1); after = basic(h)
                assert after[:3] == before[:3] and after[4] == 0x22
                assert after[3] == before[3] if frozen else after[3] > before[3]
                h.close(); d.close(); sec.close()
                passed(f'{dialect:x}: security notification is immediate; archive is visible before close; change time is '+('frozen' if frozen else 'deferred'))

            h = create(t, folder+'/denied'); before = prepare(h); sd = get_sd(h)
            limited = create(t, folder+'/denied', disposition=1, access=0x80)
            d, req = watch(t, folder, 4 | 0x100)
            denied(lambda: set_sd(limited, sd), 0xc0000022)
            denied(lambda: set_sd(h, b'bad'), 0xc0000079)
            assert basic(h) == before and get_sd(h) == sd
            limited.close(); h.close(); cancel(c, req); d.close()
            h = create(t, folder+'/denied', disposition=1); assert basic(h) == before; h.close()
            passed(f'{dialect:x}: rejected security updates change neither descriptor, attributes, times nor notifications')

            h = create(t, folder+'/directory', options=1); before = prepare(h)
            d, req = watch(t, folder, 4); set_sd(h, get_sd(h))
            assert basic(h) == before; h.close(); cancel(c, req); d.close()
            h = create(t, folder+'/directory', options=1, disposition=1)
            assert basic(h) == before and not basic(h)[4] & 0x20; h.close()
            passed(f'{dialect:x}: directory security updates do not invent archive or change-time changes')
            c.disconnect()

        c, t = connect(); folder = 'security-lifecycle'; create(t, folder, options=1).close()
        h = create(t, folder+'/shared'); before = prepare(h)
        peer = create(t, folder+'/shared', disposition=1); d, req = watch(t, folder, 4)
        set_sd(h, get_sd(h)); peer.close(); assert events(c, req) == [(3, 'shared')]
        assert basic(h)[3] == before[3]
        d.close(); d, req = watch(t, folder, 4); h.close(); cancel(c, req); d.close()
        h = create(t, folder+'/shared', disposition=1); assert basic(h)[3] > before[3]; h.close()
        passed('another close flushes file-wide notifications; only the originating close completes its timestamp')

        h = create(t, folder+'/cancel'); prepare(h, archive=True); set_sd(h, get_sd(h))
        attributes(h, 0, (0, 0, 0, BASE+99)); d, req = watch(t, folder, 4)
        h.close(); cancel(c, req); d.close()
        h = create(t, folder+'/cancel', disposition=1); assert basic(h)[3] == BASE+99; h.close()
        h = create(t, folder+'/reenable'); prepare(h, automatic=False, archive=True)
        set_sd(h, get_sd(h)); attributes(h, 0, (0, 0, 0, 2**64-2)); d, req = watch(t, folder, 4)
        h.close(); assert events(c, req) == [(3, 'reenable')]; d.close()
        h = create(t, folder+'/reenable', disposition=1); assert basic(h)[3] > BASE+30; h.close()
        passed('explicit ChangeTime cancels a pending automatic update; -2 re-enables it')

        h = create(t, folder+'/old'); before = prepare(h); d, req = watch(t, folder, 4)
        set_sd(h, get_sd(h)); rename(h, folder+'/new'); set_sd(h, get_sd(h))
        still_pending(req); h.close(); assert events(c, req) == [(3, 'new')]; d.close()
        h = create(t, folder+'/new', disposition=1)
        assert basic(h)[:3] == before[:3] and basic(h)[3] > before[3] and basic(h)[4] == 0x22; h.close()
        passed('repeated security updates and rename merge their pending metadata at the final name')

        h = create(t, folder+'/recovery'); before = prepare(h); sd = get_sd(h); set_sd(h, sd)
        pid = f.ctl('status')['smb']['identity']['pid']
        if os.name == 'nt': subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True, check=True)
        else: os.kill(pid, signal.SIGKILL)
        wait(lambda: (x := f.ctl('status')['smb'])['status'] == 'running' and x['identity']['pid'] != pid)
        c, t = connect(); h = create(t, folder+'/recovery', disposition=1)
        assert basic(h)[:3] == before[:3] and basic(h)[3] > before[3] and basic(h)[4] == 0x22
        assert get_sd(h) == sd; h.close(); c.disconnect()
        f.stop(); f.ctl('backup', '--output', str(f.base/'security-recovered-backup'))
        passed('SMB process loss recovers the committed descriptor, archive and deferred timestamp; clean metadata backup succeeds')
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
