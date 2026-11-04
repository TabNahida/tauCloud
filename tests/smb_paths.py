#!/usr/bin/env python3
"""SMB CREATE dot components, share-root normalization and authority confinement."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import traceback
import uuid

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.file_info import FileRenameInformation, FileDispositionInformation
from m5_integration import Fixture, create, query, setinfo, denied
from smb_security_integration import descriptor, ace, EVERYONE, set_sd
from smb_notify_integration import notify, events


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true'); a = p.parse_args()
    f = None; clients = []; report = dict(status='failed', checks=[])
    def passed(text): report['checks'].append(text); print('PASS ' + text, flush=True)
    def connect(dialect, share='smb'):
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        c.connect(dialect=dialect); clients.append(c)
        s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=dialect >= 0x300, auth_protocol='ntlm')
        s.connect(); t = TreeConnect(s, '\\\\127.0.0.1\\'+share); t.connect()
        return c, t
    try:
        f = Fixture(a.bin, 512 if a.sanitizers else 256)
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, t = connect(dialect); base = f'paths-{dialect}'
            create(t, base, options=1).close(); create(t, base+'/child', options=1).close()
            h = create(t, base+'/data'); h.write(b'canonical'); identity = query(h, 6); h.close()
            for name in (base+'/./data', base+'/child/../data', './'+base+'/data',
                         '../'+base+'/data', '../../../'+base+'/data',
                         base+'/missing/../data'):
                h = create(t, name, disposition=1)
                assert query(h, 6) == identity and h.read(0, 9) == b'canonical'
                h.close()
            for name in ('.', '..', '../..'):
                h = create(t, name, options=1, disposition=1); root = create(t, '', options=1, disposition=1)
                assert query(h, 6) == query(root, 6); h.close(); root.close()
            # Windows product note 304 rejects this leading prefix, even though
            # deeper dot normalization and leading root-parent names work.
            denied(lambda: create(t, base+'/../forbidden'), 0xc000000d)
            alias = create(t, base+'/child/..', options=1, disposition=1)
            req = notify(alias)
            create(t, base+'/child/../event').close()
            assert events(c, req) == [(1, 'event')]
            rename = FileRenameInformation(); rename['file_name'] = base+'/renamed'
            h = create(t, base+'/child/../data', disposition=1)
            setinfo(h, rename); assert h.read(0, 9) == b'canonical'; h.close()
            alias.close(); c.disconnect()
        passed('four signed/encrypted dialects normalize dot components before lookup, retain native identity and canonical handle paths, clamp root parents and deliver notifications through an alias')

        c, t = connect(0x311)
        create(t, 'published', options=1).close()
        h = create(t, 'outside'); h.write(b'outside-secret'); h.close()
        h = create(t, 'published/outside'); h.write(b'inside'); h.close()
        f.api('shares', f.admin, dict(id='sub', space='smbdata', path='published', exposures={'smb':'rw'}))
        sc, sub = connect(0x311, 'sub')
        for name in ('../outside', '../../outside', './../../../outside'):
            h = create(sub, name, disposition=1); assert h.read(0, 6) == b'inside'; h.close()
        create(sub, '../../../root-confined').close()
        assert (f.root/'smbdata/published/root-confined').is_file()
        assert not (f.root/'smbdata/root-confined').exists() and not (f.root/'root-confined').exists()
        h = create(t, 'published/private', access=0x1f01ff)
        set_sd(h, descriptor([ace(EVERYONE, 1, deny=True), ace(EVERYONE)])); h.close()
        denied(lambda: create(sub, '.././private', access=1, disposition=1), 0xc0000022)
        h = create(sub, '../outside', disposition=1, share=0)
        denied(lambda: create(t, 'published/outside', disposition=1), 0xc0000043)
        h.close()
        f.api('shares', f.admin, dict(id='readonly', space='smbdata', path='published', exposures={'smb':'r'}))
        rc, readonly = connect(0x311, 'readonly')
        denied(lambda: create(readonly, '../new'), 0xc0000022)
        h = create(readonly, '../outside', access=1, disposition=1); assert h.read(0, 6) == b'inside'; h.close()
        rc.disconnect(); sc.disconnect()
        passed('normalization stays within a subdirectory share and preserves final-object DACLs, global sharing conflicts and read-only publication')

        for name in ('published/.tc-secret/../bad', 'published/bad:stream/../bad',
                     'published/CON/../bad', 'published/e\u0301/../bad',
                     'published//../bad', 'published/name /../bad',
                     'published/'+('x'*121)+'/../bad', 'published/'+('./'*600)+'bad'):
            denied(lambda name=name: create(t, name), 0xc0000033)
        assert not (f.root/'smbdata/published/bad').exists()
        # Replace an indexed directory after closing it. A stale metadata entry
        # must not allow normalized lookup to follow a host symlink/junction.
        create(t, 'published/link', options=1).close()
        create(t, 'published/link/outside').close()
        link = f.root/'smbdata/published/link'
        (link/'outside').unlink(); link.rmdir()
        if os.name == 'nt':
            subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(f.root/'smbdata')],
                           check=True, capture_output=True)
        else:
            link.symlink_to(f.root/'smbdata', target_is_directory=True)
        denied(lambda: create(t, 'published/./link/outside', access=1, disposition=1), 0xc000000d)
        if os.name == 'nt': link.rmdir()
        else: link.unlink()
        link.mkdir(); (link/'outside').write_bytes(b'restored')
        delete = FileDispositionInformation(); delete['delete_pending'] = True
        h = create(t, 'published/./outside', disposition=1); setinfo(h, delete); h.close()
        assert not (f.root/'smbdata/published/outside').exists()
        assert (f.root/'smbdata/outside').read_bytes() == b'outside-secret'
        c.disconnect()
        passed('raw invalid/reserved/overlong components cannot be hidden by dot removal; native links remain confined and alias deletion affects only the canonical object')
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
