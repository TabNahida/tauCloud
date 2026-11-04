#!/usr/bin/env python3
"""MS-FSA destination-directory sharing, independent of the source open."""
import argparse
import json
from pathlib import Path
import traceback
import uuid
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.file_info import FileRenameInformation
from m5_integration import Fixture, create, denied, setinfo


def rename(h, path):
    q = FileRenameInformation(); q['file_name'] = path
    setinfo(h, q)


def run():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    a = p.parse_args(); f = c = None
    report = dict(status='failed', checks=[])
    def passed(s): report['checks'].append(s); print('PASS ' + s, flush=True)
    try:
        f = Fixture(a.bin, 512 if a.sanitizers else 256)
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True); c.connect()
        s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=True, auth_protocol='ntlm'); s.connect()
        t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect()
        for directory in (False, True):
            for access in (0x1f01ff, 0x80):
                for sharing in range(8):
                    base = f'parent-{directory}-{access}-{sharing}'
                    create(t, base, options=1).close()
                    parent = create(t, base, options=1, access=access, share=sharing, disposition=1)
                    h = create(t, base + '/old', options=1 if directory else 0x40, share=0)
                    target = base + '/new'
                    if access == 0x1f01ff and not sharing & 2:
                        denied(lambda: rename(h, target), 0xc0000043)
                        assert (f.root/'smbdata'/base/'old').exists() and not (f.root/'smbdata'/target).exists()
                    else:
                        rename(h, target)
                        assert (f.root/'smbdata'/target).exists() and not (f.root/'smbdata'/base/'old').exists()
                    h.close(); parent.close()
        passed('32 file/directory and full/metadata-only parent combinations enforce destination WRITE sharing; parent DELETE rights and child share mode do not add obsolete restrictions')
        for directory in (False, True):
            base = f'move-{directory}'
            create(t, base, options=1).close(); create(t, base+'/from', options=1).close(); create(t, base+'/to', options=1).close()
            source = create(t, base+'/from', options=1, access=0x1f01ff, share=0, disposition=1)
            h = create(t, base+'/from/child', options=1 if directory else 0x40)
            rename(h, base+'/to/child'); h.close(); source.close()
            h = create(t, base+'/to/child', options=1 if directory else 0x40, disposition=1); h.close()
        passed('moving files/directories out of an exclusively opened source directory checks the destination rather than rejecting the source parent')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush(); report['server_log'] = (f.base/'supervisor.log').read_text(errors='replace')[-10000:]
    finally:
        if c:
            try: c.disconnect(close=False)
            except Exception: pass
        if f: f.close()
        a.output.parent.mkdir(parents=True, exist_ok=True); a.output.write_text(json.dumps(report, indent=2)+'\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(run())
