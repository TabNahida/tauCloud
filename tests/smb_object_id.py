#!/usr/bin/env python3
"""Persistent object identifiers with independent signed/encrypted SMB clients."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import traceback
import uuid

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.ioctl import SMB2IOCTLRequest, SMB2IOCTLResponse
from smbprotocol.file_info import FileRenameInformation, FileDispositionInformation
from m5_integration import Fixture, create, denied, setinfo

CREATE, GET = 0x900c0, 0x9009c


def request(handle, control=CREATE, limit=64, data=b'', flags=1, fid=None):
    q = SMB2IOCTLRequest()
    # This library predates GET_OBJECT_ID; permit the published FSCC code.
    q['ctl_code'].enum_strict = False
    q['ctl_code'] = control
    q['file_id'] = handle.file_id if fid is None else fid
    q['max_output_response'] = limit
    q['flags'] = flags
    q['buffer'] = data
    return q


def identifier(handle, **kwargs):
    q = request(handle, **kwargs)
    c, t = handle.connection, handle.tree_connect
    raw = c.receive(c.send(q, t.session.session_id, t.tree_connect_id))
    response = SMB2IOCTLResponse()
    response['ctl_code'].enum_strict = False
    response.unpack(raw['data'].get_value())
    assert response['ctl_code'].get_value() == q['ctl_code'].get_value()
    assert response['file_id'].get_value() == handle.file_id
    assert response['output_count'].get_value() == 64
    assert response['output_offset'].get_value() == 112
    value = response['buffer'].get_value()
    assert len(value) == 64 and value[:16] != bytes(16)
    return value


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', required=True)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    f = None
    clients = []
    report = dict(status='failed', checks=[], recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())

    def passed(message):
        report['checks'].append(message)
        print('PASS ' + message, flush=True)

    def connect(dialect=0x311, share='smb'):
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        clients.append(c)
        c.connect(dialect=dialect)
        s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=dialect >= 0x300, auth_protocol='ntlm')
        s.connect()
        t = TreeConnect(s, '\\\\127.0.0.1\\' + share)
        t.connect()
        return c, t

    try:
        f = Fixture(args.bin, memory=1024)
        saved = {}
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, t = connect(dialect)
            name = f'object-{dialect:x}'
            h = create(t, name)
            denied(lambda: identifier(h, control=GET), 0xc00002f0)
            for limit in (0, 16, 63):
                denied(lambda: identifier(h, limit=limit), 0xc000000d)
            denied(lambda: identifier(h, data=b'unexpected'), 0xc000000d)
            denied(lambda: identifier(h, flags=0), 0xc00000bb)
            denied(lambda: identifier(h, fid=bytes(16)), 0xc0000128)
            denied(lambda: identifier(h, control=GET), 0xc00002f0)
            value = identifier(h)
            assert value[32:48] == value[:16] and value[48:] == bytes(16)
            assert identifier(h, control=GET) == identifier(h) == value
            readonly = create(t, name, access=0x80, disposition=1)
            assert identifier(readonly) == value
            readonly.close()
            ren = FileRenameInformation()
            ren['replace_if_exists'] = False
            ren['file_name'] = name + '-renamed'
            setinfo(h, ren)
            assert identifier(h) == value
            h.close()
            d = create(t, name + '-dir', options=1)
            directory_value = identifier(d)
            assert directory_value != value
            assert identifier(d, control=GET) == directory_value
            d.close()
            create(t, name + '-metadata').close()
            metadata = create(t, name + '-metadata', access=0x80, disposition=1)
            assert identifier(metadata) != value
            metadata.close()
            saved[name + '-renamed'] = value
            saved[name + '-dir'] = directory_value
            c.disconnect()
            passed(f'{dialect:x}: absent GET, invalid requests without mutation, repeatable IDs, metadata-only handles, rename and directories')

        # Copying Linux user xattrs must not clone an object's identity.
        if os.name != 'nt':
            source = f.root / 'smbdata/object-210-renamed'
            copied = source.with_name('copied-with-xattrs')
            c, t = connect()
            create(t, copied.name).close()
            shutil.copy2(source, copied)
            assert os.getxattr(source, 'user.taucloud.object-id.v1') == os.getxattr(copied, 'user.taucloud.object-id.v1')
            h = create(t, copied.name, disposition=1)
            denied(lambda: identifier(h, control=GET), 0xc00002f0)
            assert identifier(h) != saved['object-210-renamed']
            h.close()
            c.disconnect()
            passed('copying Linux data and xattrs cannot clone the source object identifier')

        f.stop()
        native = f.root / 'smbdata/object-210-renamed'
        native.rename(native.with_name('host-renamed'))
        saved['host-renamed'] = saved.pop('object-210-renamed')
        f.start()
        c, t = connect()
        for name, value in saved.items():
            h = create(t, name, disposition=1, options=1 if name.endswith('-dir') else 0x40)
            assert identifier(h, control=GET) == value
            h.close()
        passed('identifiers survive all-service restart and out-of-band native rename')

        h = create(t, 'host-renamed', disposition=1)
        deletion = FileDispositionInformation()
        deletion['delete_pending'] = True
        setinfo(h, deletion)
        h.close()
        h = create(t, 'host-renamed')
        denied(lambda: identifier(h, control=GET), 0xc00002f0)
        assert identifier(h) != saved['host-renamed']
        h.close()
        passed('delete and same-name recreation do not inherit the old identifier')

        create(t, 'not-yet-assigned').close()
        f.api('shares', f.admin, dict(id='readonly-object-id', space='smbdata', exposures={'smb':'r'}))
        ro, rt = connect(share='readonly-object-id')
        h = create(rt, 'object-300-renamed', access=0x80, disposition=1)
        assert identifier(h) == saved['object-300-renamed']
        h.close()
        h = create(rt, 'not-yet-assigned', access=0x80, disposition=1)
        denied(lambda: identifier(h), 0xc0000022)
        denied(lambda: identifier(h, control=GET), 0xc00002f0)
        h.close()
        passed('read-only share can retrieve existing IDs but cannot create metadata')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc()
        print(report['error'], flush=True)
    finally:
        for c in clients:
            try: c.disconnect()
            except Exception: pass
        if f:
            f.log.flush()
            report['server_log'] = (f.base / 'supervisor.log').read_text(errors='replace')[-65536:]
            f.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
