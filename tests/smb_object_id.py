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
DELETE, EXTENDED = 0x900a0, 0x900bc


def ntfs_identifier(path, create=False):
    """Independent local NTFS oracle; no server metadata or private RPC."""
    import ctypes
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.DeviceIoControl.argtypes = [w.HANDLE, w.DWORD, w.LPVOID, w.DWORD, w.LPVOID,
                                      w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID]
    kernel.DeviceIoControl.restype = w.BOOL
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    handle = kernel.CreateFileW(str(path), 0x80, 7, None, 3, 0x02000000, None)
    if handle == w.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        value = ctypes.create_string_buffer(64)
        size = w.DWORD()
        if not kernel.DeviceIoControl(handle, CREATE if create else GET, None, 0,
                                      value, 64, ctypes.byref(size), None):
            error = ctypes.get_last_error()
            if not create and error == 2:
                return None
            raise ctypes.WinError(error)
        assert size.value == 64
        return value.raw
    finally:
        kernel.CloseHandle(handle)


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


def mutate(handle, control, data=b'', **kwargs):
    q = request(handle, control=control, limit=0, data=data, **kwargs)
    c, t = handle.connection, handle.tree_connect
    raw = c.receive(c.send(q, t.session.session_id, t.tree_connect_id))
    response = SMB2IOCTLResponse()
    response['ctl_code'].enum_strict = False
    response.unpack(raw['data'].get_value())
    assert response['ctl_code'].get_value() == control
    assert response['file_id'].get_value() == handle.file_id
    assert response['input_count'].get_value() == response['output_count'].get_value() == 0
    assert response['buffer'].get_value() == b''


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
        native_recreated_has_id = False
        if os.name == 'nt':
            # NTFS can tunnel metadata on rapid same-name recreation. Measure
            # the actual filesystem behavior independently instead of imposing
            # Linux xattr semantics on a native Windows FSCTL passthrough.
            probe = f.root / 'object-id-native-oracle'
            probe.touch(exist_ok=False)
            before = ntfs_identifier(probe, True)
            old_inode = probe.stat().st_ino
            probe.unlink()
            assert not probe.exists()
            probe.touch(exist_ok=False)
            assert probe.stat().st_ino != old_inode
            after = ntfs_identifier(probe)
            native_recreated_has_id = after is not None
            report['native_recreation'] = dict(has_identifier=native_recreated_has_id,
                                              retained_identifier=after == before)
            probe.unlink()
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
            # Extended information is opaque, exactly 48 bytes, and cannot
            # change the first 16-byte identity. Check rights on actual opens.
            h = create(t, name + '-renamed', access=0x100, disposition=1)
            payload = bytes(range(48))
            for bad in (b'', bytes(47), bytes(49), bytes(64)):
                denied(lambda bad=bad: mutate(h, EXTENDED, bad), 0xc000000d)
            denied(lambda: mutate(h, DELETE, b'x'), 0xc000000d)
            readonly = create(t, name + '-renamed', access=0x80, disposition=1)
            denied(lambda: mutate(readonly, EXTENDED, payload), 0xc0000022)
            denied(lambda: mutate(readonly, DELETE), 0xc0000022)
            assert identifier(readonly, control=GET) == value
            readonly.close()
            mutate(h, EXTENDED, payload)
            value = value[:16] + payload
            assert identifier(h, control=GET) == value
            if os.name == 'nt':
                assert ntfs_identifier(f.root / 'smbdata' / (name + '-renamed')) == value
            denied(lambda: h.write(b'forbidden'), 0xc0000022)
            h.close()
            d = create(t, name + '-dir', access=0x100, disposition=1, options=1)
            mutate(d, EXTENDED, bytes(reversed(payload)))
            directory_value = directory_value[:16] + bytes(reversed(payload))
            assert identifier(d, control=GET) == directory_value
            d.close()
            removable = create(t, name + '-delete-id')
            removable.write(b'file survives identifier deletion')
            mutate(removable, DELETE)  # Idempotent even before assignment.
            denied(lambda: mutate(removable, EXTENDED, payload), 0xc0000034)
            identifier(removable)
            mutate(removable, DELETE); mutate(removable, DELETE)
            denied(lambda: identifier(removable, control=GET), 0xc00002f0)
            assert removable.read(0, 33) == b'file survives identifier deletion'
            if os.name == 'nt':
                assert ntfs_identifier(f.root / 'smbdata' / (name + '-delete-id')) is None
            removable.close()
            removable_dir = create(t, name + '-delete-id-dir', options=1)
            identifier(removable_dir)
            mutate(removable_dir, DELETE); mutate(removable_dir, DELETE)
            denied(lambda: identifier(removable_dir, control=GET), 0xc00002f0)
            create(t, name + '-delete-id-dir/child').close()
            removable_dir.close()
            passed(f'{dialect:x}: extended info preserves identity across file/directory metadata-only opens; malformed/unauthorized mutations leave metadata intact; DELETE is idempotent and preserves data')
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
        recreated = f.root / 'smbdata/host-renamed'
        old_inode = recreated.stat().st_ino
        deletion = FileDispositionInformation()
        deletion['delete_pending'] = True
        setinfo(h, deletion)
        h.close()
        assert not recreated.exists(), 'SMB CLOSE did not complete native deletion'
        h = create(t, 'host-renamed', disposition=2)  # FILE_CREATE, never reopen an old name.
        if os.name == 'nt':
            assert recreated.stat().st_ino != old_inode, 'recreation retained the old NTFS incarnation'
            native_value = ntfs_identifier(recreated)
            assert (native_value is not None) == native_recreated_has_id
            if native_value is None:
                denied(lambda: identifier(h, control=GET), 0xc00002f0)
            else:
                assert identifier(h, control=GET) == native_value
            assert identifier(h) == ntfs_identifier(recreated)
        else:
            denied(lambda: identifier(h, control=GET), 0xc00002f0)
            assert identifier(h) != saved['host-renamed']
        h.close()
        passed('delete completes, same-name recreation has a new native incarnation and identifiers follow native filesystem behavior')

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
        h = create(t, 'object-300-renamed', access=0x100, disposition=1)
        f.api('shares', f.admin, dict(id='smb', space='smbdata', exposures={'smb':'r'}, update=True))
        denied(lambda: mutate(h, EXTENDED, bytes(48)), 0xc0000022)
        denied(lambda: mutate(h, DELETE), 0xc0000022)
        # Reauthorization may retire the old write handle. Verify unchanged
        # storage through a fresh read-only open, rather than requiring it live.
        h = create(rt, 'object-300-renamed', access=0x80, disposition=1)
        assert identifier(h, control=GET) == saved['object-300-renamed']
        h.close()
        passed('revoking share write authority denies mutations through an already-open WRITE_ATTRIBUTES handle without changing its identifier')
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
