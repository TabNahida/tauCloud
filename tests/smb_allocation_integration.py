#!/usr/bin/env python3
"""Exercise native SMB preallocation and durable quota reservations over the wire."""
import argparse
import json
import os
from pathlib import Path
import struct
import sqlite3
import traceback
from m5_integration import Fixture, create, query, setinfo, denied
from smbprotocol.open import SMB2SetInfoRequest, Open, ImpersonationLevel
from smbprotocol.create_contexts import SMB2CreateContextRequest
from smbprotocol.file_info import FileDispositionInformation, FileEndOfFileInformation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fixture = Fixture(args.bin)
    clients = []
    report = dict(status='failed', checks=[])

    def connect():
        connection, session, tree = fixture.connect(share='allocation')
        clients.append(connection)
        return connection, tree

    def allocate(handle, size):
        request = SMB2SetInfoRequest()
        request['info_type'] = 1
        request['file_info_class'] = 19
        request['file_id'] = handle.file_id
        request['buffer'] = struct.pack('<Q', size)
        response = handle.connection.send(request, handle.tree_connect.session.session_id,
                                          handle.tree_connect.tree_connect_id)
        handle.connection.receive(response)

    def sizes(handle):
        return struct.unpack_from('<QQ', query(handle, 5))

    try:
        fixture.stop()
        for role in ('file', 'file_1', 'file_2', 'file_3'):
            db = sqlite3.connect(fixture.state / (role + '.db'))
            try:
                db.executescript('DROP TABLE allocations; PRAGMA user_version=4;')
            finally:
                db.close()
        fixture.start()
        assert all((fixture.state / (role + '.pre-v5.db')).exists()
                   for role in ('file', 'file_1', 'file_2', 'file_3'))
        report['checks'].append('schema v4 migration preserves a pre-v5 backup before adding durable reservations')
        fixture.api('spaces', fixture.admin, dict(id='allocation', root='data', path='allocation',
                                                owner='alice', quota=8192))
        fixture.api('shares', fixture.admin, dict(id='allocation', space='allocation',
                                                exposures={'smb': 'rw'}))
        token = fixture.api('auth/login', data=dict(username='alice', password=fixture.password,
                                                   scope='files'))['token']

        def used():
            return fixture.api('files/quota', token, dict(space='allocation', path=''))['used']

        connection, tree = connect()
        first = create(tree, 'first')
        allocate(first, 4096)
        assert sizes(first) == (4096, 0), sizes(first)
        assert used() == 4096, used()
        if os.name != 'nt':
            assert (fixture.root / 'allocation/first').stat().st_blocks * 512 == 4096
        second = create(tree, 'second')
        allocate(second, 4096)
        assert used() == 8192
        denied(lambda: allocate(first, 8192), 0xc000007f)
        assert sizes(first) == (4096, 0) and used() == 8192
        first.write(b'allocated data')
        first.flush()
        assert used() == 8192
        denied(lambda: first.write(b'outside reservation', 4096), 0xc000007f)
        reader = create(tree, 'first', access=0x120089, disposition=1)
        denied(lambda: allocate(reader, 0), 0xc0000022)
        reader.close()
        report['checks'].append('native space allocation preserves EOF, charges quota once, rejects over-quota growth before mutation and enforces WRITE_DATA')
        first.close()
        second.close()
        connection.disconnect()
        fixture.stop()
        fixture.start()
        connection, tree = connect()
        first = create(tree, 'first', disposition=1)
        second = create(tree, 'second', disposition=1)
        reopened = [sizes(first), sizes(second)]
        report['native_allocation_after_reopen'] = reopened
        assert reopened[0][1] == 14 and reopened[1][1] == 0, reopened
        if os.name == 'nt':
            # NTFS can trim preallocation at close (MS-FSA 2.1.5.4 phase 4).
            # Check the actual native values instead of assuming Linux retention.
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                           wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
            kernel.CreateFileW.restype = wintypes.HANDLE
            kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            for name, expected in zip(('first', 'second'), reopened):
                handle = kernel.CreateFileW(str(fixture.root / ('allocation/' + name)), 0x80, 7, None, 3, 0, None)
                assert handle != ctypes.c_void_p(-1).value, ctypes.get_last_error()
                try:
                    info = ctypes.create_string_buffer(24)
                    assert kernel.GetFileInformationByHandleEx(handle, 1, info, len(info)), ctypes.get_last_error()
                    assert struct.unpack_from('<QQ', info.raw) == expected
                    assert 0 <= expected[0] <= 4096
                finally:
                    kernel.CloseHandle(handle)
        else:
            assert reopened == [(4096, 14), (4096, 0)], reopened
        assert used() == 8192
        assert first.read(0, 14) == b'allocated data'
        allocate(second, 0)
        assert sizes(second) == (0, 0) and used() == 4096, (sizes(second), used())
        allocate(first, 8192)
        # Extending EOF within the reservation must not charge the same bytes again.
        eof = FileEndOfFileInformation()
        eof['end_of_file'] = 8192
        setinfo(first, eof)
        assert sizes(first) == (8192, 8192) and used() == 8192
        allocate(first, 4096)
        assert sizes(first) == (4096, 4096) and used() == 4096
        allocate(first, 0)
        assert sizes(first) == (0, 0) and used() == 0
        allocate(second, 8192)
        deletion = FileDispositionInformation()
        deletion['delete_pending'] = True
        setinfo(second, deletion)
        second.close()
        assert used() == 0
        replacement = create(tree, 'second')
        assert sizes(replacement) == (0, 0) and used() == 0
        allocate(replacement, 1)
        assert sizes(replacement) == (4096, 0) and used() == 1
        replacement.write(b'rounding')
        allocate(replacement, 1)
        assert sizes(replacement) == (4096, 8) and used() == 8
        allocate(replacement, 0)
        replacement.close()
        first.close()
        report['checks'].append('durable logical quota survives restart while allocation reports native close-time trimming; EOF extension consumes reservations; shrink and deletion release quota')
        def initial(name, size, disposition=3, access=0x13019f, raw=None, duplicate=False, options=0x40):
            context=SMB2CreateContextRequest()
            context['buffer_name']=b'AlSi'
            context['buffer_data']=struct.pack('<Q',size) if raw is None else raw
            handle=Open(tree,name)
            handle.create(ImpersonationLevel.Impersonation,access,0x80,7,disposition,options,
                          create_contexts=[context,context] if duplicate else [context])
            return handle
        preallocated=initial('created-allocation',4096)
        assert sizes(preallocated)==(4096,0) and used()==4096
        preallocated.write(b'keep on failed overwrite')
        denied(lambda:initial('over-quota-create',8192),0xc000007f)
        assert not (fixture.root/'allocation/over-quota-create').exists() and used()==4096
        denied(lambda:initial('created-allocation',16384,disposition=4),0xc000007f)
        assert preallocated.read(0,24)==b'keep on failed overwrite' and used()==4096
        for disposition in (1,3):
            ignored=initial('created-allocation',16384,disposition=disposition,access=0x120089)
            assert sizes(ignored)==(4096,24) and used()==4096
            ignored.close()
        eof['end_of_file']=8192;setinfo(preallocated,eof)
        assert used()==8192
        smaller=initial('created-allocation',4096,disposition=4)
        assert sizes(smaller)==(4096,0) and used()==4096
        smaller.close()
        for disposition in (4,5,0):
            overwritten=initial('created-allocation',4096,disposition=disposition)
            assert sizes(overwritten)==(4096,0) and used()==4096
            overwritten.write(b'next overwrite');overwritten.close()
        # Creation can reserve storage even when the returned handle is read-only.
        readonly=initial('readonly-allocation',4096,access=0x120089)
        assert sizes(readonly)==(4096,0) and used()==8192
        denied(lambda:readonly.write(b'x'),0xc0000022);readonly.close()
        for raw in (b'',b'\0'*7,b'\0'*9,struct.pack('<Q',2**63)):
            denied(lambda:initial('malformed-allocation',0,raw=raw),0xc000000d)
        denied(lambda:initial('duplicate-allocation',0,duplicate=True),0xc000000d)
        assert not (fixture.root/'allocation/malformed-allocation').exists()
        assert not (fixture.root/'allocation/duplicate-allocation').exists()
        directory=initial('allocation-directory',16384,options=1)
        assert used()==8192;directory.close()
        preallocated.close()
        report['checks'].append('AlSi CREATE/overwrite preallocation preserves zero EOF, charges durable quota, ignores existing opens/directories, validates context shape and fails over-quota before namespace/data mutation')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc()
        raise
    finally:
        for connection in clients:
            try:
                connection.disconnect(close=False)
            except Exception:
                pass
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        fixture.close()
    print(json.dumps(report))


if __name__ == '__main__':
    main()
