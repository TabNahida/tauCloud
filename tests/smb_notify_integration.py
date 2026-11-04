#!/usr/bin/env python3
"""Independent SMB CHANGE_NOTIFY: native events, FIFO, cancellation and security."""
import argparse
import json
import os
from pathlib import Path
import struct
import time
import traceback
import uuid
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.change_notify import SMB2ChangeNotifyRequest
from smbprotocol.open import SMB2SetInfoRequest
from smbprotocol.file_info import FileRenameInformation, FileDispositionInformation
from m5_integration import Fixture, create, denied, setinfo
from smb_blocking_locks import pending
from smb_security_integration import descriptor, ace, EVERYONE, set_sd


def notify(h, mask=3, recursive=False, limit=65536, interim=True):
    request = SMB2ChangeNotifyRequest()
    request['file_id'] = h.file_id
    request.fields['completion_filter'].flag_strict = False
    request['completion_filter'] = mask
    request['flags'] = int(recursive)
    request['output_buffer_length'] = limit
    result = h.connection.send(request, h.tree_connect.session.session_id, h.tree_connect.tree_connect_id)
    if interim: pending(result)
    return result


def events(c, request, asynchronous=True):
    response = c.receive(request, timeout=10)
    assert bool(response['flags'].get_value() & 2) == asynchronous
    assert response['credit_response'].get_value() == (0 if asynchronous else 1)
    packet = response.pack()
    size, offset, length = struct.unpack_from('<HHI', packet, 64)
    assert size == 9 and offset == 72 and length <= len(packet) - offset
    output, at = [], offset
    while True:
        nxt, action, n = struct.unpack_from('<III', packet, at)
        assert n % 2 == 0 and at + 12 + n <= offset + length
        output.append((action, packet[at+12:at+12+n].decode('utf-16-le')))
        if not nxt: break
        assert nxt % 4 == 0 and nxt >= 12 + n
        at += nxt
    return output


def run():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    args = p.parse_args(); f = None; clients = []
    report = dict(status='failed', checks=[])
    def passed(message): report['checks'].append(message); print('PASS ' + message, flush=True)
    try:
        f = Fixture(args.bin, 512 if args.sanitizers else 256)
        profile = next(x for x in f.api('protocols', f.admin) if x['id'] == 'smb')
        assert profile['change_notify'] and profile['persistent_acl']
        assert 'AES-256-GCM' in profile['ciphers'] and 'AES-256-CCM' in profile['ciphers']
        def connect(dialect=0x311):
            c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
            clients.append(c); c.connect(dialect=dialect)
            s = Session(c, username='TAUCLOUD\\alice', password=f.password,
                        require_encryption=dialect >= 0x300, auth_protocol='ntlm'); s.connect()
            t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect()
            return c, s, t
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, s, t = connect(dialect)
            path = 'notify-' + str(dialect)
            directory = create(t, path, options=1, access=0x120089)
            req = notify(directory)
            c.echo(sid=s.session_id, timeout=5)
            h = create(t, path + '/你好'); h.close()
            assert (1, '你好') in events(c, req)
            req = notify(directory)
            h = create(t, path + '/你好', disposition=1)
            rename = FileRenameInformation(); rename['file_name'] = path + '/renamed'
            setinfo(h, rename)
            result = events(c, req)
            assert result == [(4, '你好'), (5, 'renamed')], result
            req = notify(directory)
            delete = FileDispositionInformation(); delete['delete_pending'] = True
            setinfo(h, delete); h.close()
            assert (2, 'renamed') in events(c, req)
            req = notify(directory); req.cancel()
            denied(lambda: c.receive(req, timeout=10), 0xc0000120)
            req = notify(directory); directory.close()
            denied(lambda: c.receive(req, timeout=10), 0x10b)
            c.disconnect()
        passed('SMB2.1/3.0/3.0.2/3.1.1 signed/encrypted asynchronous create/rename/delete, live ECHO, CANCEL and CLOSE cleanup')

        c, s, t = connect()
        d = create(t, 'fifo', options=1, access=0x120089)
        first = notify(d, 1); second = notify(d, 2, recursive=True)
        child = create(t, 'fifo/dir', options=1); child.close()
        c.echo(sid=s.session_id); time.sleep(.1)
        assert first.response['status'].get_value() == second.response['status'].get_value() == 0x103
        h = create(t, 'fifo/one'); h.close(); assert events(c, first) == [(1, 'one')]
        assert second.response['status'].get_value() == 0x103
        h = create(t, 'fifo/two'); h.close(); assert events(c, second) == [(1, 'two')]
        # Events remain buffered between requests; new filters cannot change an open.
        h = create(t, 'fifo/buffered'); h.close()
        req = notify(d, 0, interim=False); assert events(c, req, asynchronous=False) == [(1, 'buffered')]
        # Mutations sent after an already-buffered request form the next batch.
        for i in range(10):
            h = create(t, 'fifo/batch-' + str(i)); h.close()
        req = notify(d, interim=False)
        h = create(t, 'fifo/after-request'); h.close()
        batch = events(c, req, asynchronous=False)
        assert batch == [(1, 'batch-' + str(i)) for i in range(10)], batch
        req = notify(d, interim=False)
        assert events(c, req, asynchronous=False) == [(1, 'after-request')]
        d.close()
        passed('per-open first filter/watch-tree settings, FIFO completion and events buffered between requests')

        root = f.root / 'smbdata'
        for recursive in (False, True):
            name = 'tree-' + str(recursive)
            d = create(t, name, options=1, access=0x120089); sub = create(t, name + '/sub', options=1); sub.close()
            req = notify(d, 1, recursive)
            (root / name / 'sub/host-file').write_bytes(b'host')
            if recursive: assert (1, 'sub\\host-file') in events(c, req)
            else:
                time.sleep(.1); assert req.response['status'].get_value() == 0x103
                req.cancel(); denied(lambda: c.receive(req, timeout=10), 0xc0000120)
            d.close()
        passed('native host writes trigger recursive watches while nonrecursive watches ignore descendants')

        if os.name != 'nt':
            name = 'moved-out'
            d = create(t, name, options=1, access=0x120089)
            sub = create(t, name + '/sub', options=1); sub.close()
            req = notify(d, 1, True)
            outside = f.base / 'outside-watch'
            (root / name / 'sub').rename(outside)
            (outside / 'private').write_bytes(b'not exported')
            time.sleep(.1)
            assert req.response['status'].get_value() == 0x103
            (root / name / 'public').write_bytes(b'exported')
            assert events(c, req) == [(1, 'public')]
            d.close()
            passed('recursive watches stop observing moved-out subtrees and do not disclose queued outside names')

        d = create(t, 'size-filter', options=1, access=0x120089)
        h = create(t, 'size-filter/file'); h.write(b'1234'); h.close()
        req = notify(d, 8)
        h = create(t, 'size-filter/file', disposition=1); h.write(b'5678'); h.flush(); h.close()
        time.sleep(.1)
        assert req.response['status'].get_value() == 0x103
        h = create(t, 'size-filter/file', disposition=1); h.write(b'longer'); h.flush(); h.close()
        assert events(c, req) == [(3, 'file')]; d.close()
        passed('SIZE filter ignores equal-length writes and reports actual growth')

        d = create(t, 'write-filter', options=1, access=0x120089)
        req = notify(d, 16)
        (root / 'write-filter' / 'new-file').write_bytes(b'created and written together')
        assert (3, 'new-file') in events(c, req); d.close()
        passed('LAST_WRITE observes new-file writes even when native CREATE and WRITE are drained together')

        for limit in (0, 1, 12):
            d = create(t, 'overflow-' + str(limit), options=1)
            req = notify(d, 1, limit=limit)
            h = create(t, d.file_name + '/long-name'); h.close()
            denied(lambda: c.receive(req, timeout=10), 0x10c)
            req = notify(d, 1)
            h = create(t, d.file_name + '/next'); h.close()
            denied(lambda: c.receive(req, timeout=10), 0x10c); d.close()
            d = create(t, 'overflow-' + str(limit), options=1, disposition=1)
            req = notify(d, 1)
            h = create(t, d.file_name + '/reopened'); h.close()
            assert events(c, req) == [(1, 'reopened')]; d.close()
        d = create(t, 'zero-filter', options=1); req = notify(d, 0x80000000)
        h = create(t, 'zero-filter/ignored'); h.close(); time.sleep(.1)
        assert req.response['status'].get_value() == 0x103
        req.cancel(); denied(lambda: c.receive(req, timeout=10), 0xc0000120); d.close()
        passed('first per-open zero/short capacity persists, reopening restores capacity; NOTIFY_ENUM_DIR has no partial records; invalid-only filters stay pending and cancel cleanly')

        h = create(t, 'not-directory')
        denied(lambda: c.receive(notify(h, interim=False), timeout=10), 0xc000000d); h.close()
        h = create(t, 'no-list', access=0x80, options=1)
        denied(lambda: c.receive(notify(h, interim=False), timeout=10), 0xc0000022); h.close()
        d = create(t, 'security-watch', options=1)
        h = create(t, 'security-watch/file', access=0x1f01ff)
        req = notify(d, 0x100)
        set_sd(h, descriptor([ace(EVERYONE, 0x120089)]))
        assert (3, 'file') in events(c, req); h.close(); d.close()
        passed('directory/list-access validation and persistent shared security descriptor changes generate SECURITY notifications')

        for mask, klass, data in (
            (4, 4, struct.pack('<QQQQII', 0, 0, 0, 0, 2, 0)),
            (64, 4, struct.pack('<QQQQII', 133000000000000000, 0, 0, 0, 0, 0)),
            (128, 15, struct.pack('<IBBH', 0, 0, 1, 1) + b'X\0Y'),
        ):
            name = 'metadata-' + str(mask)
            d = create(t, name, options=1, access=0x120089)
            h = create(t, name + '/file'); req = notify(d, mask)
            q = SMB2SetInfoRequest(); q['info_type'] = 1; q['file_info_class'] = klass
            q['file_id'] = h.file_id; q['buffer'] = data
            c.receive(c.send(q, s.session_id, t.tree_connect_id))
            assert events(c, req) == [(3, 'file')]
            h.close(); d.close()
        passed('portable DOS attributes, creation-time and EA changes participate in native notification streams')

        d = create(t, 'initial-metadata', options=1, access=0x120089)
        req = notify(d, 0x185)  # FILE_NAME, ATTRIBUTES, EA, SECURITY.
        h = create(t, 'initial-metadata/file', access=0x1f01ff)
        assert events(c, req) == [(1, 'file')]
        req = notify(d)
        set_sd(h, descriptor([ace(EVERYONE, 0x120089)]))
        assert events(c, req) == [(3, 'file')]
        h.close(); d.close()
        passed('initial CREATE metadata produces only ADDED; subsequent changes still produce MODIFIED')

        if os.name != 'nt':
            name = 'watch-cap'
            d = create(t, name, options=1, access=0x120089)
            for index in range(100): (root / name / str(index)).mkdir()
            for _ in range(2):
                req = notify(d, 1, True, interim=False)
                denied(lambda: c.receive(req, timeout=10), 0x10c)
                assert not req.response['flags'].get_value() & 2
                assert req.response['credit_response'].get_value() == 1
                assert req.response['data'].get_value() == struct.pack('<HHI', 9, 0, 0)
            d.close()
            passed('recursive descriptor exhaustion stays visibly overflowed across requests and releases all watches on close')

        d = create(t, 'delete-watch', options=1, access=0x120089)
        req = notify(d)
        h = create(t, 'delete-watch', options=1, disposition=1)
        delete = FileDispositionInformation(); delete['delete_pending'] = True
        setinfo(h, delete); h.close()
        denied(lambda: c.receive(req, timeout=10), 0xc0000056); d.close()
        passed('delete-pending directories complete outstanding watches without waiting for last-handle deletion')

        for cleanup in ('tree', 'session'):
            other, session, tree = connect()
            d = create(tree, 'cleanup-' + cleanup, options=1)
            req = notify(d)
            # Send protocol teardown without the client's convenience CLOSEs.
            if cleanup == 'tree':
                from smbprotocol.tree import SMB2TreeDisconnect
                request = other.send(SMB2TreeDisconnect(), session.session_id, tree.tree_connect_id)
            else:
                from smbprotocol.session import SMB2Logoff
                request = other.send(SMB2Logoff(), session.session_id)
            other.receive(request)
            denied(lambda: other.receive(req, timeout=10), 0x10b)
            other.disconnect(close=False)
        passed('TREE_DISCONNECT and LOGOFF finish pending notifications with NOTIFY_CLEANUP before releasing keys')

        d = create(t, 'revoke-watch', options=1); req = notify(d)
        f.api('grants', f.admin, dict(space='smbdata', subject_type='user', subject='alice', rights='r'))
        # A poll already holding an older authorization grant can lose the
        # epoch race and return ACCESS_DENIED; a later poll sees FILE_CLOSED.
        # After the completed revocation, the old handle must be gone in either
        # case, and an exclusive read open proves its sharing/watch is released.
        denied(lambda: c.receive(req, timeout=10), 0xc0000128, 0xc0000022)
        from m5_integration import query
        denied(lambda: query(d, 5), 0xc0000128)
        fresh = create(t, 'revoke-watch', access=0x120089, disposition=1, share=0, options=1)
        fresh.close()
        c.disconnect(close=False)
        passed('policy revocation denies the pending poll, invalidates its old handle and permits a fresh exclusive read open without retained watch/sharing authority')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush(); report['server_log'] = (f.base/'supervisor.log').read_text(errors='replace')[-8000:]
    finally:
        for c in clients:
            try: c.disconnect(close=False)
            except Exception: pass
        if f: f.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(run())
