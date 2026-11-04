#!/usr/bin/env python3
"""Real signed/encrypted SMB lease CREATE, shared recalls and cross-connection ACKs."""
import argparse
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
from pathlib import Path
import platform
import queue
import struct
import time
import traceback
import uuid

from smbprotocol.connection import Connection, SMB2HeaderResponse, SMB2TransformHeader
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open
from smbprotocol.create_contexts import SMB2CreateContextRequest
from smbprotocol.structure import Structure, IntField, BytesField
from m5_integration import Fixture, create, denied
from smb_blocking_locks import pending
from smb_oplock_integration import native_read, native_write


class Ack(Structure):
    COMMAND = 18
    def __init__(self, key, state):
        self.fields = OrderedDict([
            ('size', IntField(size=2, default=36)), ('reserved', IntField(size=2)),
            ('flags', IntField(size=4)), ('key', BytesField(size=16, default=key)),
            ('state', IntField(size=4, default=state)), ('duration', IntField(size=8))])
        super().__init__()


def capture_breaks(c, received):
    original = c.transport.recv
    def receive(timeout):
        while True:
            raw = original(timeout)
            if not raw: return raw
            encrypted = raw[:4] == b'\xfdSMB'
            plain = raw
            if encrypted:
                transform = SMB2TransformHeader(); transform.unpack(raw)
                plain = c._decrypt(transform)
            if (len(plain) >= 64 and struct.unpack_from('<Q', plain, 24)[0] == 2**64-1 and
                    struct.unpack_from('<H', plain, 12)[0] == 18):
                h = SMB2HeaderResponse(); h.unpack(plain)
                assert len(plain) == 108 and h['status'].get_value() == 0
                assert h['flags'].get_value() == 1 and h['credit_response'].get_value() == 0
                assert plain[36:64] == bytes(28)  # TreeId, SessionId and signature
                size, epoch, flags, key, current, target, reason, access, share = struct.unpack('<HHI16sIIIII', plain[64:])
                assert size == 44 and flags in (0, 1) and (reason, access, share) == (0, 0, 0)
                received.put((key, current, target, epoch, flags, encrypted))
                continue
            return raw
    c.transport.recv = receive


def lease_context(key, state=7, version=2, epoch=0, flags=0):
    data = key + struct.pack('<IIQ', state, flags, 0)
    if version == 2: data += bytes(16) + struct.pack('<HH', epoch, 0)
    c = SMB2CreateContextRequest(); c['buffer_name'] = b'RqLs'; c['buffer_data'] = data
    return c


def leased(t, name, key, state=7, version=2, epoch=0, send=True, disposition=3, access=0x13019f):
    h = Open(t, name)
    result = h.create(2, access, 0x80, 7, disposition, 0x40, oplock_level=255,
                      create_contexts=[lease_context(key, state, version, epoch)], send=send)
    return h, result


def response(contexts, key, state, version=2, epoch=None, breaking=False):
    assert contexts and len(contexts) == 1, contexts
    data = contexts[0].pack()
    assert len(data) == (32 if version == 1 else 52), data.hex()
    assert data[:16] == key and struct.unpack_from('<I', data, 16)[0] == state, data.hex()
    assert struct.unpack_from('<I', data, 20)[0] == (2 if breaking else 0), data.hex()
    assert data[24:32] == bytes(8)
    if version == 2:
        assert data[32:48] == bytes(16) and data[50:] == bytes(2)
        if epoch is not None: assert struct.unpack_from('<H', data, 48)[0] == epoch, data.hex()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', required=True); p.add_argument('--output', required=True, type=Path)
    a = p.parse_args(); f = None; clients = []
    report = dict(status='failed', host=platform.platform(), checks=[],
                  recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    def passed(text):
        report['checks'].append(text); print('PASS ' + text, flush=True)
    def connect(dialect=0x311, guid=None, received=None):
        c = Connection(guid or uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        clients.append(c); c.connect(dialect=dialect, timeout=10)
        assert c.server_capabilities.get_value() & 2
        assert not c.server_capabilities.get_value() & (8 | 32)  # multichannel/directory leasing
        q = received if received is not None else queue.Queue(); capture_breaks(c, q)
        s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=dialect >= 0x300, auth_protocol='ntlm')
        s.connect(); t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect()
        return c, s, t, q
    def ack(c, s, t, key, state):
        r = c.receive(c.send(Ack(key, state), s.session_id, t.tree_connect_id), timeout=10)
        assert r['data'].get_value() == struct.pack('<HHI16sIQ', 36, 0, 0, key, state, 0)
    def begin(h, result):
        message, receive = result; t = h.tree_connect
        r = t.session.connection.send(message, t.session.session_id, t.tree_connect_id)
        pending(r); return r, receive
    try:
        f = Fixture(a.bin, memory=1024)
        for dialect in (0x210, 0x300, 0x302, 0x311):
            version = 1 if dialect == 0x210 else 2
            guid = uuid.uuid4(); c, s, t, q = connect(dialect, guid)
            peer, ps, pt, _ = connect(dialect, guid, q)
            foreign, fs, ft, fq = connect(dialect)
            key = uuid.uuid4().bytes; name = f'lease-{dialect:x}'
            h, ctx = leased(t, name, key, version=version, epoch=10)
            assert h.oplock_level == 255; response(ctx, key, 7, version, 11)
            h.write(b'old bytes'); time.sleep(2.6)
            sibling, ctx = leased(pt, name, key, version=version, epoch=500)
            response(ctx, key, 7, version, 11); assert sibling.read(0, 9) == b'old bytes'
            assert q.empty()
            denied(lambda: ack(c, s, t, key, 7), 0xc0000001)
            other, result = leased(ft, name, uuid.uuid4().bytes, state=0, version=version, send=False)
            request, receive = begin(other, result)
            assert q.get(timeout=10) == (key, 7, 3, 0 if version == 1 else 12, 1, s.encrypt_data)
            denied(lambda: ack(c, s, t, key, 7), 0xc00000d0)
            denied(lambda: ack(foreign, fs, ft, key, 3), 0xc0000034)
            join, ctx = leased(pt, name, key, version=version)
            response(ctx, key, 7, version, 12, breaking=True)
            h.write(b'new bytes'); h.flush()
            ack(peer, ps, pt, key, 3); receive(request)
            assert other.read(0, 9) == b'new bytes'
            # A foreign WRITE invalidates the shared RH state only once.
            msg, receive_write = other.write(b'changed!!', send=False)
            wr = foreign.send(msg, fs.session_id, ft.tree_connect_id); pending(wr)
            assert q.get(timeout=10) == (key, 3, 0, 0 if version == 1 else 13, 1, s.encrypt_data)
            ack(c, s, t, key, 0); assert receive_write(wr) == 9
            assert sibling.read(0, 9) == b'changed!!' and q.empty()
            denied(lambda: ack(peer, ps, pt, key, 0), 0xc0000001)
            for handle in (join, sibling, h, other): handle.close()
            for conn in (c, peer, foreign): conn.disconnect()
            passed(f'{dialect:x}: v{version} shared lease survives renewal, joins during recall, validates client/key/ACK state and coherently breaks RWH to RH to NONE')

        c, s, t, q = connect(); peer, ps, pt, pq = connect(0x311, c.client_guid, q)
        key = uuid.uuid4().bytes
        h, ctx = leased(t, 'cross-ack', key); response(ctx, key, 7, epoch=1)
        # The ACK transport has no handle for this key: route by ClientGuid.
        with ThreadPoolExecutor() as pool:
            read = pool.submit(native_read, f.root/'smbdata/cross-ack')
            assert q.get(timeout=10)[:3] == (key, 7, 0)
            ack(peer, ps, pt, key, 0); assert read.result(timeout=10) == b''
        h.close(); passed('same-client authenticated transport without an open routes the native recall ACK to the owning connection')

        key = uuid.uuid4().bytes
        h, ctx = leased(t, 'read-only-cache', key, state=1); response(ctx, key, 1, epoch=1)
        with ThreadPoolExecutor() as pool:
            write = pool.submit(native_write, f.root/'smbdata/read-only-cache', b'native')
            assert q.get(timeout=10) == (key, 1, 0, 2, 0, True)
            assert write.result(timeout=10) == 6
        assert h.read(0, 6) == b'native'; h.close()
        passed('R-only native invalidation delivers an encrypted no-ACK break before releasing exclusion')

        key = uuid.uuid4().bytes
        h, ctx = leased(t, 'reserved-key', key, state=0); response(ctx, key, 0, epoch=0)
        denied(lambda: leased(pt, 'wrong-name', key), 0xc000000d)
        h.close()
        h, ctx = leased(pt, 'wrong-name', key); response(ctx, key, 7, epoch=1); h.close()
        missing = uuid.uuid4().bytes
        denied(lambda: leased(t, 'missing-file', missing, disposition=1), 0xc0000034)
        h, ctx = leased(pt, 'after-failure', missing); response(ctx, missing, 7, epoch=1); h.close()
        passed('global key/name reservation covers NONE leases, rejects another path and is released after final close or failed CREATE')
        for version in (1, 2):
            for state in range(8):
                key = uuid.uuid4().bytes
                h, ctx = leased(t, f'combination-{version}-{state}', key, state=state, version=version)
                granted = state if state & 1 else 0
                response(ctx, key, granted, version, int(bool(granted))); h.close()
        passed('all eight v1/v2 requested state combinations return legal grants; H/W without READ succeeds with NONE')

        key = uuid.uuid4().bytes
        h, ctx = leased(t, 'promote-none', key, state=0); response(ctx, key, 0, epoch=0)
        sibling, ctx = leased(pt, 'promote-none', key); response(ctx, key, 7, epoch=1)
        sibling.write(b'retained'); sibling.close(); time.sleep(2.6)
        with ThreadPoolExecutor() as pool:
            read = pool.submit(native_read, f.root/'smbdata/promote-none')
            assert q.get(timeout=10) == (key, 7, 0, 2, 1, True)
            ack(peer, ps, pt, key, 0); assert read.result(timeout=10) == b'retained'
        h.close()
        passed('an original NONE member renews promoted shared authority after the promoting member closes')

        key = uuid.uuid4().bytes; foreign_key = uuid.uuid4().bytes
        h, ctx = leased(t, 'partial-promotion', key, state=1); response(ctx, key, 1, epoch=1)
        neighbor, ctx = leased(pt, 'partial-promotion', foreign_key, state=3)
        response(ctx, foreign_key, 3, epoch=1)
        join, ctx = leased(t, 'partial-promotion', key)
        response(ctx, key, 1, epoch=1)
        for handle in (join, neighbor, h): handle.close()
        passed('a conflicting lease prevents partial promotion of an existing R lease to RH when RWH was requested')

        # Test parser boundaries independently of the client's typed contexts.
        key = uuid.uuid4().bytes
        def custom(contexts, level=255, tree=t, name='lease-parser'):
            handle = Open(tree, name)
            result = handle.create(2, 0x13019f, 0x80, 7, 3, 0x40,
                                   oplock_level=level, create_contexts=contexts)
            return handle, result
        for size in (0, 31, 33, 51, 53):
            ctx = SMB2CreateContextRequest(); ctx['buffer_name'] = b'RqLs'; ctx['buffer_data'] = bytes(size)
            denied(lambda: custom([ctx]), 0xc000000d)
        denied(lambda: custom([lease_context(key, 8)]), 0xc000000d)
        denied(lambda: custom([lease_context(key), lease_context(key)]), 0xc000000d)
        h, ctx = custom([lease_context(key, flags=0xfffffff9)])
        response(ctx, key, 7, epoch=1); h.close()
        h, ctx = custom([lease_context(key)], level=0)
        assert h.oplock_level == 0 and not ctx; h.close()
        old, olds, oldt, oldq = connect(0x210)
        h, ctx = custom([lease_context(key)], tree=oldt)
        assert h.oplock_level == 0 and not ctx; h.close(); old.disconnect()
        passed('malformed sizes, unknown state bits and duplicate lease contexts fail; reserved flags are ignored and v2 is ignored on SMB 2.1')

        other, osession, ot, oq = connect()
        key = uuid.uuid4().bytes
        h, ctx = leased(t, 'client-isolation-a', key); response(ctx, key, 7, epoch=1)
        independent, ctx = leased(ot, 'client-isolation-b', key); response(ctx, key, 7, epoch=1)
        h.close(); independent.close()
        passed('the same LeaseKey under different client GUIDs identifies independent leases')

        # No ACK: the stale transport must be fenced before a native writer
        # can modify the file. A fresh client then reads the committed bytes.
        stale, ss, st, sq = connect()
        key = uuid.uuid4().bytes
        h, ctx = leased(st, 'unacknowledged-lease', key); h.write(b'previous')
        with ThreadPoolExecutor() as pool:
            write = pool.submit(native_write, f.root/'smbdata/unacknowledged-lease', b'current!')
            assert sq.get(timeout=10)[:3] == (key, 7, 0)
            assert write.result(timeout=10) == 8
            end = time.monotonic() + 3
            while stale.transport.connected and time.monotonic() < end: time.sleep(.02)
            assert not stale.transport.connected
        fresh = create(ot, 'unacknowledged-lease', disposition=1)
        assert fresh.read(0, 8) == b'current!'; fresh.close()
        passed('unacknowledged native recall fences stale lease authority before admitting the native writer')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush(); report['server_log'] = (f.base/'supervisor.log').read_text(errors='replace')[-16000:]
            log = f.state/'logs/smb.jsonl'
            report['smb_log'] = log.read_text(errors='replace')[-16000:] if log.exists() else ''
    finally:
        for c in clients:
            try: c.disconnect(close=False)
            except Exception: pass
        if f:
            try: f.close()
            except Exception:
                report['status'] = 'failed'; report['cleanup_error'] = traceback.format_exc()
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(report, indent=2)+'\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(main())
