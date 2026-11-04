#!/usr/bin/env python3
"""SMB exclusive cache grants, native exclusion, asynchronous recall and ACK."""
import argparse
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
import datetime
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import queue
import struct
import socket
import signal
import http.client
import time
import traceback
import uuid

from smbprotocol.connection import Connection, SMB2HeaderResponse, SMB2TransformHeader
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open, SMB2SetInfoRequest
from smbprotocol.file_info import FileEndOfFileInformation, FileBasicInformation
from smbprotocol.structure import Structure, IntField, BytesField
from m5_integration import Fixture, create, denied, query
from smb_blocking_locks import pending


class Ack(Structure):
    COMMAND = 18
    def __init__(self, fid, level=0):
        self.fields = OrderedDict([
            ('size', IntField(size=2, default=24)), ('level', IntField(size=1, default=level)),
            ('reserved', BytesField(size=5, default=bytes(5))), ('fid', BytesField(size=16, default=fid))])
        super().__init__()


def capture_breaks(c, include_level=False):
    """smbprotocol has no unsolicited handler: consume only verified break frames.

    Keep its transport, authentication, encryption and ordinary reply parser.
    No server-side hooks or private IPC credentials participate in this test.
    """
    received = queue.Queue()
    original = c.transport.recv
    def receive(timeout):
        while True:
            raw = original(timeout)
            if not raw: return raw
            encrypted = raw[:4] == b'\xfdSMB'
            plain = raw
            if encrypted:
                transform = SMB2TransformHeader(); transform.unpack(raw)
                plain = c._decrypt(transform)  # independent AEAD tag verification
            if (len(plain) >= 64 and struct.unpack_from('<Q', plain, 24)[0] == 2**64-1 and
                    struct.unpack_from('<H', plain, 12)[0] == 18):
                h = SMB2HeaderResponse(); h.unpack(plain)
                assert len(plain) == 88 and h['status'].get_value() == 0
                assert h['flags'].get_value() == 1  # spec recommends unsigned break
                assert plain[48:64] == bytes(16) and plain[36:40] == bytes(4)
                assert h['credit_response'].get_value() == 0
                assert struct.unpack_from('<H', plain, 64)[0] == 24 and plain[66] in (0, 1)
                item = (h['session_id'].get_value(), plain[72:88], encrypted)
                if include_level: item += (plain[66],)
                else: assert plain[66] == 0
                received.put(item)
                continue
            return raw
    c.transport.recv = receive
    return received


@contextmanager
def native_file(path, writing=False):
    if os.name != 'nt':
        with path.open('r+b' if writing else 'rb') as stream:
            yield stream
        return
    # Match the platform's sharing contract, including DELETE sharing. CRT
    # fopen omits that bit and can fail before a native oplock is even examined.
    import ctypes
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]; kernel.CloseHandle.restype = w.BOOL
    kernel.ReadFile.argtypes = [w.HANDLE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID]
    kernel.ReadFile.restype = w.BOOL
    kernel.WriteFile.argtypes = [w.HANDLE, w.LPCVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID]
    kernel.WriteFile.restype = w.BOOL
    handle = kernel.CreateFileW(str(path), 0xc0000000 if writing else 0x80000000, 7, None, 3, 0x80, None)
    if handle == w.HANDLE(-1).value: raise ctypes.WinError(ctypes.get_last_error())
    class Stream:
        def read(self):
            data = ctypes.create_string_buffer(65536); size = w.DWORD()
            if not kernel.ReadFile(handle, data, len(data), ctypes.byref(size), None):
                raise ctypes.WinError(ctypes.get_last_error())
            return data.raw[:size.value]
        def write(self, data):
            buffer = ctypes.create_string_buffer(data); size = w.DWORD()
            if not kernel.WriteFile(handle, buffer, len(data), ctypes.byref(size), None):
                raise ctypes.WinError(ctypes.get_last_error())
            return size.value
    try: yield Stream()
    finally: kernel.CloseHandle(handle)


def native_read(path):
    with native_file(path) as stream: return stream.read()


def native_write(path, data):
    with native_file(path, True) as stream: return stream.write(data)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', required=True)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    f = None; clients = []
    report = dict(status='failed', host=platform.platform(), checks=[],
                  recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    def passed(text):
        report['checks'].append(text); print('PASS ' + text, flush=True)
    def connect(dialect=0x311):
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        clients.append(c)
        # connect creates the transport before starting the receive thread.
        c.connect(dialect=dialect, timeout=10)
        q = capture_breaks(c)
        # Wake the already blocked original receive before expecting a break.
        s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=dialect >= 0x300, auth_protocol='ntlm')
        s.connect(); t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect()
        return c, s, t, q
    def cached(t, name, **kw):
        h = Open(t, name)
        h.create(2, kw.get('access', 0x13019f), 0x80, kw.get('share', 7), 3,
                 kw.get('options', 0x40), oplock_level=8)
        assert h.oplock_level == kw.get('expected', 8), h.oplock_level
        return h
    def recalled(q, s, h):
        assert q.get(timeout=10) == (s.session_id, h.file_id, s.encrypt_data)
    def ack(c, s, t, h, level=0, fid=None):
        r = c.receive(c.send(Ack(h.file_id if fid is None else fid, level), s.session_id, t.tree_connect_id), timeout=10)
        assert r['data'].get_value() == struct.pack('<H',24) + bytes(6) + h.file_id
    def begin(t, name):
        h = Open(t, name)
        message, receive = h.create(2, 0x13019f, 0x80, 7, 1, 0x40, send=False)
        r = t.session.connection.send(message, t.session.session_id, t.tree_connect_id)
        pending(r)
        return h, r, receive
    try:
        f = Fixture(a.bin)
        f.stop()
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0)); nfs_port = probe.getsockname()[1]
        config = json.loads((f.state/'config.json').read_text()); config['nfs_port'] = nfs_port
        (f.state/'config.json').write_text(json.dumps(config)); f.start()
        f.api('shares', f.admin, dict(id='cache-read', space='smbdata', exposures={'nfs':'r', 'webdav':'r'}))
        f.api('groups', f.admin, dict(name='unix'))
        f.api('memberships', f.admin, dict(username='alice', group='unix'))
        f.api('nfs-exports', f.admin, dict(id='cache-read', trust='loopback-auth-sys', anonymous='bob',
                                          uids={'1000':'alice'}, gids={'1000':'unix'}))
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, s, t, q = connect(dialect)
            holder = cached(t, f'oplock-{dialect:x}'); holder.write(b'old bytes')
            denied(lambda: ack(c, s, t, holder), 0xc0000184)
            # Native exclusion should survive an otherwise idle lease interval.
            time.sleep(2.6); assert holder.read(0, 9) == b'old bytes'
            other, request, receive = begin(t, holder.file_name)
            recalled(q, s, holder); c.echo(sid=s.session_id, timeout=5)
            denied(lambda: ack(c, s, t, holder, fid=uuid.uuid4().bytes), 0xc0000128)
            holder.write(b'new bytes'); holder.flush()
            assert request.response['status'].get_value() == 0x103
            ack(c, s, t, holder); receive(request)
            assert request.response['flags'].get_value() & 2
            assert request.response['credit_response'].get_value() == 0
            assert other.read(0, 9) == b'new bytes'
            denied(lambda: ack(c, s, t, holder), 0xc0000184)
            other.close(); holder.close()
            passed(f'{dialect:x}: EXCLUSIVE grant survives idle renewal, same-transport CREATE waits, break is bound to session/FileId, holder flush precedes ACK and final read sees new bytes')

            holder = cached(t, f'compound-cache-{dialect:x}'); holder.write(b'previous')
            other = Open(t, holder.file_name)
            opening, receive_open = other.create(2, 0x13019f, 0x80, 7, 1, 0x40, send=False)
            read, receive_read = holder.read(0, 8, send=False); read['file_id'] = b'\xff'*16
            close, receive_close = holder.close(send=False); close['file_id'] = b'\xff'*16
            requests = c.send_compound([opening, read, close], s.session_id, t.tree_connect_id, related=True)
            for request in requests: pending(request)
            recalled(q, s, holder); holder.write(b'current!'); ack(c, s, t, holder)
            receive_open(requests[0]); assert receive_read(requests[1]) == b'current!'
            # Parse the close response without marking the original holder closed.
            other._close_response(requests[2]); holder.close()
            passed(f'{dialect:x}: cache-conflicting related CREATE/READ/CLOSE keeps all descendants pending and resolves the newly generated FileId after ACK')

            holder = cached(t, f'cancel-cache-{dialect:x}')
            other, request, receive = begin(t, holder.file_name)
            recalled(q, s, holder); request.cancel()
            denied(lambda: c.receive(request, timeout=10), 0xc0000120)
            holder.write(b'flush after cancel'); ack(c, s, t, holder)
            assert holder.read(0, 18) == b'flush after cancel'
            other = create(t, holder.file_name, disposition=1)
            assert other.read(0, 18) == b'flush after cancel'
            holder.close(); other.close(); c.disconnect()
            passed(f'{dialect:x}: CANCEL abandons a conflicting CREATE without cancelling the holder recall or leaking an open')

        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, s, t, q = connect(dialect)
            peer_c, peer_s, peer_t, peer_q = connect(dialect)
            holder = cached(t, f'attributes-only-{dialect:x}', share=0)
            holder.write(b'cached data')
            attributes = cached(peer_t, holder.file_name, access=0x100180, share=0, expected=0)
            assert len(query(attributes, 4)) == 40
            denied(lambda: attributes.read(0, 1), 0xc0000022)
            denied(lambda: attributes.write(b'x'), 0xc0000022)
            attributes.close()
            time.sleep(.4); assert q.empty() and peer_q.empty()
            holder.write(b'still cached')
            attributes = cached(peer_t, holder.file_name, access=0x100180, share=0, expected=0)
            basic = FileBasicInformation(); basic['file_attributes'] = 0x22
            change = SMB2SetInfoRequest(); change['info_type'] = 1
            change['file_info_class'] = basic.INFO_CLASS; change['file_id'] = attributes.file_id
            change['buffer'] = basic
            request = peer_c.send(change, peer_s.session_id, peer_t.tree_connect_id)
            pending(request); recalled(q, s, holder)
            holder.write(b'latest bytes'); holder.flush(); ack(c, s, t, holder)
            peer_c.receive(request, timeout=10)
            assert struct.unpack_from('<I', query(attributes, 4), 32)[0] == 0x22
            assert holder.read(0, 12) == b'latest bytes'
            holder.close(); attributes.close(); peer_c.disconnect(); c.disconnect()
            passed(f'{dialect:x}: a separate attribute-only OPEN_IF/query/close preserves EXCLUSIVE despite share-none; data access is denied and an actual attribute mutation recalls before committing')

        c, s, t, q = connect()
        holder = cached(t, 'sharing-cache', share=0)
        denied(lambda: create(t, holder.file_name, disposition=1), 0xc0000043)
        denied(lambda: create(t, holder.file_name, access=0x02000000, disposition=1), 0xc0000043)
        time.sleep(.4); assert q.empty(), 'sharing violation unnecessarily recalled the cache'
        holder.write(b'still cached'); holder.close()
        cached(t, 'readonly-open', access=0x120089, expected=0).close()
        cached(t, 'directory-open', options=1, expected=0).close()
        cached(t, 'delete-on-close', options=0x1040, expected=0).close()
        h = create(t, 'host-held'); h.write(b'data'); h.close()
        with native_file(f.root/'smbdata/host-held') as native:
            cached(t, 'host-held', expected=0).close()
            assert native.read() == b'data'
        passed('sharing violations do not recall dirty caches; readonly, directory, delete-on-close and conflicting native opens receive no unsupported cache grant')

        holder = cached(t, 'bad-ack')
        other, request, receive = begin(t, holder.file_name)
        recalled(q, s, holder)
        denied(lambda: ack(c, s, t, holder, level=255), 0xc000000d)
        receive(request); other.close()
        denied(lambda: ack(c, s, t, holder), 0xc0000184)
        holder.close()
        passed('a lease-form ACK for a classic oplock is rejected and finishes the recall without leaving native exclusion stuck')

        extra = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=True, auth_protocol='ntlm')
        extra.connect(); extra_tree = TreeConnect(extra, r'\\127.0.0.1\smb'); extra_tree.connect()
        first = cached(t, 'first-session-cache'); second = cached(extra_tree, 'second-session-cache')
        first.write(b'original'); second.write(b'second!!')
        time.sleep(2.6)
        other, request, receive = begin(extra_tree, first.file_name)
        recalled(q, s, first)
        denied(lambda: ack(c, extra, extra_tree, first), 0xc0000128)
        first.write(b'new data'); ack(c, s, t, first); receive(request)
        assert other.read(0, 8) == b'new data' and second.read(0, 8) == b'second!!'
        other.close(); first.close(); second.close(); extra.disconnect()
        passed('two encrypted sessions on one transport renew independent cache authority and route breaks/ACKs with their own keys; a foreign-session ACK cannot release another open')

        holder = cached(t, 'native-cache'); holder.write(b'old bytes')
        with ThreadPoolExecutor(max_workers=1) as pool:
            read = pool.submit(native_read, f.root/'smbdata/native-cache')
            recalled(q, s, holder); assert not read.done()
            holder.write(b'new bytes'); holder.flush(); ack(c, s, t, holder)
            assert read.result(timeout=10) == b'new bytes'
        holder.close()
        holder = cached(t, 'native-write'); holder.write(b'old bytes')
        with ThreadPoolExecutor(max_workers=1) as pool:
            write = pool.submit(native_write, f.root/'smbdata/native-write', b'host data')
            recalled(q, s, holder); assert not write.done()
            holder.write(b'new bytes'); ack(c, s, t, holder)
            assert write.result(timeout=10) == 9
            assert holder.read(0, 9) == b'host data'
        holder.close()
        passed('native host reads/writes wait for SMB recall; dirty client data flushes before host access and the original handle observes subsequent native writes')

        holder = cached(t, 'metadata-cache'); holder.write(b'original')
        eof = FileEndOfFileInformation(); eof['end_of_file'] = 4
        set_info = SMB2SetInfoRequest(); set_info['info_type'] = 1
        set_info['file_info_class'] = eof.INFO_CLASS; set_info['file_id'] = holder.file_id
        set_info['buffer'] = eof
        request = c.send(set_info, s.session_id, t.tree_connect_id); pending(request)
        recalled(q, s, holder); holder.write(b'latest!!'); ack(c, s, t, holder)
        response = c.receive(request, timeout=10)
        assert response['flags'].get_value() & 2 and response['credit_response'].get_value() == 0
        assert holder.read(0, 4) == b'late'; holder.close()
        passed('SET_INFO recalls before mutation, permits cached flush while pending and applies EOF after ACK without replaying side effects')

        holder = Open(t, 'create-then-eof')
        opening, receive_open = holder.create(2, 0x13019f, 0x80, 7, 3, 0x40, oplock_level=8, send=False)
        set_info['file_id'] = b'\xff'*16
        reader, receive_read = holder.read(0, 4, send=False); reader['file_id'] = b'\xff'*16
        requests = c.send_compound([opening, set_info, reader], s.session_id, t.tree_connect_id, related=True)
        receive_open(requests[0]); assert holder.oplock_level == 8
        pending(requests[1]); pending(requests[2]); recalled(q, s, holder)
        holder.write(b'content!'); ack(c, s, t, holder)
        c.receive(requests[1], timeout=10); assert receive_read(requests[2]) == b'cont'
        holder.close()
        passed('a new cached CREATE is announced before its own compound SET_INFO recall; asynchronous retries preserve the inherited FileId through the dependent READ')

        # Obtain an NFS handle before the SMB cache exists; otherwise LOOKUP
        # itself may legitimately need a recall to obtain fresh attributes.
        from m7_integration import Client, t3
        nfs = Client(nfs_port)
        try:
            status, root = nfs.mount(b'/cache-read'); assert status == 0
            h = create(t, 'nfs-cache'); h.write(b'original'); h.close()
            lookup = nfs.v3('LOOKUP', t3.LOOKUP3args(t3.diropargs3(t3.nfs_fh3(root), b'nfs-cache')), 3)
            assert lookup.status == 0
            fh = lookup.resok.object.data
            holder = cached(t, 'nfs-cache')
            request = t3.READ3args(t3.nfs_fh3(fh), 0, 8)
            result = nfs.v3('READ', request, 6); assert result.status == 10008, result
            recalled(q, s, holder)
            for _ in range(3):
                result = nfs.v3('READ', request, 6); assert result.status == 10008, result
            holder.write(b'from SMB'); ack(c, s, t, holder)
            result = nfs.v3('READ', request, 6)
            assert result.status == 0 and result.resok.data == b'from SMB', result
            holder.close()
        finally: nfs.close()
        passed('NFSv3 READ on an existing handle returns JUKEBOX during native recall; repeated retries leave SMB flush/ACK live and the next read returns current data')

        holder = cached(t, 'dav-cache'); holder.write(b'original')
        def dav_read():
            conn = http.client.HTTPSConnection('127.0.0.1', f.davport, context=f.context, timeout=10)
            try:
                conn.request('GET', '/dav/cache-read/dav-cache', headers={'Authorization':f.auth})
                response = conn.getresponse(); return response.status, response.read()
            finally: conn.close()
        status, data = dav_read(); assert status == 503 and b'cache_break_pending' in data
        recalled(q, s, holder); holder.write(b'from SMB'); ack(c, s, t, holder)
        assert dav_read() == (200, b'from SMB')
        holder.close(); c.disconnect()
        passed('DAV GET returns a retryable response while a cache recall is pending and reads freshly flushed bytes after ACK')

        c, s, t, q = connect()
        d, ds, dt, dq = connect()
        holder = cached(t, 'peer-cache'); holder.write(b'peer data')
        other, request, receive = begin(dt, holder.file_name)
        recalled(q, s, holder)
        denied(lambda: ack(d, ds, dt, holder), 0xc0000128)
        holder.write(b'new peer!'); holder.close(); receive(request)
        assert other.read(0, 9) == b'new peer!'; other.close()
        passed('another transport cannot ACK the holder FileId; CLOSE flushes/releases authority and wakes the peer CREATE')

        holder = cached(t, 'timeout-cache'); holder.write(b'confirmed')
        other, request, receive = begin(dt, holder.file_name)
        recalled(q, s, holder)
        # No ACK: fresh server polling must not extend the fixed recall timer.
        receive(request)
        assert other.read(0, 9) == b'confirmed'
        end = time.monotonic()+3
        while c.transport.connected and time.monotonic()<end: time.sleep(.02)
        assert not c.transport.connected, 'expired cache still has a live transport'
        other.close(); d.disconnect()
        passed('unacknowledged recall fences the holder transport and open while the conflicting client completes after native exclusion releases')
        c, s, t, q = connect()
        holder = cached(t, 'revoked-cache'); holder.write(b'persisted')
        f.api('smb/credentials', f.admin, dict(username='alice', enabled=False))
        end = time.monotonic()+5
        while c.transport.connected and time.monotonic()<end: time.sleep(.02)
        assert not c.transport.connected
        assert native_read(f.root/'smbdata/revoked-cache') == b'persisted'
        f.api('smb/credentials', f.admin, dict(username='alice', password=f.password))
        passed('credential revocation closes the cache-bearing transport and releases native exclusion without requiring a client request')

        if os.name != 'nt':
            c, s, t, q = connect()
            holder = cached(t, 'watchdog-cache'); holder.write(b'watchdog')
            pid = f.ctl('status')['identity']['identity']['pid']
            os.kill(pid, signal.SIGSTOP)
            try:
                # The next poll suspends inside an identity RPC while holding
                # the connection gate. The independent watchdog must still act.
                start = time.monotonic()
                while c.transport.connected and time.monotonic()-start < 3: time.sleep(.01)
                assert not c.transport.connected and time.monotonic()-start < 2.5
            finally: os.kill(pid, signal.SIGCONT)
            assert native_read(f.root/'smbdata/watchdog-cache') == b'watchdog'
            passed('stalled identity RPC cannot hold the cache transport past its authority: independent watchdog closes it before IPC timeout and autonomous worker expiry releases native exclusion')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush(); report['server_log']=(f.base/'supervisor.log').read_text(errors='replace')[-16000:]
            report['smb_log']=(f.state/'logs/smb.jsonl').read_text(errors='replace')[-16000:] if (f.state/'logs/smb.jsonl').exists() else ''
    finally:
        for c in clients:
            try: c.disconnect(close=False)
            except Exception: pass
        if f:
            try: f.close()
            except Exception:
                report['status']='failed'; report['cleanup_error']=traceback.format_exc()
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(report,indent=2)+'\n')
    return int(report['status']!='passed')


if __name__ == '__main__': raise SystemExit(main())
