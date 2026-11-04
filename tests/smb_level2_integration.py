#!/usr/bin/env python3
"""Real-client Level II grants, downgrade races and invalidation without ACK."""
import argparse
import datetime
import json
from pathlib import Path
import platform
import struct
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open
from smbprotocol.file_info import FileDispositionInformation
from m5_integration import Fixture, create, denied, setinfo, lock
from smb_blocking_locks import pending, send_lock, completed
from smb_oplock_integration import capture_breaks, Ack, native_write


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', required=True)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    report = dict(status='failed', host=platform.platform(), checks=[],
                  recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    f = None; clients = []
    def passed(message):
        report['checks'].append(message); print('PASS ' + message, flush=True)
    def connect(dialect):
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        clients.append(c); c.connect(dialect=dialect, timeout=10)
        q = capture_breaks(c, include_level=True)
        s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=dialect >= 0x300,
                    auth_protocol='ntlm')
        s.connect(); t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect()
        return c, s, t, q
    def cached(t, name, level=8, access=0x13019f, disposition=3, expected=None):
        h = Open(t, name)
        h.create(2, access, 0x80, 7, disposition, 0x40, oplock_level=level)
        assert h.oplock_level == (level if expected is None else expected), h.oplock_level
        return h
    def begin(t, name, level=8, access=0x13019f):
        h = Open(t, name)
        packet, receive = h.create(2, access, 0x80, 7, 1, 0x40, oplock_level=level, send=False)
        return h, t.session.connection.send(packet, t.session.session_id, t.tree_connect_id), receive
    def recalled(q, s, h, level):
        assert q.get(timeout=10) == (s.session_id, h.file_id, s.encrypt_data, level)
    def ack(c, s, t, h, level):
        response = c.receive(c.send(Ack(h.file_id, level), s.session_id, t.tree_connect_id), timeout=10)
        assert response['data'].get_value() == struct.pack('<HBBI', 24, level, 0, 0) + h.file_id
    def begin_write(h, data):
        packet, receive = h.write(data, send=False)
        c = h.connection; t = h.tree_connect
        return c.send(packet, t.session.session_id, t.tree_connect_id), receive
    def finish_write(request, receive, length):
        assert receive(request) == length
        assert request.response['flags'].get_value() & 2
        assert request.response['credit_response'].get_value() == 0
    try:
        f = Fixture(a.bin, memory=1024)
        f.api('shares', f.admin, dict(id='cache-read', space='smbdata', exposures={'smb': 'r'}))
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, s, t, q = connect(dialect)
            pc, ps, pt, pq = connect(dialect)
            read_tree = TreeConnect(ps, r'\\127.0.0.1\cache-read'); read_tree.connect()
            first = cached(t, f'level2-alone-{dialect:x}', level=1)
            denied(lambda: ack(c, s, t, first, 0), 0xc0000184)
            time.sleep(2.6); c.echo(sid=s.session_id, timeout=5)
            request, receive = begin_write(first, b'initial')
            recalled(q, s, first, 0)
            finish_write(request, receive, 7)  # deliberately send no client ACK
            assert first.read(0, 7) == b'initial'; first.close()
            passed(f'{dialect:x}: direct Level II grant; own WRITE completes asynchronously after notification without a client ACK or extra credits')

            first = cached(t, f'level2-compound-{dialect:x}', level=1)
            writing, receive_write = first.write(b'flow', send=False)
            reading, receive_read = first.read(0, 4, send=False)
            closing, receive_close = first.close(send=False)
            requests = c.send_compound([writing, reading, closing], s.session_id,
                                       t.tree_connect_id, related=True)
            recalled(q, s, first, 0)
            finish_write(requests[0], receive_write, 4)
            assert receive_read(requests[1]) == b'flow'; receive_close(requests[2])
            passed(f'{dialect:x}: related WRITE/READ/CLOSE remains ordered across the no-ACK read-cache invalidation')

            first = cached(t, f'level2-share-{dialect:x}'); first.write(b'old')
            second, request, receive = begin(pt, first.file_name)
            pending(request); recalled(q, s, first, 1)
            first.write(b'new'); first.flush(); ack(c, s, t, first, 1)
            receive(request); assert second.oplock_level == 1
            reader = cached(pt, first.file_name, level=1, access=0x120089, disposition=1)
            denied(lambda: reader.write(b'bad'), 0xc0000022)
            ordinary = create(pt, first.file_name, access=0x120089, disposition=1)
            assert ordinary.read(0, 3) == reader.read(0, 3) == b'new'
            ordinary.close(); time.sleep(.3); assert q.empty() and pq.empty()
            request, receive = begin_write(second, b'end')
            recalled(q, s, first, 0)
            peer_breaks = {pq.get(timeout=10), pq.get(timeout=10)}
            assert peer_breaks == {(ps.session_id, second.file_id, ps.encrypt_data, 0),
                                   (ps.session_id, reader.file_id, ps.encrypt_data, 0)}
            finish_write(request, receive, 3)
            assert first.read(0, 3) == reader.read(0, 3) == b'end'
            denied(lambda: ack(c, s, t, first, 0), 0xc00000e3)
            first.close(); second.close(); reader.close()
            passed(f'{dialect:x}: EXCLUSIVE downgrades to shared Level II across transports; read-only and uncached readers coexist, then WRITE invalidates every cached reader without ACK')

            first = cached(t, f'level2-lock-{dialect:x}', level=1)
            second = cached(pt, first.file_name, level=1, disposition=1)
            request = send_lock(second, 0, 1, 0x12)
            recalled(q, s, first, 0); recalled(pq, ps, second, 0)
            completed(pc, request)
            denied(lambda: first.write(b'x'), 0xc0000054)
            lock(second, (0, 1, 4)); first.write(b'x')
            first.close(); second.close()
            passed(f'{dialect:x}: byte-range LOCK waits for both no-ACK invalidations and only then excludes the other handle')

            seed = create(t, f'level2-readonly-{dialect:x}'); seed.write(b'old'); seed.close()
            first = cached(read_tree, seed.file_name, level=1, access=0x120089, disposition=1)
            assert first.read(0, 3) == b'old'
            denied(lambda: first.write(b'bad'), 0xc0000022)
            time.sleep(2.6); assert first.read(0, 3) == b'old' and pq.empty()
            second, request, receive = begin(t, first.file_name, level=0)
            recalled(pq, ps, first, 0); receive(request)
            second.write(b'end'); assert first.read(0, 3) == b'end'
            first.close(); second.close()
            passed(f'{dialect:x}: a read-only share renews standalone Level II without write authority; a later writer recalls it and obtains a genuinely writable native handle')

            first = cached(t, f'level2-cancel-{dialect:x}')
            second, request, receive = begin(pt, first.file_name)
            pending(request); recalled(q, s, first, 1)
            request.cancel(); denied(lambda: pc.receive(request, timeout=10), 0xc0000120)
            ack(c, s, t, first, 1)
            request, receive = begin_write(first, b'after cancel')
            recalled(q, s, first, 0); finish_write(request, receive, 12)
            first.close()
            passed(f'{dialect:x}: CANCEL abandons a waiting CREATE while the valid downgrade ACK retains read caching until the next write')

            first = cached(t, f'level2-race-{dialect:x}'); first.write(b'old')
            second, request, receive = begin(pt, first.file_name)
            pending(request); recalled(q, s, first, 1)
            with ThreadPoolExecutor(max_workers=1) as pool:
                native = pool.submit(native_write, f.root/'smbdata'/first.file_name, b'host')
                time.sleep(.4); assert not native.done()
                first.write(b'flush'); first.flush(); ack(c, s, t, first, 1)
                recalled(q, s, first, 0)
                assert native.result(timeout=10) == 4
                receive(request); assert second.read(0, 4) == b'host'
            first.close(); second.close()
            passed(f'{dialect:x}: native writer tightens an outstanding downgrade; valid II ACK is followed by NONE with no second ACK, and the native writer sees the flushed boundary')

            first = cached(t, f'level2-flush-lock-{dialect:x}'); first.write(b'data')
            second, request, receive = begin(pt, first.file_name)
            pending(request); recalled(q, s, first, 1)
            lock(first, (0, 1, 0x12))  # cached lock flush is allowed before ACK
            ack(c, s, t, first, 1); recalled(q, s, first, 0)
            receive(request); assert second.oplock_level == 0
            denied(lambda: second.read(0, 1), 0xc0000054)
            lock(first, (0, 1, 4)); assert second.read(0, 4) == b'data'
            first.close(); second.close()
            passed(f'{dialect:x}: flushing a cached byte lock during downgrade forces a subsequent NONE break and prevents a conflicting Level II grant')

            for delete_mode in ('setinfo', 'close'):
                seed = create(t, f'level2-delete-{delete_mode}-{dialect:x}')
                seed.write(b'kept'); seed.close()
                first = cached(t, seed.file_name, level=1, disposition=1)
                second = cached(pt, first.file_name, level=1, disposition=1)
                deletion = create(pt, first.file_name, access=0x10000, disposition=1,
                                  options=0x1040 if delete_mode == 'close' else 0x40)
                if delete_mode == 'setinfo':
                    info = FileDispositionInformation(); info['delete_pending'] = True
                    setinfo(deletion, info)
                deletion.close()
                denied(lambda: create(pt, first.file_name, disposition=1), 0xc0000056)
                assert first.read(0, 4) == b'kept'; first.close()
                assert second.read(0, 4) == b'kept'
                time.sleep(.3); assert q.empty() and pq.empty()
                second.close(); assert not (f.root/'smbdata'/seed.file_name).exists()
            passed(f'{dialect:x}: SET_INFO and DELETE_ON_CLOSE preserve existing Level II data caches; last close removes the file and releases native exclusion')
            c.disconnect(); pc.disconnect()
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            for name in ('smb', 'file'):
                path = f.state/'logs'/f'{name}.jsonl'
                if path.exists(): report[name+'_log'] = path.read_text(errors='replace')[-12000:]
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
