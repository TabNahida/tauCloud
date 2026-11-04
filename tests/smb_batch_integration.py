#!/usr/bin/env python3
"""Independent clients exercising BATCH handle-cache recall and release."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
from pathlib import Path
import platform
import struct
import time
import traceback
import uuid

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open
from m5_integration import Fixture, create, denied, lock
from smb_blocking_locks import pending
from smb_oplock_integration import Ack, capture_breaks, native_write


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    report = dict(status='failed', host=platform.platform(), checks=[],
                  recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    f = None; clients = []
    def passed(message):
        report['checks'].append(message); print('PASS '+message, flush=True)
    def connect(dialect):
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        clients.append(c); c.connect(dialect=dialect, timeout=10)
        q = capture_breaks(c, include_level=True)
        s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=dialect >= 0x300,
                    auth_protocol='ntlm')
        s.connect(); t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect()
        return c, s, t, q
    def opened(t, name, share=7):
        h = Open(t, name); h.create(2, 0x13019f, 0x80, share, 3, 0x40, oplock_level=9)
        assert h.oplock_level == 9, h.oplock_level
        return h
    def begin(t, name, disposition=1, level=9):
        h = Open(t, name)
        packet, receive = h.create(2, 0x13019f, 0x80, 7, disposition, 0x40,
                                    oplock_level=level, send=False)
        return h, t.session.connection.send(packet, t.session.session_id, t.tree_connect_id), receive
    def recalled(q, s, h, level):
        assert q.get(timeout=10) == (s.session_id, h.file_id, s.encrypt_data, level)
    def ack(c, s, t, h, level):
        response = c.receive(c.send(Ack(h.file_id, level), s.session_id, t.tree_connect_id), timeout=10)
        assert response['data'].get_value() == struct.pack('<HBBI', 24, level, 0, 0) + h.file_id
    def writing(h, data):
        packet, receive = h.write(data, send=False); t = h.tree_connect
        return h.connection.send(packet, t.session.session_id, t.tree_connect_id), receive
    try:
        f = Fixture(a.bin, memory=1024)
        f.api('shares', f.admin, dict(id='batch-read', space='smbdata', exposures={'smb': 'r'}))
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, s, t, q = connect(dialect); pc, ps, pt, pq = connect(dialect)
            first = opened(t, f'batch-sharing-{dialect:x}', share=0)
            denied(lambda: ack(c, s, t, first, 0), 0xc0000184)
            first.write(b'cached'); assert first.read(0, 6) == b'cached'
            lock(first, (0, 1, 2)); lock(first, (0, 1, 4))
            denied(lambda: create(pt, first.file_name, disposition=1, options=1), 0xc0000103)
            attrs = create(pt, first.file_name, access=0x100180, share=0, disposition=1)
            attrs.close(); time.sleep(2.6); c.echo(sid=s.session_id, timeout=5)
            assert q.empty()
            _, request, receive = begin(pt, first.file_name)
            pending(request); recalled(q, s, first, 1)
            denied(lambda: ack(pc, ps, pt, first, 0), 0xc0000128)
            first.write(b'flushed'); first.flush(); ack(c, s, t, first, 1)
            denied(lambda: receive(request), 0xc0000043)
            denied(lambda: create(pt, first.file_name, disposition=1), 0xc0000043)
            assert q.empty()
            request, receive = writing(first, b'after')
            recalled(q, s, first, 0); assert receive(request) == 5
            assert request.response['credit_response'].get_value() == 0
            first.close()
            passed(f'{dialect:x}: BATCH survives self I/O, locks, metadata opens and idle renewal; incompatible CREATE recalls before sharing denial, then II WRITE invalidates without ACK')

            first = opened(t, f'batch-close-{dialect:x}', share=0); first.write(b'old')
            second, request, receive = begin(pt, first.file_name)
            pending(request); recalled(q, s, first, 1)
            # The cached close removes the sharing conflict instead of ACKing.
            first.write(b'closed'); first.close()
            receive(request); assert second.oplock_level == 9
            assert second.read(0, 6) == b'closed'; second.close()
            passed(f'{dialect:x}: CLOSE in response to recall releases the cached server handle and permits a new BATCH grant with flushed data')

            first = opened(t, f'batch-downgrade-{dialect:x}'); first.write(b'old')
            second, request, receive = begin(pt, first.file_name)
            pending(request); recalled(q, s, first, 1)
            ack(c, s, t, first, 1); receive(request); assert second.oplock_level == 1
            request, receive = writing(second, b'new')
            recalled(q, s, first, 0); recalled(pq, ps, second, 0)
            assert receive(request) == 3 and first.read(0, 3) == b'new'
            first.close(); second.close()
            passed(f'{dialect:x}: compatible BATCH opens downgrade to shared Level II and invalidate both holders before a peer WRITE')

            first = opened(t, f'batch-overwrite-{dialect:x}'); first.write(b'old')
            second, request, receive = begin(pt, first.file_name, disposition=5)
            pending(request); recalled(q, s, first, 0)
            first.write(b'last flush'); first.flush(); ack(c, s, t, first, 0)
            receive(request); assert second.oplock_level == 1 and second.end_of_file == 0
            first.close(); second.close()
            passed(f'{dialect:x}: overwrite recalls BATCH to NONE and truncates only after the final flush/ACK')

            first = opened(t, f'batch-cancel-{dialect:x}', share=0)
            _, request, receive = begin(pt, first.file_name)
            pending(request); recalled(q, s, first, 1)
            request.cancel(); denied(lambda: pc.receive(request, timeout=10), 0xc0000120)
            first.close()
            second = opened(pt, first.file_name); second.close()
            passed(f'{dialect:x}: cancelling the waiting CREATE leaves no phantom open and a subsequent cached close releases all sharing state')

            first = opened(t, f'batch-native-{dialect:x}'); first.write(b'old')
            with ThreadPoolExecutor(max_workers=1) as pool:
                native = pool.submit(native_write, f.root/'smbdata'/first.file_name, b'host')
                recalled(q, s, first, 0); assert not native.done()
                first.write(b'flush'); first.flush(); ack(c, s, t, first, 0)
                assert native.result(timeout=10) == 4
            assert first.read(0, 4) == b'host'; first.close()
            passed(f'{dialect:x}: a real native writer waits for BATCH recall and dirty-data flush before acquiring the file')

            first = Open(t, f'batch-attributes-{dialect:x}')
            first.create(2, 0x100180, 0x80, 7, 2, 0x40, oplock_level=9)
            assert first.oplock_level == 9
            denied(lambda: first.read(0, 1), 0xc0000022)
            denied(lambda: first.write(b'bad'), 0xc0000022)
            attrs = Open(pt, first.file_name)
            attrs.create(2, 0x100180, 0x80, 7, 1, 0x40, oplock_level=9)
            assert attrs.oplock_level == 0; attrs.close(); assert q.empty()
            second, request, receive = begin(pt, first.file_name)
            pending(request); recalled(q, s, first, 1)
            ack(c, s, t, first, 1); receive(request); assert second.oplock_level == 1
            request, receive = writing(second, b'new')
            recalled(q, s, first, 0); recalled(pq, ps, second, 0); assert receive(request) == 3
            first.close(); second.close()
            passed(f'{dialect:x}: attribute-only creation gets BATCH without data rights; another attribute open gets NONE, then a data open downgrades both caches')

            seed = create(t, f'batch-readonly-{dialect:x}'); seed.write(b'read'); seed.close()
            rt = TreeConnect(s, r'\\127.0.0.1\batch-read'); rt.connect()
            first = Open(rt, seed.file_name)
            first.create(2, 0x120089, 0x80, 7, 1, 0x40, oplock_level=9)
            assert first.oplock_level == 9
            time.sleep(2.6); assert first.read(0, 4) == b'read'
            denied(lambda: first.write(b'bad'), 0xc0000022)
            with ThreadPoolExecutor(max_workers=1) as pool:
                native = pool.submit(native_write, f.root/'smbdata'/first.file_name, b'host')
                recalled(q, s, first, 0); assert not native.done()
                ack(c, s, rt, first, 0); assert native.result(timeout=10) == 4
            assert first.read(0, 4) == b'host'; first.close(); rt.disconnect()
            passed(f'{dialect:x}: read-only-share BATCH renews without write authority and acknowledges native recall without flushing a read-only Windows handle')
            first = Open(t, f'batch-delete-close-{dialect:x}')
            first.create(2, 0x13019f, 0x80, 0, 3, 0x1040, oplock_level=9)
            assert first.oplock_level == 9; first.write(b'delete me')
            _, request, receive = begin(pt, first.file_name)
            pending(request); recalled(q, s, first, 1); first.close()
            denied(lambda: receive(request), 0xc0000034)
            assert not (f.root/'smbdata'/first.file_name).exists()
            passed(f'{dialect:x}: DELETE_ON_CLOSE receives BATCH; the recalled cached close deletes the file and a waiting OPEN observes absence')
            c.disconnect(); pc.disconnect()
        c, s, t, q = connect(0x311); pc, ps, pt, pq = connect(0x311)
        first = opened(t, 'batch-timeout', share=0); first.write(b'confirmed')
        second, request, receive = begin(pt, first.file_name)
        pending(request); recalled(q, s, first, 1)
        receive(request); assert second.read(0, 9) == b'confirmed'
        end = time.monotonic()+3
        while c.transport.connected and time.monotonic()<end: time.sleep(.02)
        assert not c.transport.connected
        second.close(); pc.disconnect()
        passed('unacknowledged BATCH recall fences the old transport/open and allows a separate contender to complete; same-transport timeout recovery remains an open gate')
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
