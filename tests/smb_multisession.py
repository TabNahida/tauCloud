#!/usr/bin/env python3
"""Independent SMB session multiplexing, scoped replacement and transport cleanup."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading
import time
import traceback
import uuid

import spnego
from smbprotocol.connection import Connection, SMB2CancelRequest
from smbprotocol.exceptions import MoreProcessingRequired, SMBConnectionClosed, SMBResponseException
from smbprotocol.file_info import FileRenameInformation
from smbprotocol.open import SMB2ReadRequest
from smbprotocol.session import Session, SMB2SessionSetupRequest
from smbprotocol.tree import TreeConnect
from m5_integration import Fixture, create, denied, lock, setinfo
from smb_notify_integration import notify, events
from smb_blocking_locks import send_lock, pending, completed


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true'); a = p.parse_args()
    f = None; clients = []; report = dict(status='failed', checks=[])
    def passed(text): report['checks'].append(text); print('PASS ' + text, flush=True)
    def connection(dialect=0x311):
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        c.connect(dialect=dialect); clients.append(c); return c
    def session(c, user='alice', previous=0, password=None, barrier=None):
        s = Session(c, 'TAUCLOUD\\'+user, f.password if password is None else password,
                    require_encryption=c.dialect >= 0x300, auth_protocol='ntlm')
        send = c.send; count = 0
        def setup(message, *args, **kwargs):
            nonlocal count
            if isinstance(message, SMB2SessionSetupRequest):
                count += 1
                message['previous_session_id'] = previous[min(count-1, 1)] if isinstance(previous, tuple) else previous
                if count == 2 and barrier is not None: barrier.wait(timeout=15)
            return send(message, *args, **kwargs)
        c.send = setup
        try: s.connect()
        finally: c.send = send
        return s
    def tree(s, share='smb'):
        t = TreeConnect(s, '\\\\127.0.0.1\\'+share); t.connect(); return t
    try:
        f = Fixture(a.bin, 512 if a.sanitizers else 256)
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c = connection(dialect); first = session(c); ta = tree(first)
            h = create(ta, f'multi-{dialect}'); h.write(b'original')
            second = session(c); tb = tree(second)
            assert first.session_id != second.session_id and first.signing_key != second.signing_key
            # Tree IDs can coincide: session identity must determine authority.
            assert ta.tree_connect_id == tb.tree_connect_id
            peer = create(tb, f'multi-{dialect}', disposition=1)
            assert peer.read(0, 8) == h.read(0, 8) == b'original'
            q = SMB2ReadRequest(); q['file_id'] = h.file_id; q['length'] = 1
            denied(lambda: c.receive(c.send(q, second.session_id, tb.tree_connect_id)), 0xc0000128)
            lock(h, (0, 8, 2|16)); denied(lambda: lock(peer, (0, 8, 2|16)), 0xc0000055)
            lock(h, (0, 8, 4)); lock(peer, (0, 8, 2|16)); lock(peer, (0, 8, 4))
            lock(h, (0, 8, 2|16)); waiting = send_lock(peer); pending(waiting)
            c.echo(sid=first.session_id); lock(h, (0, 8, 4)); completed(c, waiting)
            lock(peer, (0, 8, 4))
            rename = FileRenameInformation(); rename['file_name'] = f'multi-{dialect}-renamed'
            setinfo(h, rename); assert peer.read(0, 8) == b'original'
            d = create(ta, f'watch-{dialect}', options=1, access=0x120089); req = notify(d)
            c.send(SMB2CancelRequest(), sid=second.session_id,
                   message_id=req.message['message_id'].get_value(), async_id=req.async_id, credit_request=0)
            c.echo(sid=second.session_id); assert req.response['status'].get_value() == 0x103
            second.disconnect(); assert h.read(0, 8) == b'original'
            create(ta, f'watch-{dialect}/live').close(); assert events(c, req) == [(1, 'live')]
            d.close(); h.close(); first.disconnect(); c.disconnect(close=False)
        passed('four dialects multiplex independent signing/encryption, scoped tree/file IDs, shared locks and rename across inactive opens; LOGOFF preserves the other session and its pending watch')

        c = connection(); send = c.send; barrier = threading.Barrier(2)
        def interleaved(message, *args, **kwargs):
            request = send(message, *args, **kwargs)
            if isinstance(message, SMB2SessionSetupRequest) and kwargs.get('sid', 0) == 0:
                barrier.wait(timeout=15)
            return request
        def authenticate():
            s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=True, auth_protocol='ntlm')
            s.connect(); return s
        c.send = interleaved
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                one, two = pool.submit(authenticate), pool.submit(authenticate)
                sa, sb = one.result(timeout=20), two.result(timeout=20)
        finally: c.send = send
        assert sa.session_id != sb.session_id and sa.signing_key != sb.signing_key
        for index, s in enumerate((sa, sb)):
            h = create(tree(s), f'interleaved-{index}'); h.write(b'own transcript')
            assert h.read(0, 14) == b'own transcript'; h.close(); s.disconnect()
        c.disconnect(close=False)
        passed('interleaved SMB3.1.1 authentication exchanges retain separate preauthentication transcripts and independently verified encryption keys')

        c = connection(); old = session(c); ta = tree(old)
        h = create(ta, 'proof-survivor', share=0); h.write(b'held')
        denied(lambda: session(c, previous=old.session_id, password='wrong-proof'), 0xc000006d)
        assert h.read(0, 4) == b'held'; c.echo(sid=old.session_id)
        different = session(c, user='bob', previous=old.session_id)
        ipc = tree(different, 'IPC$'); c.echo(sid=different.session_id)
        assert h.read(0, 4) == b'held'; different.disconnect()
        cancelled = session(c, previous=(old.session_id, 0))
        assert h.read(0, 4) == b'held'; cancelled.disconnect()
        passed('failed new authentication preserves established sessions; valid different-user authentication cannot replace a guessed PreviousSessionId')

        survivor = session(c); ts = tree(survivor); keep = create(ts, 'keep'); keep.write(b'survives')
        d = create(ta, 'replacement-watch', options=1, access=0x120089); req = notify(d)
        replacement = session(c, previous=(0, old.session_id)); tr = tree(replacement)
        denied(lambda: c.receive(req, timeout=10), 0x10b)
        # Probe the deleted ID without credentials; its old cipher is gone.
        c.session_table.pop(old.session_id)
        denied(lambda: c.echo(sid=old.session_id), 0xc0000203)
        reopened = create(tr, 'proof-survivor', share=0, disposition=1); assert reopened.read(0, 4) == b'held'; reopened.close()
        assert keep.read(0, 8) == b'survives'
        passed('same-transport replacement authenticates first, completes old watches under old keys and releases old exclusive opens while another session survives')

        d = create(tr, 'remote-replacement-watch', options=1, access=0x120089); req = notify(d)
        h = create(tr, 'remote-exclusive', share=0)
        other = connection(); fresh = session(other, previous=replacement.session_id); tf = tree(fresh)
        denied(lambda: c.receive(req, timeout=10), 0x10b)
        c.session_table.pop(replacement.session_id)
        denied(lambda: c.echo(sid=replacement.session_id), 0xc0000203)
        create(tf, 'remote-exclusive', share=0, disposition=1).close()
        assert keep.read(0, 8) == b'survives'; c.echo(sid=survivor.session_id)
        fresh.disconnect(); other.disconnect(close=False)
        keep.close(); survivor.disconnect(); c.disconnect(close=False)
        passed('cross-transport replacement drains only the matching old session and keeps its transport and unrelated sessions usable')

        for iteration in range(4):
            left = connection(); right = connection(); la = session(left); rb = session(right)
            dl = create(tree(la), f'race-left-{iteration}', options=1, access=0x120089)
            dr = create(tree(rb), f'race-right-{iteration}', options=1, access=0x120089)
            nl, nr = notify(dl), notify(dr); barrier = threading.Barrier(2)
            with ThreadPoolExecutor(max_workers=2) as pool:
                l = pool.submit(session, left, previous=rb.session_id, barrier=barrier)
                r = pool.submit(session, right, previous=la.session_id, barrier=barrier)
                ls, rs = l.result(timeout=25), r.result(timeout=25)
            denied(lambda: left.receive(nl, timeout=10), 0x10b)
            denied(lambda: right.receive(nr, timeout=10), 0x10b)
            left.echo(sid=ls.session_id); right.echo(sid=rs.session_id)
            left.session_table.pop(la.session_id); right.session_table.pop(rb.session_id)
            ls.disconnect(); rs.disconnect(); left.disconnect(close=False); right.disconnect(close=False)
        passed('four simultaneous reciprocal replacement races complete without holding transport gates in a cycle, and both new encrypted sessions remain usable')

        c = connection(); sa = session(c); sb = session(c)
        create(tree(sa), 'lost-a', share=0); create(tree(sb), 'lost-b', share=0)
        c.disconnect(close=False)
        fresh = connection(); st = tree(session(fresh))
        for name in ('lost-a', 'lost-b'):
            deadline = time.monotonic()+10
            while True:
                try: create(st, name, share=0, disposition=1).close(); break
                except SMBResponseException as e:
                    assert e.status == 0xc0000043 and time.monotonic() < deadline
                    time.sleep(.02)
        fresh.disconnect()
        passed('abrupt transport loss releases every session and all exclusive opens, including the inactive context')

        for encrypted in (False, True):
            c = connection(); sa = session(c); sb = session(c); tb = tree(sb)
            h = create(tb, 'wrong-key'); h.write(b'confined')
            # Address B with A's cryptographic material: routing must select
            # B's key and reject the message, never search for a key that fits.
            sb.encrypt_data = encrypted
            if encrypted: sb.encryption_key = sa.encryption_key
            else: sb.signing_key = sa.signing_key
            try: h.read(0, 8); raise AssertionError('cross-session key accepted')
            except (SMBConnectionClosed, ConnectionResetError): pass
            c.disconnect(close=False)
        passed('known-session requests signed or encrypted with a different session key are rejected at the transport boundary')

        c = connection(); live = [session(c) for _ in range(16)]
        denied(lambda: session(c), 0xc000009a)
        for s in live: c.echo(sid=s.session_id)
        live.pop().disconnect(); live.append(session(c))
        for s in live: s.disconnect()
        # A half-completed authentication cannot permanently consume a slot.
        context = spnego.client('TAUCLOUD\\alice', f.password, protocol='ntlm', service='cifs', hostname='127.0.0.1')
        q = SMB2SessionSetupRequest(); q['security_mode'] = c.client_security_mode; q['buffer'] = context.step()
        request = c.send(q)
        try: c.receive(request); raise AssertionError('expected challenge')
        except MoreProcessingRequired as e: abandoned = e.header['session_id'].get_value()
        live = [session(c) for _ in range(15)]
        time.sleep(10.2); live.append(session(c))
        q['buffer'] = b'abandoned-authentication'
        denied(lambda: c.receive(c.send(q, sid=abandoned)), 0xc0000203)
        for s in live: c.echo(sid=s.session_id); s.disconnect()
        c.disconnect(close=False)
        passed('sixteen-session transport bound rejects excess authentication without damaging peers; LOGOFF and expired abandoned handshakes release capacity')
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
