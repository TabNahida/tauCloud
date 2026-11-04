#!/usr/bin/env python3
"""SMB renewal with independent SPNEGO tokens and the original channel keys."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import struct
import traceback
import uuid

import spnego
from smbprotocol.connection import Connection
from smbprotocol.exceptions import MoreProcessingRequired, SMBResponseException
from smbprotocol.session import Session, SMB2SessionSetupRequest, SMB2SessionSetupResponse
from smbprotocol.tree import TreeConnect
from m5_integration import Fixture, create, denied, lock
from m5_wire import authenticate, exchange, header, signed, status


def reauthenticate(session, username, password=None, protocol='ntlm', interim=None):
    c = session.connection
    keys = (session.session_key, session.signing_key, session.encryption_key, session.decryption_key)
    context = spnego.client(username, password, service='cifs', hostname=c.server_name,
                            options=spnego.NegotiateOptions.session_key, protocol=protocol)
    incoming = c.gss_negotiate_token if protocol == 'negotiate' else None
    statuses = []
    for _ in range(8):
        outgoing = context.step(incoming)
        if not outgoing:
            assert context.complete and statuses[-1] == 0
            break
        q = SMB2SessionSetupRequest()
        q['security_mode'] = c.client_security_mode
        q['buffer'] = outgoing
        request = c.send(q, sid=session.session_id)
        try:
            response = c.receive(request)
        except MoreProcessingRequired as e:
            response = e.header
        except SMBResponseException as e:
            if not session.encrypt_data:
                c.verify_signature(e.header, session.session_id, force=True)
            raise
        assert response['session_id'].get_value() == session.session_id
        if not session.encrypt_data:
            c.verify_signature(response, session.session_id, force=True)
        status = response['status'].get_value()
        statuses.append(status)
        reply = SMB2SessionSetupResponse(); reply.unpack(response['data'].get_value())
        incoming = reply['buffer'].get_value()
        if status == 0:
            if incoming and not context.complete:
                assert not context.step(incoming)
            assert context.complete
            break
        assert status == 0xc0000016
        if interim:
            interim()
    else:
        raise AssertionError('unbounded authentication exchange')
    assert keys == (session.session_key, session.signing_key, session.encryption_key, session.decryption_key)
    # Independent new authentication generates a different key. Subsequent SMB
    # traffic must continue to use the initial keys, not this new GSS key.
    assert context.session_key[:16].ljust(16, b'\0') != session.session_key
    return statuses


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    args = p.parse_args()
    report = dict(status='failed', checks=[])
    f, connections = None, []

    def passed(message):
        report['checks'].append(message); print('PASS ' + message, flush=True)

    try:
        f = Fixture(args.bin, 512 if args.sanitizers else 256)

        def connect(dialect=0x311, encrypted=False):
            c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
            connections.append(c); c.connect(dialect=dialect, timeout=10)
            s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=encrypted, auth_protocol='ntlm')
            s.connect()
            t = TreeConnect(s, '\\\\127.0.0.1\\smb'); t.connect()
            return c, s, t

        for dialect, encrypted in ((0x210, False), (0x300, True), (0x302, True), (0x311, False), (0x311, True)):
            c, s, t = connect(dialect, encrypted)
            name = f'renew-{dialect}-{encrypted}'
            h = create(t, name); h.write(b'original'); lock(h, (0, 8, 2 | 16))
            for _ in range(3):
                assert reauthenticate(s, 'TAUCLOUD\\alice', f.password) == [0xc0000016, 0]
                assert h.read(0, 8) == b'original'
            other, _, tree = connect(dialect, encrypted)
            h2 = create(tree, name, disposition=1)
            denied(lambda: lock(h2, (0, 8, 2 | 16)), 0xc0000055)
            lock(h, (0, 8, 4)); h2.close(); other.disconnect()
            h.write(b'renewed!'); assert h.read(0, 8) == b'renewed!'
            h.close(); c.disconnect()
        passed('SMB2.1/3.0/3.0.2/3.1.1 repeated signed/encrypted NTLM renewal preserves session ID, keys, opens and byte-range locks')

        c, s, t = connect(encrypted=True)
        h = create(t, 'expired'); h.write(b'kept')
        # Advance only the authority expiry; the actual NTLM/SPNEGO exchange and
        # SMB cryptography remain unmodified on both sides.
        with closing(sqlite3.connect(f.state / 'identity.db')) as db:
            with db:
                db.execute("UPDATE sessions SET expires=expires-3601000 WHERE kind='smb' AND name='alice'")
        denied(lambda: h.read(0, 4), 0xc000035c)
        denied(lambda: create(t, 'expired-denied'), 0xc000035c)
        # Ordinary management login must not prune an SMB renewal candidate.
        f.api('auth/login', data=dict(username='alice', password=f.password, scope='files'))
        reauthenticate(s, 'TAUCLOUD\\alice', f.password)
        assert h.read(0, 4) == b'kept'
        h.close(); c.disconnect()
        passed('expired authority reports NETWORK_SESSION_EXPIRED and renews the same open after an intervening management login')

        for user, password in (('alice', 'WrongPassword-123'), ('bob', f.password)):
            c, s, t = connect()
            h = create(t, 'failed-renewal', share=0); h.write(b'owner')
            denied(lambda: reauthenticate(s, 'TAUCLOUD\\' + user, password), 0xc000006d)
            fresh, _, tree = connect()
            h2 = create(tree, 'failed-renewal', share=0, disposition=1)
            assert h2.read(0, 5) == b'owner'
            h2.close(); fresh.disconnect(); c.disconnect(close=False)
        passed('wrong proof and different-user renewal fail, remove old session authority and release exclusive handles before the error reply')

        c, s, t = connect(); h = create(t, 'revoked-renewal', share=0)
        f.api('smb/credentials', f.admin, dict(username='alice', password=f.password))
        denied(lambda: reauthenticate(s, 'TAUCLOUD\\alice', f.password), 0xc000006d)
        fresh, _, tree = connect(); h2 = create(tree, 'revoked-renewal', share=0, disposition=1)
        h2.close(); fresh.disconnect(); c.disconnect(close=False)
        passed('fresh valid credentials cannot renew a revoked token or resurrect its exclusive open')

        c, s, t = connect(encrypted=True)
        class Abandoned(Exception):
            pass
        def abandon():
            raise Abandoned()
        try:
            reauthenticate(s, 'TAUCLOUD\\alice', f.password, interim=abandon)
            raise AssertionError('expected intermediate challenge')
        except Abandoned:
            pass
        s.disconnect()
        fresh = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=True, auth_protocol='ntlm')
        fresh.connect()
        tree = TreeConnect(fresh, '\\\\127.0.0.1\\smb'); tree.connect()
        reauthenticate(fresh, 'TAUCLOUD\\alice', f.password)
        h = create(tree, 'abandoned-renewal'); h.write(b'fresh'); assert h.read(0, 5) == b'fresh'
        h.close(); c.disconnect()
        passed('LOGOFF during an incomplete renewal resets authentication state and permits a fresh encrypted session on the same transport')

        sock, sid, key = authenticate(f.smbport, 'alice', f.password)
        try:
            context = spnego.client('TAUCLOUD\\alice', f.password, protocol='ntlm', service='cifs', hostname='127.0.0.1')
            def setup(token, mid, session_id):
                packet = header(1, mid, session_id, flags=8) + struct.pack('<HBBIIHHQ', 25, 0, 1, 0, 0, 88, len(token), 0) + token
                return signed(packet, key)
            reply = exchange(sock, setup(context.step(), 3, sid))
            assert status(reply) == 0xc0000016 and signed(reply, key)[48:64] == reply[48:64]
            offset, size = struct.unpack_from('<HH', reply, 68)
            proof = context.step(reply[offset:offset+size])
            reply = exchange(sock, setup(b'foreign-session', 4, sid ^ 0x100000000))
            assert status(reply) == 0xc0000203 and reply[48:64] == bytes(16)
            reply = exchange(sock, setup(proof, 5, sid))
            assert status(reply) == 0 and signed(reply, key)[48:64] == reply[48:64]
            reply = exchange(sock, signed(header(13, 6, sid, flags=8) + struct.pack('<HH', 4, 0), key))
            assert status(reply) == 0 and signed(reply, key)[48:64] == reply[48:64]
        finally:
            sock.close()
        passed('SESSION_SETUP for an unknown session does not abort another session\'s in-progress renewal or borrow its signing key')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush(); report['server_log'] = (f.base / 'supervisor.log').read_text(errors='replace')[-12000:]
    finally:
        for c in connections:
            try: c.disconnect(close=False)
            except Exception: pass
        if f: f.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
