#!/usr/bin/env python3
"""Anonymous NTLM reauthentication retains an existing, protected SMB context."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import socket
import sqlite3
import struct
import traceback
import uuid

from smbprotocol.connection import Connection
from smbprotocol.exceptions import MoreProcessingRequired
from smbprotocol.session import Session, SMB2SessionSetupRequest, SMB2SessionSetupResponse
from smbprotocol.tree import TreeConnect
from m5_integration import Fixture, create, denied, lock
from m5_wire import header, exchange, status, negotiate, authenticate, rejected_connection
from smb_reauthentication import reauthenticate
from smb_security_integration import get_sd, parse, set_sd, descriptor, ace


def negotiate_token():
    return b'NTLMSSP\0' + struct.pack('<II', 1, 0x80011) + bytes(16)


def anonymous_token():
    data = bytearray(65)
    data[:8] = b'NTLMSSP\0'
    struct.pack_into('<I', data, 8, 3)
    struct.pack_into('<HHI', data, 12, 1, 1, 64)
    struct.pack_into('<I', data, 60, 0x80011 | 0x800)
    return data


def anonymous(session, tamper=None, interim=None):
    c = session.connection
    keys = (session.session_key, session.signing_key, session.encryption_key, session.decryption_key)
    for index, token in enumerate((negotiate_token(), anonymous_token())):
        if index and tamper:
            tamper(token)
        q = SMB2SessionSetupRequest(); q['security_mode'] = c.client_security_mode; q['buffer'] = bytes(token)
        request = c.send(q, sid=session.session_id)
        try:
            response = c.receive(request)
        except MoreProcessingRequired as e:
            response = e.header
        if not session.encrypt_data:
            c.verify_signature(response, session.session_id, force=True)
        assert response['session_id'].get_value() == session.session_id
        assert response['status'].get_value() == (0 if index else 0xc0000016)
        reply = SMB2SessionSetupResponse(); reply.unpack(response['data'].get_value())
        assert reply['session_flags'].get_value() == 0
        if not index and interim:
            interim()
    assert keys == (session.session_key, session.signing_key, session.encryption_key, session.decryption_key)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', required=True); p.add_argument('--output', required=True, type=Path)
    a = p.parse_args(); report = dict(status='failed', checks=[])
    f = None; connections = []
    def passed(message):
        report['checks'].append(message); print('PASS ' + message, flush=True)
    def connect(dialect=0x311):
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        connections.append(c); c.connect(dialect=dialect, timeout=10)
        s = Session(c, 'TAUCLOUD\\alice', f.password, require_encryption=dialect >= 0x300, auth_protocol='ntlm')
        s.connect(); t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect()
        return c, s, t
    def sessions():
        with closing(sqlite3.connect(f.state/'identity.db')) as db:
            return db.execute("SELECT hash,name,csrf,expires FROM sessions WHERE kind='smb' ORDER BY hash").fetchall()
    try:
        f = Fixture(a.bin, memory=1024)
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, s, t = connect(dialect)
            h = create(t, f'anon-{dialect:x}', access=0x1f01ff)
            h.write(b'original'); lock(h, (0, 8, 2 | 16))
            owner = parse(get_sd(h))['owner']; set_sd(h, descriptor([ace(owner)]))
            before = sessions()
            for omitted in (False, True):
                anonymous(s, tamper=(lambda b: struct.pack_into('<HHI', b, 12, 0, 0, 0)) if omitted else None)
                assert h.read(0, 8) == b'original' and parse(get_sd(h))['owner'] == owner
                newer = create(t, h.file_name, disposition=1)
                denied(lambda: lock(newer, (0, 8, 2 | 16)), 0xc0000055)
                newer.close()
            assert sessions() == before, 'anonymous renewal changed identity/provenance/credential lifetime'
            reauthenticate(s, 'TAUCLOUD\\alice', f.password)
            assert h.read(0, 8) == b'original'
            lock(h, (0, 8, 4)); h.close(); c.disconnect()
            passed(f'{dialect:x}: anonymous reauthentication preserves old keys, account-only ACL access, handles and locks; authority lifetime is unchanged and credential renewal still works')

        for reason in ('expired', 'revoked'):
            c, s, t = connect(); h = create(t, 'anon-' + reason, share=0)
            def invalidate():
                if reason == 'expired':
                    with closing(sqlite3.connect(f.state/'identity.db')) as db:
                        with db: db.execute("UPDATE sessions SET expires=0 WHERE kind='smb'")
                else:
                    f.api('smb/credentials', f.admin, dict(username='alice', password=f.password))
            denied(lambda: anonymous(s, interim=invalidate), 0xc000006d)
            fresh, _, tree = connect(); reopened = create(tree, h.file_name, share=0, disposition=1)
            reopened.close(); fresh.disconnect(); c.disconnect(close=False)
            passed(f'{reason}: anonymous authentication cannot revive invalidated authority; failed renewal releases exclusive opens')

        for reason, tamper in (
                ('missing anonymous flag', lambda b: struct.pack_into('<I', b, 60, 0x80011)),
                ('nonzero LM response', lambda b: b.__setitem__(64, 1)),
                ('nonempty NT response', lambda b: struct.pack_into('<HHI', b, 20, 1, 1, 64))):
            c, s, _ = connect()
            denied(lambda: anonymous(s, tamper=tamper), 0xc000006d)
            c.disconnect(close=False)
            passed(reason + ': malformed anonymous token cannot renew a session')

        with closing(socket.create_connection(('127.0.0.1', f.smbport), timeout=10)) as sock:
            negotiate(sock)
            def setup(token, mid, sid):
                return header(1, mid, sid) + struct.pack('<HBBIIHHQ', 25, 0, 3, 0, 0, 88, len(token), 0) + token
            response = exchange(sock, setup(negotiate_token(), 1, 0))
            assert status(response) == 0xc0000016
            sid = struct.unpack_from('<Q', response, 40)[0]
            assert status(exchange(sock, setup(anonymous_token(), 2, sid))) == 0xc000006d
        passed('anonymous authentication without an established security context grants no standalone file authority')
        sock, sid, _ = authenticate(f.smbport, 'alice', f.password)
        token = negotiate_token()
        rejected_connection(sock, header(1, 3, sid) + struct.pack('<HBBIIHHQ', 25, 0, 3, 0, 0, 88, len(token), 0) + token)
        passed('unsigned anonymous renewal cannot enter an authenticated session')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); raise
    finally:
        for c in connections:
            try: c.disconnect(close=False)
            except Exception: pass
        if f: f.close()
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__': main()
