#!/usr/bin/env python3
"""Independent SMB3.1.1 HMAC/CMAC/GMAC negotiation, signed I/O and nonce domains."""
import argparse
import json
from pathlib import Path
import struct
import traceback
import uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from m5_integration import Fixture, create, denied
from m5_wire import header, exchange, status, rejected_connection
from m6_integration import sign, wire_auth
from smb_notify_integration import notify, events
from smb_reauthentication import reauthenticate


def run():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    a = p.parse_args(); f = None; clients = []
    report = dict(status='failed', checks=[])
    def passed(message): report['checks'].append(message); print('PASS ' + message, flush=True)
    try:
        f = Fixture(a.bin, 512 if a.sanitizers else 256)
        profile = next(x for x in f.api('protocols', f.admin) if x['id'] == 'smb')
        assert set(profile['smb311_signing_algorithms']) == {'AES-GMAC', 'AES-CMAC', 'HMAC-SHA256'}
        for algorithm in (0, 1, 2):
            c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True); clients.append(c)
            c.connect(dialect=0x311, preferred_signing_algos=[algorithm])
            assert c.signing_algorithm_id == algorithm
            s = Session(c, username='TAUCLOUD\\alice', password=f.password, require_encryption=False, auth_protocol='ntlm'); s.connect()
            t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect()
            h = create(t, 'signing-' + str(algorithm)); h.write(b'signed payload'); h.flush()
            assert h.read(0, 14) == b'signed payload'
            key = s.signing_key
            reauthenticate(s, 'TAUCLOUD\\alice', f.password)
            assert key == s.signing_key and h.read(0, 14) == b'signed payload'; h.close()
            d = create(t, 'notify-' + str(algorithm), options=1, access=0x120089)
            req = notify(d)
            h = create(t, d.file_name + '/child'); h.close()
            assert events(c, req) == [(1, 'child')]
            h = create(t, d.file_name + '/buffered'); h.close()
            req = notify(d, interim=False)
            assert events(c, req, asynchronous=False) == [(1, 'buffered')]
            req = notify(d); req.cancel(); denied(lambda: c.receive(req, timeout=10), 0xc0000120)
            # Cancellation before the interim arrives must use the request MID;
            # after it arrives it may identify the request by AsyncId instead.
            req = notify(d, interim=False); req.cancel()
            denied(lambda: c.receive(req, timeout=10), 0xc0000120)
            d.close(); c.disconnect()
        passed('HMAC-SHA256/CMAC/GMAC-only offers authenticate, verify signed I/O and preserve the key and open across same-session renewal')
        passed('each negotiated algorithm signs synchronous/asynchronous notifications and supports CANCEL before/after STATUS_PENDING')
        for algorithm in (0, 1, 2):
            sock, sid, key, *_ = wire_auth(f.smbport, f.password, 'alice', signing_algorithm=algorithm)
            packet = sign(header(13, 3, sid, flags=8) + struct.pack('<HH', 4, 0), key, algorithm)
            response = exchange(sock, packet)
            assert status(response) == 0 and sign(response, key, algorithm)[48:64] == response[48:64]
            rejected_connection(sock, packet)
        passed('independent raw signatures verify SESSION_SETUP/ECHO responses for all algorithms and duplicate request MIDs disconnect')
        for mode in ('response-nonce', 'cancel-nonce', 'wrong-algorithm', 'payload', 'signature'):
            sock, sid, key, *_ = wire_auth(f.smbport, f.password, 'alice', signing_algorithm=2)
            plain = header(13, 3, sid, flags=8) + struct.pack('<HH', 4, 0)
            if mode in ('response-nonce', 'cancel-nonce'):
                nonce = plain[24:32] + struct.pack('<I', 1 if mode == 'response-nonce' else 2)
                signature = AESGCM(key).encrypt(nonce, b'', plain)
                packet = plain[:48] + signature + plain[64:]
            else:
                packet = bytearray(sign(plain, key, 1 if mode == 'wrong-algorithm' else 2))
                if mode == 'payload': packet[-1] ^= 1
                if mode == 'signature': packet[48] ^= 1
            rejected_connection(sock, packet)
        passed('GMAC rejects response/CANCEL nonce substitution, CMAC substitution and payload/tag tampering before dispatch')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush(); report['server_log'] = (f.base/'supervisor.log').read_text(errors='replace')[-12000:]
    finally:
        for c in clients:
            try: c.disconnect(close=False)
            except Exception: pass
        if f: f.close()
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(run())
