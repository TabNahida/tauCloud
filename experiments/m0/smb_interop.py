#!/usr/bin/env python3
"""Loopback-only native Python SMB fixture + independent Impacket client.

Only NEGOTIATE / NTLMv2 SESSION_SETUP / TREE_CONNECT / signed CREATE / CLOSE.
No general server, writes, share enumeration, MIC/channel-binding or production auth.
Impacket is imported only in client_probe(), never by the fixture implementation.
"""
import hashlib
import argparse
import hmac
import json
import secrets
import socket
import struct
import tempfile
import threading
import time
from pathlib import Path
from smb import decode, enroll, response_key, signature, signed_open


def der(tag, value):
    length = len(value)
    return bytes([tag]) + (bytes([length]) if length < 128 else b'\x82' + length.to_bytes(2, 'big')) + value


NTLM_OID = bytes.fromhex('060a2b06010401823702020a')
SPNEGO_OID = bytes.fromhex('06062b0601050502')


def spnego(token=None, complete=False):
    value = der(0xa0, der(0x0a, bytes([0 if complete else 1])))
    if token is not None:
        value += der(0xa1, NTLM_OID) + der(0xa2, der(0x04, token))
    return der(0xa1, der(0x30, value))


def ntlm_token(data):
    if data.startswith(b'NTLMSSP\0'):
        return data
    # Strict bounded DER traversal; accept only an OCTET STRING containing NTLM.
    tokens = []
    def walk(data, depth=0):
        if depth > 6:
            raise ValueError('DER nesting')
        offset = 0
        while offset < len(data):
            if offset + 2 > len(data):
                raise ValueError('DER truncated')
            tag, length = data[offset:offset + 2]; offset += 2
            if length & 128:
                count = length & 127
                if count not in (1, 2) or offset + count > len(data):
                    raise ValueError('DER length')
                length = int.from_bytes(data[offset:offset + count], 'big'); offset += count
            end = offset + length
            if end > len(data):
                raise ValueError('DER bounds')
            value = data[offset:end]; offset = end
            if tag == 4 and value.startswith(b'NTLMSSP\0'):
                tokens.append(value)
            elif tag & 0x20:
                walk(value, depth + 1)
    walk(data)
    if len(tokens) != 1:
        raise ValueError('expected one NTLM token')
    return tokens[0]


def security_buffer(data, offset):
    if offset + 8 > len(data):
        raise ValueError('short security descriptor')
    size, maximum, start = struct.unpack_from('<HHI', data, offset)
    if size > maximum or start + size > len(data) or (size and start < 64):
        raise ValueError('security buffer bounds')
    return data[start:start + size]


def receive_exact(connection, count):
    result = bytearray()
    while len(result) < count:
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise EOFError()
        result.extend(chunk)
    return bytes(result)


class Fixture:
    def __init__(self, directory):
        self.directory = directory
        self.nt_hash = enroll('Password')
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(1)
        self.socket.settimeout(15)
        self.port = self.socket.getsockname()[1]
        self.events = []
        self.error = None

    def serve(self):
        try:
            with self.socket, self.socket.accept()[0] as connection:
                connection.settimeout(10)
                self.session(connection)
        except Exception as error:
            self.error = repr(error)

    def session(self, connection):
        key, challenge, authenticated, negotiated = None, None, False, False
        tree_connected = False
        raw_auth = False
        last_message = -1
        opened = None
        try:
            for _ in range(32):
                transport = receive_exact(connection, 4)
                size = int.from_bytes(transport, 'big')
                if not 64 <= size <= 65536:
                    raise ValueError('transport frame budget')
                request = receive_exact(connection, size)
                command = struct.unpack_from('<H', request, 12)[0]
                fields = decode(request, command)
                if fields[8] <= last_message:
                    raise ValueError('replayed message ID')
                last_message = fields[8]
                status, tree = 0, fields[10]
                try:
                    if command == 0 and not negotiated:
                        if len(request) < 102:
                            raise ValueError('short negotiate')
                        structure, count = struct.unpack_from('<HH', request, 64)
                        if structure != 36 or not 1 <= count <= 8 or len(request) != 100 + count * 2:
                            raise ValueError('negotiate length')
                        if 0x210 not in struct.unpack_from('<' + 'H' * count, request, 100):
                            raise ValueError('unsupported dialect')
                        token = der(0x60, SPNEGO_OID + der(0xa0, der(0x30, der(0xa0, der(0x30, NTLM_OID)))))
                        body = struct.pack('<HHHH16sIIIIQQHHI', 65, 3, 0x210, 0, bytes(16),
                                           0, 65536, 65536, 65536, 0, 0, 128, len(token), 0) + token
                        negotiated = True; self.events.append('negotiate_2.1_signing_required')
                    elif command == 1 and negotiated and not authenticated:
                        if len(request) < 88:
                            raise ValueError('short session setup')
                        offset, length = struct.unpack_from('<HH', request, 76)
                        if offset < 88 or offset + length != len(request):
                            raise ValueError('session token bounds')
                        token = ntlm_token(request[offset:])
                        kind = struct.unpack_from('<I', token, 8)[0]
                        if kind == 1 and challenge is None:
                            raw_auth = request[offset:].startswith(b'NTLMSSP\0')
                            challenge = secrets.token_bytes(8)
                            domain = 'Domain'.encode('utf-16le')
                            server = 'Server'.encode('utf-16le')
                            av = struct.pack('<HH', 2, len(domain)) + domain + struct.pack('<HH', 1, len(server)) + server + bytes(4)
                            # Unicode, request target, NTLM, sign, always-sign,
                            # extended-session security, target-info; no RC4 key exchange.
                            flags = 0xa0888215  # Include 128/56-bit session-key capability.
                            challenge_token = (b'NTLMSSP\0' + struct.pack('<IHHII8s8sHHI', 2, len(domain), len(domain),
                                48, flags, challenge, bytes(8), len(av), len(av), 48 + len(domain)) + domain + av)
                            response = challenge_token if raw_auth else spnego(challenge_token)
                            body = struct.pack('<HHHH', 9, 0, 72, len(response)) + response
                            status = 0xc0000016  # MORE_PROCESSING_REQUIRED
                        elif kind == 3 and challenge is not None:
                            user = security_buffer(token, 36).decode('utf-16le')
                            domain = security_buffer(token, 28).decode('utf-16le')
                            response = security_buffer(token, 20)
                            if user != 'User' or domain != 'Domain' or len(response) < 48:
                                raise ValueError('credentials')
                            proof, blob = response[:16], response[16:]
                            if blob[:8] != bytes.fromhex('0101000000000000'):
                                raise ValueError('NTLMv2 required')
                            responsekey = response_key(self.nt_hash, user, domain)
                            if not hmac.compare_digest(proof, hmac.digest(responsekey, challenge + blob, 'md5')):
                                raise ValueError('NTLMv2 proof')
                            if struct.unpack_from('<I', token, 60)[0] & 0x40000000:
                                raise ValueError('key exchange not negotiated')
                            key = hmac.digest(responsekey, proof, 'md5')
                            authenticated = True
                            response = b'' if raw_auth else spnego(complete=True)
                            body = struct.pack('<HHHH', 9, 0, 72, len(response)) + response
                            self.events.append('ntlmv2_authenticated')
                        else:
                            raise ValueError('authentication state')
                    else:
                        if not authenticated or fields[11] != 1 or not fields[6] & 8 or not hmac.compare_digest(
                                request[48:64], signature(request, key)):
                            self.events.append('rejected_unsigned_or_tampered')
                            raise ValueError('signed session required')
                        if command == 3:
                            offset, length = struct.unpack_from('<HH', request, 68)
                            if offset < 72 or offset + length != len(request) or not request[offset:].decode('utf-16le').endswith('\\fixture'):
                                raise ValueError('ungranted share')
                            tree = 1; tree_connected = True
                            body = struct.pack('<HBBIII', 16, 1, 0, 0, 0, 0x00120089)
                        elif command == 5 and tree_connected and opened is None:
                            name = signed_open(request, key, authenticated)
                            opened = (self.directory / name).open('rb')
                            body = struct.pack('<HBBIQQQQQQII16sII', 89, 0, 0, 1, 0, 0, 0, 0,
                                               4096, 7, 0x80, 0, bytes.fromhex('01' * 16), 0, 0)
                            self.events.append('signed_open')
                        elif command == 6 and opened is not None:
                            opened.close(); opened = None
                            body = struct.pack('<HHIQQQQQQI', 60, 0, 0, 0, 0, 0, 0, 4096, 7, 0x80)
                        elif command in (2, 4, 13):
                            body = struct.pack('<HH', 4, 0)
                        elif command == 11:  # No SMB3 validate-negotiate IOCTL in this 2.1 fixture.
                            status, body = 0xc00000bb, struct.pack('<HBBI', 9, 0, 0, 0) + b'\0'
                        else:
                            raise ValueError('unsupported fixture command')
                except (ValueError, UnicodeError, struct.error):
                    status, body = 0xc0000022, struct.pack('<HBBI', 9, 0, 0, 0) + b'\0'
                flags = 1 | (8 if authenticated else 0)
                reply = struct.pack('<4sHHIHHIIQIIQ16s', b'\xfeSMB', 64, 1, status, command, 1,
                                    flags, 0, fields[8], 0, tree, 1 if challenge else 0, bytes(16)) + body
                if authenticated:
                    reply = reply[:48] + signature(reply, key) + reply[64:]
                connection.sendall(len(reply).to_bytes(4, 'big') + reply)
        except EOFError:
            pass
        finally:
            if opened:
                opened.close()


def client_probe(port):
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.smb3structs import SMB2_DIALECT_21
    client = SMBConnection('Server', '127.0.0.1', sess_port=port, preferredDialect=SMB2_DIALECT_21, timeout=5)
    try:
        client.login('User', 'Password', 'Domain')
        assert client.getDialect() == SMB2_DIALECT_21
        assert client.isSigningRequired()
        tree = client.connectTree('fixture')
        file = client.openFile(tree, 'fixture.txt', desiredAccess=0x00120089)
        client.closeFile(tree, file)
        # Independent client's signer emits a corrupted signature with a wrong key.
        client.getSMBServer()._Session['SessionKey'] = bytes(16)
        try:
            client.openFile(tree, 'fixture.txt', desiredAccess=0x00120089)
            raise AssertionError('tampered signed open accepted')
        except SessionError as error:
            assert error.getErrorCode() == 0xc0000022
    finally:
        client.getSMBServer().get_socket().close()


def smbprotocol_probe(port):
    import uuid
    from smbprotocol.connection import Connection, Dialects
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect
    from smbprotocol.open import Open
    from smbprotocol.exceptions import AccessDenied
    connection = Connection(uuid.uuid4(), '127.0.0.1', port, require_signing=True)
    connection.connect(dialect=Dialects.SMB_2_1_0, timeout=5)
    try:
        session = Session(connection, username='Domain\\User', password='Password',
                          require_encryption=False, auth_protocol='ntlm')
        session.connect()
        tree = TreeConnect(session, r'\\127.0.0.1\fixture')
        tree.connect()
        opened = Open(tree, 'fixture.txt')
        opened.create(2, 0x00120089, 0x80, 7, 1, 0x40)
        opened.close()
        original_send = connection.transport.send
        def corrupt(data):
            original_send(data[:48] + bytes([data[48] ^ 1]) + data[49:])
        connection.transport.send = corrupt
        try:
            Open(tree, 'fixture.txt').create(2, 0x00120089, 0x80, 7, 1, 0x40)
            raise AssertionError('tampered open accepted')
        except AccessDenied:
            pass
        finally:
            connection.transport.send = original_send
    finally:
        connection.disconnect(close=False)


def probe(client_name='impacket'):
    with tempfile.TemporaryDirectory(prefix='taucloud-m0-smb-') as temporary:
        root = Path(temporary)
        (root / 'fixture.txt').write_bytes(b'fixture')
        fixture = Fixture(root)
        thread = threading.Thread(target=fixture.serve)
        thread.start()
        try:
            (client_probe if client_name == 'impacket' else smbprotocol_probe)(fixture.port)
        finally:
            thread.join(20)
        if thread.is_alive() or fixture.error:
            raise RuntimeError(fixture.error or 'SMB fixture timeout')
        assert fixture.events == ['negotiate_2.1_signing_required', 'ntlmv2_authenticated', 'signed_open', 'rejected_unsigned_or_tampered']
        import importlib.metadata
        return {'probe': 'smb_interop', 'status': 'passed', 'client': client_name + ' ' + importlib.metadata.version(client_name),
                'events': fixture.events, 'scope': 'loopback disposable protocol slice, not SMB support'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', choices=['impacket', 'smbprotocol'], default='impacket')
    print(json.dumps(probe(parser.parse_args().client)))
