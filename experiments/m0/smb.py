#!/usr/bin/env python3
"""Offline SMB 2.1/NTLMv2 feasibility vectors, NOT an SMB server/interoperability test."""
import hashlib
import hmac
import json
import os
import struct
import subprocess
from updates import openssl


def enroll(password):
    # Mature crypto implementation; legacy MD4 is confined to the NTLM fixture.
    # Password enters stdin, never argv/logs. Production vault and zeroization pending.
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        library = ctypes.WinDLL('bcrypt')
        library.BCryptOpenAlgorithmProvider.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.ULONG]
        library.BCryptHash.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG]
        library.BCryptCloseAlgorithmProvider.argtypes = [wintypes.HANDLE, wintypes.ULONG]
        provider = wintypes.HANDLE()
        if library.BCryptOpenAlgorithmProvider(ctypes.byref(provider), 'MD4', None, 0) < 0:
            raise RuntimeError('CNG MD4 unavailable')
        try:
            value = password.encode('utf-16le')
            output = ctypes.create_string_buffer(16)
            if library.BCryptHash(provider, None, 0, value, len(value), output, 16) < 0:
                raise RuntimeError('CNG MD4 failed')
            return output.raw
        finally:
            library.BCryptCloseAlgorithmProvider(provider, 0)
    result = subprocess.run([openssl(), 'dgst', '-provider', 'default', '-provider', 'legacy', '-md4', '-binary'],
                            input=password.encode('utf-16le'), capture_output=True, check=True)
    if len(result.stdout) != 16:
        raise ValueError('invalid NT hash')
    return result.stdout


def response_key(nt_hash, user, domain):
    return hmac.digest(nt_hash, (user.upper() + domain).encode('utf-16le'), 'md5')


def header(command, message=1, session=0, tree=0, signed=False):
    return struct.pack('<4sHHIHHIIQIIQ16s', b'\xfeSMB', 64, 1, 0, command, 1,
                       8 if signed else 0, 0, message, 0, tree, session, bytes(16))


def decode(packet, command):
    if not 64 <= len(packet) <= 65536:
        raise ValueError('frame budget')
    fields = struct.unpack('<4sHHIHHIIQIIQ16s', packet[:64])
    if fields[0] != b'\xfeSMB' or fields[1] != 64 or fields[4] != command or fields[7] != 0:
        raise ValueError('invalid or unsupported compound header')
    return fields


def negotiate(packet):
    decode(packet, 0)
    if len(packet) < 100:
        raise ValueError('short negotiate')
    size, count, security = struct.unpack_from('<HHH', packet, 64)
    if size != 36 or count < 1 or count > 8 or len(packet) != 100 + count * 2 or security & 3 != 3:
        raise ValueError('negotiate bounds/signing required')
    dialects = struct.unpack_from('<' + 'H' * count, packet, 100)
    if 0x0210 not in dialects:
        raise ValueError('SMB 2.1 fixture only')
    return 0x0210


def signature(packet, session_key):
    return hmac.digest(session_key, packet[:48] + bytes(16) + packet[64:], 'sha256')[:16]


def signed_open(packet, session_key, authenticated):
    fields = decode(packet, 5)
    if not authenticated or fields[6] & 8 == 0 or fields[11] != 1 or fields[10] != 1:
        raise ValueError('unauthenticated session/tree or unsigned open')
    if not hmac.compare_digest(packet[48:64], signature(packet, session_key)):
        raise ValueError('signature mismatch')
    if len(packet) < 120 or struct.unpack_from('<H', packet, 64)[0] != 57:
        raise ValueError('short create')
    offset, length, contexts, context_size = struct.unpack_from('<HHII', packet, 108)
    if contexts or context_size or offset != 120 or length % 2 or offset + length != len(packet):
        raise ValueError('create name bounds/unsupported contexts')
    name = packet[offset:offset + length].decode('utf-16le')
    if name != 'fixture.txt':
        raise ValueError('ungranted object')
    return name


def probe():
    nt_hash = enroll('Password')  # Public MS-NLMP example, not a user credential.
    assert nt_hash.hex() == 'a4f49c406510bdcab6824ee7c30fd852'
    key = response_key(nt_hash, 'User', 'Domain')
    assert key.hex() == '0c868a403bfd7a93a3001ef22ef02e3f'
    challenge = bytes.fromhex('0123456789abcdef')
    blob = (bytes.fromhex('01010000000000000000000000000000aaaaaaaaaaaaaaaa00000000') +
            bytes.fromhex('02000c00') + 'Domain'.encode('utf-16le') +
            bytes.fromhex('01000c00') + 'Server'.encode('utf-16le') + bytes(8))
    proof = hmac.digest(key, challenge + blob, 'md5')
    assert proof.hex() == '68cd0ab851e51c96aabc927bebef6a1c'
    session_key = hmac.digest(key, proof, 'md5')
    assert session_key.hex() == '8de40ccadbc14a82f15cb0ad0de95ca3'
    management_verifier = hashlib.pbkdf2_hmac('sha256', b'Password', b'fixture-only', 1000)
    assert response_key(management_verifier, 'User', 'Domain') != key
    negotiate_packet = header(0) + struct.pack('<HHHHI16sIHH', 36, 1, 3, 0, 0, bytes(16), 0, 0, 0) + struct.pack('<H', 0x210)
    assert negotiate(negotiate_packet) == 0x210
    name = 'fixture.txt'.encode('utf-16le')
    create = header(5, session=1, tree=1, signed=True) + struct.pack(
        '<HBBIQQIIIIIHHII', 57, 0, 0, 2, 0, 0, 0x00120089, 0, 7, 1, 0x40, 120, len(name), 0, 0) + name
    create = create[:48] + signature(create, session_key) + create[64:]
    assert signed_open(create, session_key, True) == 'fixture.txt'
    for packet, authenticated in ((create[:-1] + b'X', True), (create, False), (create[:70], True)):
        try:
            signed_open(packet, session_key, authenticated)
            raise AssertionError('unsafe open accepted')
        except ValueError:
            pass
    for packet in (negotiate_packet[:99], negotiate_packet[:-2] + b'\x02\x02'):
        try:
            negotiate(packet)
            raise AssertionError('unsafe negotiate accepted')
        except ValueError:
            pass
    return {'probe': 'smb_vectors', 'status': 'passed', 'checks': 12,
            'interop': 'not_tested', 'scope': 'offline codecs, NTLMv2 vectors, signed CREATE validation; no SPNEGO/server'}


if __name__ == '__main__':
    print(json.dumps(probe()))
