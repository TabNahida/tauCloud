#!/usr/bin/env python3
"""Real MIT Kerberos/SPNEGO SMB signing/encryption and principal-policy tests."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import time
import traceback
import uuid

import gssapi
from smbprotocol.connection import Connection
from smbprotocol.session import Session, SMB2SessionSetupRequest, SMB2SessionSetupResponse
from smbprotocol.tree import TreeConnect
from smbprotocol.file_info import FileRenameInformation, FileEndOfFileInformation, FileDispositionInformation

from m5_integration import Fixture, create, denied, setinfo
from nfs_gss_integration import Kdc, REALM
from smb_reauthentication import reauthenticate

HOST = 'files.taucloud.test'
SERVICE = 'cifs/' + HOST + '@' + REALM


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--krb5-root', type=Path)
    parser.add_argument('--sanitizers', action='store_true')
    parser.add_argument('--smbclient', help='Run an unmodified Samba client with required Kerberos')
    parser.add_argument('--native', action='store_true', help='Run real kernel CIFS mounts on an isolated sudo runner')
    args = parser.parse_args()
    report = dict(status='failed', checks=[])
    kdc, f, connections = None, None, []

    def passed(message):
        report['checks'].append(message)
        print('PASS ' + message, flush=True)

    try:
        kdc = Kdc(args.krb5_root)
        for principal in (SERVICE, 'cifs/other@' + REALM):
            kdc.admin('addprinc -randkey ' + principal)
        keytab = kdc.base / 'smb.keytab'
        kdc.admin(f'ktadd -k {keytab} -norandkey {SERVICE}')
        f = Fixture(args.bin, 512 if args.sanitizers else 256)
        f.stop()
        cfg = json.loads((f.state / 'config.json').read_text())
        cfg.update(smb_gss_service=SERVICE, smb_gss_keytab=str(keytab))
        (f.state / 'config.json').write_text(json.dumps(cfg))
        f.start()
        mapping = dict(id='alice-kerberos', principal='alice@' + REALM, username='alice')
        f.api('smb-principals', f.admin, mapping)
        member = f.api('auth/login', data=dict(username='alice', password=f.password, scope='files'))['token']
        f.api('smb-principals', member, dict(mapping, update=True, username='bob'), expected=403)
        f.api('smb-principals', f.admin, dict(mapping, id='duplicate-principal'), expected=409)
        passed('principal mappings require administrator authority and reject ambiguous duplicate principal bindings')

        def tickets(user='alice', lifetime='1h'):
            credentials = kdc.credentials(user, lifetime)
            os.environ['KRB5CCNAME'] = 'FILE:' + str(kdc.last_cache)
            return credentials

        def connection(dialect=0x311, ciphers=None):
            c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
            connections.append(c)
            c.connect(dialect=dialect, timeout=10, preferred_encryption_algos=ciphers)
            # Keep the TCP route private while authenticating the exact FQDN,
            # equivalent to smbclient's explicit -I route below.
            c.server_name = HOST
            return c

        def connect(dialect=0x311, encrypted=False, protocol='kerberos', user='alice', ciphers=None):
            c = connection(dialect, ciphers)
            s = Session(c, username=user + '@' + REALM, require_encryption=encrypted, auth_protocol=protocol)
            s.connect()
            assert s.session_key and s.signing_key
            assert s.signing_required or s.encrypt_data
            if encrypted:
                assert s.encrypt_data and s.encryption_key and s.decryption_key
            t = TreeConnect(s, '\\\\' + HOST + '\\smb')
            t.connect()
            return c, s, t

        tickets()
        for protocol in ('kerberos', 'negotiate'):
            for dialect, encrypted in ((0x210, False), (0x300, True), (0x302, True), (0x311, False), (0x311, True)):
                report['active_profile'] = dict(protocol=protocol, dialect=hex(dialect), encrypted=encrypted)
                c, s, tree = connect(dialect, encrypted, protocol)
                name = f'gss-{protocol}-{dialect}-{encrypted}'
                h = create(tree, name)
                payload = bytes(range(256)) * 300
                for offset in range(0, len(payload), 65536):
                    h.write(payload[offset:offset+65536], offset)
                h.flush()
                assert h.read(0, 65536) + h.read(65536, len(payload)-65536) == payload
                rename = FileRenameInformation(); rename['file_name'] = name + '-renamed'
                setinfo(h, rename)
                truncate = FileEndOfFileInformation(); truncate['end_of_file'] = 19
                setinfo(h, truncate)
                assert h.read(0, 100) == payload[:19]
                delete = FileDispositionInformation(); delete['delete_pending'] = True
                setinfo(h, delete); h.close()
                assert not (f.root / 'smbdata' / (name + '-renamed')).exists()
                c.disconnect()
        passed('real Kerberos and SPNEGO negotiate authenticate SMB2.1/3.0/3.0.2/3.1.1; independent client validates signing and AES encryption during write/read/flush/rename/truncate/delete')

        for cipher in (3, 4):
            for protocol in ('kerberos', 'negotiate'):
                c, s, tree = connect(encrypted=True, protocol=protocol, ciphers=[cipher])
                assert c.cipher_id == cipher and len(s.full_session_key) == 32
                assert len(s.encryption_key) == len(s.decryption_key) == 32 and len(s.signing_key) == 16
                h = create(tree, f'aes256-{cipher}-{protocol}')
                payload = bytes(range(256)) * 256
                h.write(payload); h.flush(); assert h.read(0, len(payload)) == payload
                before = (s.encryption_key, s.decryption_key, s.signing_key)
                tickets()
                reauthenticate(s, 'alice@' + REALM, protocol=protocol)
                assert before == (s.encryption_key, s.decryption_key, s.signing_key)
                assert h.read(0, len(payload)) == payload
                h.close(); c.disconnect()
        passed('AES-256-CCM/GCM derive from the complete 32-byte Kerberos key with independent signed setup, encrypted I/O and renewal checks for Kerberos/SPNEGO')

        if args.smbclient:
            report['samba'] = []
            payload = bytes(range(256)) * 4096
            source, target = f.base / 'source', f.base / 'download'
            source.write_bytes(payload)
            samba_config = f.base / 'smbclient.conf'
            samba_config.write_text('[global]\nworkgroup = TAUCLOUD\nrealm = ' + REALM + '\n')
            for dialect, protection in (('SMB2_10', 'sign'), ('SMB3_11', 'encrypt')):
                command = [args.smbclient, '//' + HOST + '/smb', '-I', '127.0.0.1', '-p', str(f.smbport),
                    '-s', str(samba_config), '-U', 'alice@' + REALM, '--no-pass',
                    '--use-kerberos=required', '--use-krb5-ccache=' + os.environ['KRB5CCNAME'],
                    '--client-protection=' + protection, '--option=client min protocol=' + dialect,
                    '--option=client max protocol=' + dialect, '-c',
                    f'put {source} samba-kerberos; get samba-kerberos {target}; rename samba-kerberos samba-renamed; del samba-renamed']
                result = subprocess.run(command, capture_output=True, text=True, timeout=45)
                report['samba'].append(dict(dialect=dialect, protection=protection,
                    returncode=result.returncode, stdout=result.stdout, stderr=result.stderr))
                assert result.returncode == 0, (result.stdout, result.stderr)
                assert target.read_bytes() == payload
                target.unlink()
            passed('unmodified Samba smbclient requires Kerberos and verifies 1 MiB signed SMB2.1 and encrypted SMB3.1.1 roundtrips')

        tickets('unmapped')
        denied(lambda: connect(user='unmapped'), 0xc000006d)
        credentials = tickets()
        for target, corrupt in (('cifs/other@' + REALM, False), (SERVICE, True)):
            ctx = gssapi.SecurityContext(name=gssapi.Name(target, name_type=gssapi.NameType.kerberos_principal),
                creds=credentials, mech=gssapi.MechType.kerberos, usage='initiate',
                flags=[gssapi.RequirementFlag.mutual_authentication, gssapi.RequirementFlag.integrity,
                       gssapi.RequirementFlag.confidentiality])
            token = ctx.step(None)
            if corrupt:
                token = token[:-1] + bytes([token[-1] ^ 1])
            c = connection()
            request = SMB2SessionSetupRequest(); request['security_mode'] = c.client_security_mode; request['buffer'] = token
            denied(lambda: c.receive(c.send(request)), 0xc000006d)
            c.disconnect()
        passed('unmapped principals, tickets for another acceptor and modified authenticators fail without NTLM or guest fallback')

        ctx = gssapi.SecurityContext(name=gssapi.Name(SERVICE, name_type=gssapi.NameType.kerberos_principal),
            creds=credentials, mech=gssapi.MechType.kerberos, usage='initiate',
            flags=[gssapi.RequirementFlag.mutual_authentication, gssapi.RequirementFlag.integrity])
        token = ctx.step(None)
        c = connection(0x210)
        request = SMB2SessionSetupRequest(); request['security_mode'] = c.client_security_mode; request['buffer'] = token
        response = c.receive(c.send(request))
        reply = SMB2SessionSetupResponse(); reply.unpack(response['data'].get_value())
        ctx.step(reply['buffer'].get_value()); assert ctx.complete
        key = gssapi.raw.inquire_sec_context_by_oid(ctx, gssapi.OID.from_int_seq('1.2.840.113554.1.2.2.5.5'))[0][:16].ljust(16, b'\0')
        packet = response.pack()
        assert int.from_bytes(packet[16:20], 'little') & 8
        assert hmac.new(key, packet[:48] + bytes(16) + packet[64:], hashlib.sha256).digest()[:16] == packet[48:64]
        c.disconnect()
        c = connection(0x210)
        denied(lambda: c.receive(c.send(request)), 0xc000006d)
        c.disconnect()
        passed('independent raw Kerberos verifies mutual AP-REP and final SMB2 HMAC; replaying the same AP-REQ on a fresh transport is rejected')

        # Exercise a real one-leg ticket without GSS mutual auth. Python GSSAPI
        # substitutes default flags for an empty set, so request replay only.
        # The remote cifs.upcall check additionally exercises exact zero flags.
        ctx = gssapi.SecurityContext(name=gssapi.Name(SERVICE, name_type=gssapi.NameType.kerberos_principal),
            creds=credentials, mech=gssapi.MechType.kerberos, usage='initiate', flags=[gssapi.RequirementFlag.replay_detection])
        token = ctx.step(None)
        assert ctx.complete and gssapi.RequirementFlag.mutual_authentication not in ctx.actual_flags
        key = gssapi.raw.inquire_sec_context_by_oid(ctx, gssapi.OID.from_int_seq('1.2.840.113554.1.2.2.5.5'))[0][:16].ljust(16, b'\0')
        c = connection(0x210)
        request = SMB2SessionSetupRequest(); request['security_mode'] = c.client_security_mode; request['buffer'] = token
        response = c.receive(c.send(request))
        packet = response.pack()
        assert int.from_bytes(packet[16:20], 'little') & 8
        assert hmac.new(key, packet[:48] + bytes(16) + packet[64:], hashlib.sha256).digest()[:16] == packet[48:64]
        s = Session(c, require_encryption=False)
        s.session_id = response['session_id'].get_value()
        s.session_key = s.signing_key = s.application_key = key
        s._connected = True; s.encrypt_data = False
        c.session_table[s.session_id] = s
        t = TreeConnect(s, '\\\\' + HOST + '\\smb'); t.connect()
        h = create(t, 'gss-no-flags'); h.write(b'SMB protects this channel')
        assert h.read(0, 25) == b'SMB protects this channel'
        h.close(); c.disconnect()
        c = connection(0x210)
        denied(lambda: c.receive(c.send(request)), 0xc000006d)
        c.disconnect()
        passed('Kerberos without GSS mutual authentication still verifies SMB2 SESSION_SETUP signing and signed file I/O; replay remains rejected')

        for dialect, encrypted in ((0x210, False), (0x300, True), (0x302, True), (0x311, False), (0x311, True)):
            c, s, tree = connect(dialect, encrypted)
            h = create(tree, f'kerberos-renew-{dialect}-{encrypted}'); h.write(b'renew')
            for protocol in ('kerberos', 'negotiate'):
                tickets()
                reauthenticate(s, 'alice@' + REALM, protocol=protocol)
                assert h.read(0, 5) == b'renew'
            h.close(); c.disconnect()
        passed('fresh Kerberos and SPNEGO renew all SMB2/3 dialects with unchanged signing/cipher keys and live file handles')

        f.api('smb-principals', f.admin, dict(id='alias-kerberos', principal='unmapped@' + REALM, username='alice'))
        c, s, tree = connect(encrypted=True)
        h = create(tree, 'principal-renewal', share=0); h.write(b'bound')
        tickets('unmapped')
        denied(lambda: reauthenticate(s, 'unmapped@' + REALM, protocol='kerberos'), 0xc000006d)
        fresh, _, tree = connect(encrypted=True, user='unmapped')
        h2 = create(tree, 'principal-renewal', share=0, disposition=1)
        assert h2.read(0, 5) == b'bound'
        h2.close(); fresh.disconnect(); c.disconnect(close=False)
        tickets()
        c, s, tree = connect(encrypted=True)
        h = create(tree, 'revoked-renewal', share=0)
        f.api('smb-principals', f.admin, dict(mapping, update=True, enabled=False))
        f.api('smb-principals', f.admin, dict(mapping, update=True))
        denied(lambda: reauthenticate(s, 'alice@' + REALM, protocol='negotiate'), 0xc000006d)
        fresh, _, tree = connect(encrypted=True)
        h2 = create(tree, 'revoked-renewal', share=0, disposition=1)
        h2.close(); fresh.disconnect(); c.disconnect(close=False)
        passed('renewal cannot switch to another Kerberos principal mapped to the same account or revive a revoked mapping token; failures release exclusive opens')

        c, s, tree = connect(encrypted=True)
        h = create(tree, 'revoked'); h.write(b'before')
        f.api('smb-principals', f.admin, dict(mapping, update=True, enabled=False))
        denied(lambda: h.read(0, 6), 0xc000006d)
        denied(lambda: connect(), 0xc000006d)
        f.api('smb-principals', f.admin, dict(mapping, update=True))
        c.disconnect(close=False) # Revoked handles cannot perform protocol CLOSE.
        c, s, tree = connect(encrypted=True)
        h = create(tree, 'revoked', disposition=1); assert h.read(0, 6) == b'before'
        h.close(); c.disconnect()
        passed('live principal mapping revocation terminates existing file authority and new logins; explicit reenable admits fresh authentication')

        # Rotating service keys affects new GSS contexts, not established SMB keys.
        c, s, tree = connect(encrypted=True)
        h = create(tree, 'rotation'); h.write(b'old-session')
        kdc.admin('cpw -randkey ' + SERVICE)
        replacement = kdc.base / 'smb-next.keytab'
        kdc.admin(f'ktadd -k {replacement} -norandkey {SERVICE}')
        os.replace(replacement, keytab)
        tickets()
        fresh, _, new_tree = connect(encrypted=True, protocol='negotiate')
        other = create(new_tree, 'rotation', disposition=1)
        assert other.read(0, 11) == b'old-session' and h.read(0, 11) == b'old-session'
        other.close(); h.close(); fresh.disconnect(); c.disconnect()
        passed('atomic cifs keytab rotation admits fresh tickets while existing signed/encrypted sessions remain valid')

        tickets(lifetime='5s')
        c, s, tree = connect(encrypted=True)
        h = create(tree, 'expiry'); h.write(b'expiring')
        time.sleep(7)
        denied(lambda: h.read(0, 8), 0xc000035c)
        tickets()
        reauthenticate(s, 'alice@' + REALM, protocol='negotiate')
        assert h.read(0, 8) == b'expiring'
        h.close(); c.disconnect()
        # No separate NTLM password enrollment is required for Kerberos access.
        f.api('smb/credentials', f.admin, dict(username='alice', enabled=False))
        c, _, tree = connect(encrypted=True)
        h = create(tree, 'expiry', disposition=1); assert h.read(0, 8) == b'expiring'
        h.close(); c.disconnect()
        denied(lambda: f.connect(), 0xc000006d)
        f.api('smb/credentials', f.admin, dict(username='alice', password=f.password))
        legacy, _, _ = f.connect(); connections.append(legacy); legacy.disconnect()
        passed('ticket lifetime bounds SMB authority; Kerberos is independent of NTLM enrollment and existing mandatory-MIC NTLM authentication still works')
        if args.native:
            from linux_native_smb_gss import exercise
            tickets()
            report['native'] = {}
            exercise(f, kdc, HOST, args.output, report['native'])
            passed('native Linux kernel CIFS uses Kerberos for signed SMB2.1 and encrypted SMB3.0/3.0.2/3.1.1 roundtrips')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc()
        print(report['error'], flush=True)
        if f:
            f.log.flush()
            report['server_log'] = (f.base / 'supervisor.log').read_text(errors='replace')[-8000:]
            print(report.get('active_profile'), report['server_log'], flush=True)
    finally:
        for c in connections:
            try: c.disconnect()
            except Exception: pass
        if f: f.close()
        if kdc: kdc.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
