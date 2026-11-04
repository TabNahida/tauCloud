#!/usr/bin/env python3
"""Real MIT KDC and GSSAPI client against NFS RPCSEC_GSS; no synthetic tickets."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import gssapi
import xdrlib3 as xdr
from pynfs_acceptance import fixture
from m7_integration import Client, op, t3

REALM = 'TAUCLOUD.TEST'
SERVICE = 'nfs/localhost@' + REALM


def uints(*values):
    return struct.pack('>' + 'I' * len(values), *values)


def opaque(value):
    p = xdr.Packer()
    p.pack_bytes(value)
    return p.get_buffer()


class Kdc:
    def __init__(self, root=None):
        self.tmp = tempfile.TemporaryDirectory(prefix='tc-krb-')
        self.base = Path(self.tmp.name)
        self.process = None
        self.log = None
        self.saved = {k: os.environ.get(k) for k in ('KRB5_CONFIG', 'KRB5_KDC_PROFILE', 'KRB5CCNAME', 'KRB5RCACHEDIR')}
        self.root = root
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        (self.base / 'krb5.conf').write_text(f'''[libdefaults]
 default_realm = {REALM}
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 dns_canonicalize_hostname = false
 udp_preference_limit = 1
 clockskew = 1
[realms]
 {REALM} = {{
  kdc = 127.0.0.1:{port}
 }}
''')
        modules = f'[dbmodules]\n db_module_dir = {root}/usr/lib/x86_64-linux-gnu/krb5/plugins/kdb\n' if root else ''
        (self.base / 'kdc.conf').write_text(f'''[kdcdefaults]
 kdc_listen = 127.0.0.1:{port}
 kdc_tcp_listen = 127.0.0.1:{port}
[realms]
 {REALM} = {{
  database_name = {self.base}/principal
  key_stash_file = {self.base}/stash
  max_life = 1h
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
 }}
{modules}
[logging]
 default = STDERR
''')
        os.environ.update(KRB5_CONFIG=str(self.base / 'krb5.conf'), KRB5_KDC_PROFILE=str(self.base / 'kdc.conf'),
                          KRB5CCNAME='FILE:' + str(self.base / 'unused.ccache'), KRB5RCACHEDIR=str(self.base))
        try:
            self.run('kdb5_util', 'create', '-s', '-P', 'disposable-kdc-master-key')
            for name in (SERVICE, 'alice@'+REALM, 'bob@'+REALM, 'unmapped@'+REALM, 'nfs/other@'+REALM):
                self.admin('addprinc -randkey ' + name)
            self.keytab = self.base / 'nfs.keytab'
            self.admin(f'ktadd -k {self.keytab} -norandkey {SERVICE}')
            self.log = (self.base / 'kdc.log').open('w')
            self.process = subprocess.Popen([self.tool('krb5kdc'), '-n'], stdout=self.log, stderr=self.log)
            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    assert time.monotonic() < deadline and self.process.poll() is None, 'KDC failed to start'
                    time.sleep(.05)
        except Exception:
            if self.log:
                self.log.flush()
                print((self.base / 'kdc.log').read_text(errors='replace'), flush=True)
            self.close()
            raise

    def tool(self, name):
        if self.root:
            for folder in ('usr/sbin', 'usr/bin'):
                p = self.root / folder / name
                if p.exists():
                    return str(p)
                if p.with_name(name + '.mit').exists():
                    return str(p.with_name(name + '.mit'))
        p = shutil.which(name) or shutil.which(name, path='/usr/sbin:/usr/bin')
        assert p, 'Missing Kerberos test dependency: ' + name
        return p

    def run(self, name, *args):
        p = subprocess.run([self.tool(name), *args], text=True, capture_output=True, timeout=15)
        assert p.returncode == 0, (name, p.stdout, p.stderr)
        return p.stdout

    def admin(self, query):
        return self.run('kadmin.local', '-r', REALM, '-q', query)

    def credentials(self, user='alice', lifetime='1h'):
        keytab = self.base / (user + '.keytab')
        self.admin(f'ktadd -k {keytab} -norandkey {user}@{REALM}')
        cache = self.base / (user + '-' + os.urandom(4).hex() + '.ccache')
        self.run('kinit', '-k', '-t', str(keytab), '-c', str(cache), '-l', lifetime, user + '@' + REALM)
        self.last_cache = cache
        return gssapi.Credentials(usage='initiate', store={'ccache': str(cache)})

    def close(self):
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=10)
        if self.log:
            self.log.close()
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()


class RpcError(Exception):
    def __init__(self, kind, status):
        self.kind, self.status = kind, status
        super().__init__(kind, status)


class GssClient(Client):
    def __init__(self, port, credentials, service=3, target=SERVICE):
        super().__init__(port)
        self.credentials, self.service, self.target = credentials, service, target
        self.contexts, self.requests = {}, {}

    def raw(self, packet):
        self.sock.sendall(uints(0x80000000 | len(packet)) + packet)
        def read(n):
            data = b''
            while len(data) < n:
                part = self.sock.recv(n - len(data))
                assert part, 'connection closed'
                data += part
            return data
        result = b''
        while True:
            marker, = struct.unpack('>I', read(4))
            result += read(marker & 0x7fffffff)
            if marker >> 31:
                break
        u = xdr.Unpacker(result)
        assert u.unpack_uint() == struct.unpack('>I', packet[:4])[0]
        assert u.unpack_uint() == 1
        if u.unpack_uint() == 1:
            assert u.unpack_uint() == 1
            raise RpcError('denied', u.unpack_uint())
        vf, verifier, status = u.unpack_uint(), u.unpack_bytes(), u.unpack_uint()
        return vf, verifier, status, result[u.get_position():]

    def establish(self, program, version):
        context = gssapi.SecurityContext(name=gssapi.Name(self.target, gssapi.NameType.kerberos_principal),
            creds=self.credentials, mech=gssapi.MechType.kerberos, usage='initiate',
            flags=[gssapi.RequirementFlag.mutual_authentication, gssapi.RequirementFlag.integrity,
                   gssapi.RequirementFlag.confidentiality])
        token, handle, control = context.step(), b'', 1
        while True:
            self.xid = (self.xid + 1) & 0xffffffff
            # The sequence and service fields are deliberately undefined in INIT.
            cred = uints(1, control, 0xffffffff, 0) + opaque(handle)
            packet = uints(self.xid, 0, 2, program, version, 0, 6) + opaque(cred) + uints(0, 0) + opaque(token)
            vf, verifier, status, data = self.raw(packet)
            assert status == 0
            u = xdr.Unpacker(data)
            handle = u.unpack_bytes()
            major, minor, window, token = u.unpack_uint(), u.unpack_uint(), u.unpack_uint(), u.unpack_bytes()
            u.done()
            assert major in (0, 1), (major, minor)
            if token:
                token = context.step(token)
            if major == 0:
                assert context.complete and vf == 6 and window == 64
                context.verify_signature(uints(window), verifier)
                break
            assert vf == 0 and verifier == b''
            control = 2
        self.contexts[(program, version)] = [context, handle, 0]

    def packet(self, program, version, proc, body, xid=None, sequence=None, control=0, inner_sequence=None):
        if (program, version) not in self.contexts:
            self.establish(program, version)
        entry = self.contexts[(program, version)]
        context, handle, _ = entry
        entry[2] += 1
        seq = entry[2] if sequence is None else sequence
        self.xid = (self.xid + 1) & 0xffffffff
        xid = self.xid if xid is None else xid
        cred = uints(1, control, seq, self.service) + opaque(handle)
        header = uints(xid, 0, 2, program, version, proc, 6) + opaque(cred)
        packet = header + uints(6) + opaque(context.get_signature(header))
        if self.service == 1:
            packet += body
        else:
            data = uints(seq if inner_sequence is None else inner_sequence) + body
            if self.service == 2:
                packet += opaque(data) + opaque(context.get_signature(data))
            else:
                wrapped = context.wrap(data, encrypt=True)
                assert wrapped.encrypted
                packet += opaque(wrapped.message)
        self.requests[xid] = context, seq, self.service
        return packet

    def exchange(self, packet, fragment=False):
        vf, verifier, status, data = self.raw(packet)
        xid, = struct.unpack('>I', packet[:4])
        context, seq, service = self.requests[xid]
        assert vf == 6, vf
        context.verify_signature(uints(seq), verifier)
        if status:
            raise RpcError('accepted', status)
        if service == 1:
            return data
        u = xdr.Unpacker(data)
        payload = u.unpack_bytes()
        if service == 2:
            context.verify_signature(payload, u.unpack_bytes())
        else:
            clear = context.unwrap(payload)
            assert clear.encrypted
            payload = clear.message
        u.done()
        assert payload[:4] == uints(seq)
        return payload[4:]

    def mount(self, name=b'/nfs'):
        u = xdr.Unpacker(self.exchange(self.packet(100005, 3, 1, opaque(name))))
        status = u.unpack_uint()
        if status:
            return status, None
        handle = u.unpack_bytes()
        self.mount_flavors = u.unpack_array(u.unpack_uint)
        u.done()
        return 0, handle


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--krb5-root', type=Path)
    p.add_argument('--sanitizers', action='store_true')
    p.add_argument('--pynfs', type=Path, help='Prepared, unmodified upstream nfs4.1 suite')
    p.add_argument('--native', action='store_true', help='Run sudo Linux kernel/GSS checks on an isolated runner')
    args = p.parse_args()
    report = dict(status='failed', checks=[])
    kdc, f, clients = None, None, []
    def passed(message):
        report['checks'].append(message)
        print('PASS ' + message, flush=True)
    def reject(client, packet, kind, code):
        try:
            client.exchange(packet)
            raise AssertionError('malformed request accepted')
        except RpcError as e:
            assert (e.kind, e.status) == (kind, code), e
    def silent(client, packet):
        client.sock.settimeout(.25)
        try:
            client.raw(packet)
            raise AssertionError('replay received a reply')
        except TimeoutError:
            pass
        finally:
            client.sock.settimeout(10)
    try:
        kdc = Kdc(args.krb5_root)
        f, port = fixture(args.bin, 512 if args.sanitizers else 256)
        f.stop()
        cfg = json.loads((f.state / 'config.json').read_text())
        cfg.update(nfs_gss_service=SERVICE, nfs_gss_keytab=str(kdc.keytab))
        (f.state / 'config.json').write_text(json.dumps(cfg))
        f.start()
        export = dict(id='nfs', update=True, trust='rpcsec-gss', anonymous='bob',
                      uids={'1000': 'alice', '1001': 'bob'}, gids={'1000': 'unix'},
                      principals={'alice@'+REALM: dict(uid=1000, gid=1000)},
                      security=['krb5', 'krb5i', 'krb5p'])
        f.api('nfs-exports', f.admin, export)
        creds = kdc.credentials()
        def client(service=3, credentials=creds, target=SERVICE):
            c = GssClient(port, credentials, service, target)
            clients.append(c)
            return c
        plain = Client(port)
        clients.append(plain)
        assert plain.mount()[0] == 13
        for service in (1, 2, 3):
            c = client(service)
            status, root = c.mount()
            assert status == 0 and c.mount_flavors == [390003, 390004, 390005]
            c.session()
            assert c.root() == root
            hstate, handle = c.open(root, ('gss-' + str(service)).encode(), create=True)
            data = b'Authenticated Kerberos data\0' * 1024
            r = c.v3('WRITE', t3.WRITE3args(t3.nfs_fh3(handle), 0, len(data), 2, data), 7)
            assert r.status == 0, r
            r = c.v3('READ', t3.READ3args(t3.nfs_fh3(handle), 0, 65536), 6)
            assert r.status == 0 and r.resok.data == data, r
            r = c.compound([op.putfh(handle), op.getattr([0, (1 << 4) | (1 << 5)])])
            assert r.status == 0, r
            r = c.compound([op.putfh(root), op.secinfo(('gss-' + str(service)).encode())])
            assert r.status == 0, r
            assert [x.flavor for x in r.resarray[-1].opsecinfo.resok4] == [6, 6, 6]
            assert c.compound([op.putfh(handle), op.close(0, hstate)]).status == 0
        passed('real MIT tickets: mutual authentication and NFSv3/v4.1 read/write in krb5, krb5i and krb5p; AUTH_SYS downgrade denied; MOUNT and SECINFO advertise Kerberos')

        c = client(2)
        c.establish(100003, 3)
        packet = c.packet(100003, 3, 0, b'')
        forged = bytearray(packet)
        forged[20] ^= 1  # Procedure, covered by header MIC.
        reject(c, bytes(forged), 'denied', 13)
        assert c.exchange(packet) == b''
        silent(c, packet)
        assert c.exchange(c.packet(100003, 3, 0, b'', sequence=100)) == b''
        assert c.exchange(c.packet(100003, 3, 0, b'', sequence=99)) == b''
        silent(c, c.packet(100003, 3, 0, b'', sequence=36))
        reject(c, c.packet(100003, 3, 0, b'', sequence=0x80000000), 'denied', 14)
        # Bad high signed-body sequence is an authenticated RPC error.
        reject(c, c.packet(100003, 3, 0, b'', sequence=101, inner_sequence=102), 'accepted', 4)
        bad = bytearray(c.packet(100003, 3, 0, b'', sequence=102))
        bad[-1] ^= 1
        reject(c, bytes(bad), 'accepted', 4)
        c.service = 3
        bad = bytearray(c.packet(100003, 3, 0, b'', sequence=103))
        bad[-8] ^= 1
        reject(c, bytes(bad), 'accepted', 4)
        assert c.exchange(c.packet(100003, 3, 0, b'', sequence=104)) == b''
        passed('header/body MIC and encrypted-body tampering rejected; 64-entry replay window drops duplicates/old requests and accepts out-of-order requests; MAXSEQ and body sequence enforced')

        c = client()
        c.session()
        root = c.root()
        state, handle = c.open(root, b'replay-file', create=True)
        packet = c.v3('WRITE', t3.WRITE3args(t3.nfs_fh3(handle), 0, 3, 2, b'abc'), 7, True)
        original = c.exchange(packet)
        xid = struct.unpack('>I', packet[:4])[0]
        from m7_integration import p3
        p = p3.NFS3Packer()
        p.pack_WRITE3args(t3.WRITE3args(t3.nfs_fh3(handle), 0, 3, 2, b'abc'))
        retry = c.packet(100003, 3, 7, p.get_buffer(), xid=xid)
        assert c.exchange(retry) == original
        revoked = dict(export, principals={'unmapped@'+REALM: dict(uid=1000, gid=1000)})
        f.api('nfs-exports', f.admin, revoked)
        denied_retry = c.packet(100003, 3, 7, p.get_buffer(), xid=xid)
        assert c.decode3('WRITE', c.exchange(denied_retry)).status == 13
        f.api('nfs-exports', f.admin, export)
        c.sock.close()
        c.sock = socket.create_connection(('127.0.0.1', port), timeout=10)
        assert c.v3('READ', t3.READ3args(t3.nfs_fh3(handle), 0, 3), 6).resok.data == b'abc'
        assert c.compound([op.putfh(handle), op.close(0, state)]).status == 0
        assert c.exchange(c.packet(100003, 3, 0, b'', control=3)) == b''
        reject(c, c.packet(100003, 3, 0, b''), 'denied', 13)
        passed('v3 duplicate mutation with fresh GSS sequence replays its result and rechecks revoked authority; context survives TCP reconnect; authenticated DESTROY invalidates the handle')

        unmapped = client(credentials=kdc.credentials('unmapped'))
        assert unmapped.mount()[0] == 13
        wrong = client(target='nfs/other@'+REALM)
        try:
            wrong.establish(100003, 3)
            raise AssertionError('wrong service ticket accepted')
        except (RpcError, AssertionError) as e:
            assert str(e) != 'wrong service ticket accepted'
        export['security'] = ['krb5p']
        f.api('nfs-exports', f.admin, export)
        weak = client(1)
        assert weak.mount()[0] == 13
        strong = client(3)
        assert strong.mount()[0] == 0
        strong.session()
        h = strong.root()
        export['principals'] = {'unmapped@'+REALM: dict(uid=1000, gid=1000)}
        f.api('nfs-exports', f.admin, export)
        assert strong.v3('GETATTR', t3.GETATTR3args(t3.nfs_fh3(h)), 1).status == 13
        passed('unmapped principals and wrong acceptor tickets denied; per-export privacy requirement prevents downgrade; existing contexts lose access after principal mapping revocation')
        export['principals'] = {'alice@'+REALM: dict(uid=1000, gid=1000)}
        export['security'] = ['krb5', 'krb5i', 'krb5p']
        f.api('nfs-exports', f.admin, export)

        if args.pynfs:
            kdc.credentials()
            env = dict(os.environ, KRB5CCNAME='FILE:' + str(kdc.last_cache))
            report['pynfs'] = {}
            for security in ('krb5', 'krb5i', 'krb5p'):
                # Upstream names files with a seconds-resolution timestamp.
                # Separate roots let consecutive flavors run without collisions.
                tree = f.root / 'nfsdata' / ('upstream-' + security)
                (tree / 'tmp').mkdir(parents=True)
                (tree / 'tree').mkdir()
                (tree / 'tree' / 'file').write_bytes(b'Independent pynfs regular file\n')
                output = args.output.resolve().with_suffix('.' + security + '.json')
                output.parent.mkdir(parents=True, exist_ok=True)
                command = [sys.executable, '-u', 'testserver.py', f'localhost:{port}/nfs/upstream-{security}',
                           '--minorversion=1', '--security='+security, '--noinit', '--nocleanup',
                           '--jsonout', str(output), '--verbose', 'COMP1', 'CSESS1', 'OPEN1', 'OPEN30', 'VF1r']
                with output.with_suffix('.log').open('w') as log:
                    result = subprocess.run(command, cwd=args.pynfs, env=env,
                                            stdout=log, stderr=subprocess.STDOUT, timeout=120)
                assert output.exists(), output.with_suffix('.log').read_text()[-8000:]
                upstream = json.loads(output.read_text())
                report['pynfs'][security] = upstream
                assert result.returncode == 0 and not upstream.get('failures') and not upstream.get('errors'), [
                    t for t in upstream.get('testcase', []) if t.get('failure') or t.get('error')]
            passed('unmodified pinned pynfs COMP1, CSESS1, OPEN1, OPEN30 and VF1r pass using krb5, krb5i and krb5p')

        keep = client()
        assert keep.v3('GETATTR', t3.GETATTR3args(t3.nfs_fh3(h)), 1).status == 0
        next_keytab = kdc.base / 'next.keytab'
        kdc.admin('cpw -randkey ' + SERVICE)
        kdc.admin(f'ktadd -k {next_keytab} -norandkey {SERVICE}')
        os.replace(next_keytab, kdc.keytab)
        fresh = client(credentials=kdc.credentials())
        assert fresh.mount()[0] == 0
        assert keep.v3('GETATTR', t3.GETATTR3args(t3.nfs_fh3(h)), 1).status == 0
        f.api('memberships', f.admin, dict(username='alice', group='unix', enabled=False))
        assert keep.v3('GETATTR', t3.GETATTR3args(t3.nfs_fh3(h)), 1).status == 13
        f.api('memberships', f.admin, dict(username='alice', group='unix'))
        passed('atomic service-key rotation accepts newly issued tickets while established contexts continue; live group-membership revocation denies existing contexts')

        expiring = client(credentials=kdc.credentials(lifetime='5s'))
        expiring.establish(100003, 3)
        expired_packet = expiring.packet(100003, 3, 0, b'')
        time.sleep(7)
        reject(expiring, expired_packet, 'denied', 13)
        before_restart = keep.packet(100003, 3, 0, b'')
        f.stop()
        f.start()
        keep.sock.close()
        keep.sock = socket.create_connection(('127.0.0.1', port), timeout=10)
        reject(keep, before_restart, 'denied', 13)
        renewed = client(credentials=kdc.credentials())
        assert renewed.v3('GETATTR', t3.GETATTR3args(t3.nfs_fh3(h)), 1).status == 0
        passed('expired tickets and pre-restart context handles are rejected; fresh mutual authentication preserves access to stable file handles')
        if args.native:
            from linux_native_gss import exercise
            # rpc.gssd uses the standard v4 service port for its context upcall.
            f.stop()
            cfg['nfs_port'] = 2049
            (f.state / 'config.json').write_text(json.dumps(cfg))
            f.start()
            export['principals'][SERVICE] = dict(uid=1000, gid=1000)
            f.api('nfs-exports', f.admin, export)
            report['native'] = exercise(f, kdc, 2049, args.output)
            passed('unmodified Linux kernel NFSv4.1 mounts and file roundtrips pass with krb5, krb5i and krb5p')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc()
        print(report['error'], flush=True)
    finally:
        for c in clients:
            c.close()
        if f:
            f.close()
        if kdc:
            kdc.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return report['status'] != 'passed'


if __name__ == '__main__':
    raise SystemExit(main())
