#!/usr/bin/env python3
"""SSV wire interoperability: independent Python HMAC/AES with real Kerberos bootstrap."""
import argparse
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
from types import SimpleNamespace
import traceback
import time
import uuid
import xdrlib3 as xdr
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from nfs_gss_integration import Kdc, GssClient, RpcError, SERVICE, REALM, uints, opaque
from nfs_machine_credentials import bitmap, CHANNEL
from nfs_gss_backchannel import SecureCallbackClient
from pynfs_acceptance import fixture
from m7_integration import Client, op, t4, p4

HASHES = {1: bytes.fromhex('06052b0e03021a'), **{
    bits: bytes.fromhex('06096086480165030402'+suffix)
    for bits, suffix in ((224,'04'), (256,'01'), (384,'02'), (512,'03'))}}
CIPHERS = {bits: bytes.fromhex('06096086480165030401'+suffix)
           for bits, suffix in ((128,'02'), (192,'16'), (256,'2a'))}
ENFORCE = bitmap(7, 40, 41, 42, 43, 44, 57)
ALLOW = bitmap(4, 14, 21, 42, 45)


class SsvContext:
    def __init__(self, hash_bits, aes_bits, window=3):
        self.hash = getattr(hashlib, 'sha1' if hash_bits == 1 else 'sha'+str(hash_bits))
        self.keylen = aes_bits // 8
        self.window = window
        self.value = bytes(self.hash().digest_size)
        self.seq = 0
        self.keys = {0: self.derive(self.value)}

    def mac(self, key, data): return hmac.new(key, data, self.hash).digest()
    def derive(self, value): return [self.mac(value, uints(i))[:self.keylen] for i in range(1, 5)]
    def rotate(self, delta):
        self.value = bytes(x ^ y for x, y in zip(self.value, delta))
        self.seq += 1
        self.keys[self.seq] = self.derive(self.value)
        self.keys = {seq: keys for seq, keys in self.keys.items() if seq > self.seq - self.window}
    def digest(self, data, direction): return self.mac(self.keys[self.seq][direction-1], data)
    def get_signature(self, data):
        return uints(self.seq) + opaque(self.digest(uints(self.seq)+opaque(data), 1))
    def verify_signature(self, data, token):
        u = xdr.Unpacker(token); seq, digest = u.unpack_uint(), u.unpack_bytes(); u.done()
        assert seq and seq in self.keys, ('SSV version', seq, self.seq)
        assert hmac.compare_digest(digest, self.mac(self.keys[seq][1], uints(seq)+opaque(data)))
    def wrap(self, data, encrypt=True):
        assert encrypt
        plain = opaque(os.urandom(16)) + uints(self.seq) + opaque(data)
        plain += opaque(bytes((-len(plain)-4) % 16))
        iv = os.urandom(16)
        enc = Cipher(algorithms.AES(self.keys[self.seq][2]), modes.CBC(iv)).encryptor()
        token = uints(self.seq)+opaque(iv)+opaque(enc.update(plain)+enc.finalize())+opaque(self.digest(plain, 1))
        return SimpleNamespace(encrypted=True, message=token)
    def unwrap(self, token):
        u = xdr.Unpacker(token)
        seq, iv, cipher, digest = u.unpack_uint(), u.unpack_bytes(), u.unpack_bytes(), u.unpack_bytes(); u.done()
        assert seq and seq in self.keys
        dec = Cipher(algorithms.AES(self.keys[seq][3]), modes.CBC(iv)).decryptor()
        plain = dec.update(cipher)+dec.finalize()
        assert hmac.compare_digest(digest, self.mac(self.keys[seq][1], plain))
        u = xdr.Unpacker(plain); u.unpack_bytes(); assert u.unpack_uint() == seq
        data, pad = u.unpack_bytes(), u.unpack_bytes(); u.done(); assert not any(pad)
        return SimpleNamespace(encrypted=True, message=data)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--krb5-root', type=Path); p.add_argument('--sanitizers', action='store_true')
    a = p.parse_args(); f = kdc = None; clients = []; report = dict(status='failed', checks=[])
    def passed(message): report['checks'].append(message); print('PASS '+message, flush=True)
    def client(credentials, service=3):
        c = GssClient(port, credentials, service); clients.append(c); return c
    def expect(c, operations, status=0, session=True, seq=None):
        r = c.compound(operations, session, seq=seq); assert r.status == status, r; return r
    def exchange(c, owner=None, hash_bits=256, aes_bits=256, hashes=None, ciphers=None,
                 window=3, handles=2, flags=0, enforce=ENFORCE, allow=ALLOW, status=0):
        owner = owner or uuid.uuid4().hex.encode()
        state = t4.state_protect4_a(2, spa_ssv_parms=t4.ssv_sp_parms4(
            t4.state_protect_ops4(enforce, allow),
            hashes if hashes is not None else [b'unknown', HASHES[hash_bits]],
            ciphers if ciphers is not None else [b'unknown', CIPHERS[aes_bits]], window, handles))
        r = expect(c, [op.exchange_id(t4.client_owner4(b'12345678', owner), flags, state, [])], status, False)
        return r.resarray[0].opexchange_id.eir_resok4 if not status else r
    def create(c, cid, seq=1, status=0):
        r = expect(c, [op.create_session(cid, seq, 0, CHANNEL, CHANNEL, 0, [])], status, False)
        if not status: c.cid, c.sid, c.seq = cid, r.resarray[0].opcreate_session.csr_resok4.csr_sessionid, 0
        return r
    def use(c, context, handle): c.contexts[(100003,4)] = [context, handle, 0]
    def reject(c, packet, status=13):
        try: c.exchange(packet); raise AssertionError('invalid SSV accepted')
        except RpcError as e: assert (e.kind, e.status) == ('denied', status), e
    def set_ssv(c, context, delta=None, status=0, bad_digest=False):
        delta = os.urandom(len(context.value)) if delta is None else delta
        seq = c.seq + 1
        seqarg = t4.SEQUENCE4args(c.sid, seq, 0, 0, True)
        pack = p4.NFS4Packer(); pack.pack_SEQUENCE4args(seqarg)
        digest = context.digest(pack.get_buffer(), 1)
        if bad_digest: digest = bytes(len(digest))
        packet = c.compound([op.set_ssv(delta, digest)], packet_only=True)
        if not status: context.rotate(delta)
        result = c.decode4(c.exchange(packet)); assert result.status == status, result
        if not status:
            pack = p4.NFS4Packer(); pack.pack_SEQUENCE4res(result.resarray[0].opsequence)
            assert hmac.compare_digest(result.resarray[1].opset_ssv.ssr_resok4.ssr_digest,
                                       context.digest(pack.get_buffer(), 2))
        return result, delta, digest
    try:
        kdc = Kdc(a.krb5_root); f, port = fixture(a.bin, 1024 if a.sanitizers else 256)
        f.stop(); cfg = json.loads((f.state/'config.json').read_text())
        cfg.update(nfs_gss_service=SERVICE, nfs_gss_keytab=str(kdc.keytab))
        (f.state/'config.json').write_text(json.dumps(cfg)); f.start()
        export = dict(id='nfs', update=True, trust='rpcsec-gss', anonymous='bob',
            uids={'1000':'alice'}, gids={'1000':'unix'},
            principals={'alice@'+REALM:dict(uid=1000,gid=1000)}, security=['krb5','krb5i','krb5p'])
        f.api('nfs-exports', f.admin, export)
        credentials = kdc.credentials(); other_credentials = kdc.credentials('bob')
        plain = Client(port); clients.append(plain); exchange(plain, status=1); plain.close()
        weak = client(credentials, 1); exchange(weak, status=1); weak.close()
        passed('AUTH_SYS and authentication-only Kerberos cannot establish SP4_SSV')
        c = client(credentials)
        for kwargs, status in ((dict(hashes=[]),22), (dict(ciphers=[]),22), (dict(window=0),22),
                (dict(hashes=[b'unknown']),10072), (dict(ciphers=[b'unknown']),10079),
                (dict(hash_bits=1, aes_bits=256),10079), (dict(hash_bits=224, aes_bits=256),10079)):
            exchange(c, status=status, **kwargs)
        c.close()
        passed('empty algorithms, zero window, unsupported OIDs and forbidden hash/cipher combinations return protocol errors')

        for hash_bits, aes_bits in ((1,128), (224,192), (256,256), (384,256), (512,256)):
            c = client(credentials); owner = uuid.uuid4().hex.encode()
            result = exchange(c, owner, hash_bits, aes_bits)
            info = result.eir_state_protect.spr_ssv_info
            assert info.spi_hash_alg == info.spi_encr_alg == 1
            assert info.spi_window == 3 and len(info.spi_handles) == 2
            context = SsvContext(hash_bits, aes_bits)
            assert info.spi_ssv_len == len(context.value)
            s = client(credentials); use(s, context, info.spi_handles[0])
            reject(s, s.packet(100003,4,0,b''))  # Initial zero SSV is never an authentication key.
            other = client(other_credentials); create(other, result.eir_clientid, status=10082); other.close()
            create(c, result.eir_clientid)
            reject(s, s.packet(100003,4,0,b''))
            created = create(c, result.eir_clientid)  # Same credential must also support confirming replay.
            expect(c, [op.reclaim_complete(False)])
            set_ssv(c, context, bad_digest=True, status=10051)
            set_ssv(c, context, delta=b'wrong-length', status=22)
            set_ssv(c, context)
            s.cid, s.sid = c.cid, c.sid
            expect(s, [op.bind_conn_to_session(c.sid, 1, False)], session=False)
            s.seq = c.seq
            for service in (1,2,3):
                s.service = service
                assert s.exchange(s.packet(100003,4,0,b'')) == b''
                expect(s, [op.backchannel_ctl(0, [])], 10082 if service == 1 else 0)
            s.service = 3; c.seq = s.seq
            passed(f'SHA-{hash_bits}/AES-{aes_bits}: indexes, confirmation identity, zero-key rejection, SET_SSV digest/length and all three RPC protection services')

            # A server reply cannot be accepted as a client MIC (directional subkeys).
            token = uints(context.seq)+opaque(context.digest(uints(context.seq)+opaque(b'x'),2))
            original = context.get_signature
            context.get_signature = lambda _: token
            reject(s, s.packet(100003,4,0,b'')); context.get_signature = original
            packet = bytearray(s.packet(100003,4,0,b'')); packet[-1] ^= 1
            try: s.exchange(bytes(packet)); raise AssertionError('tampered privacy accepted')
            except RpcError as e: assert (e.kind,e.status) == ('accepted',4), e
            passed(f'SHA-{hash_bits}: reflected signatures and corrupted privacy payloads do not authenticate')

            # Independent handle counters share the same rotating key state.
            second = SecureCallbackClient(port, credentials); clients.append(second)
            use(second, context, info.spi_handles[1])
            second.cid, second.sid = c.cid, c.sid
            expect(second, [op.bind_conn_to_session(c.sid,1,False)], session=False)
            old = copy.deepcopy(context)
            set_ssv(c, context)
            s.contexts[(100003,4)][0] = old
            # Send with old keys; verify replies with the current shared context.
            packet = s.packet(100003,4,0,b''); xid = int.from_bytes(packet[:4], 'big')
            s.requests[xid] = context, s.requests[xid][1], s.service
            assert s.exchange(packet) == b''
            s.contexts[(100003,4)][0] = context
            assert second.exchange(second.packet(100003,4,0,b'')) == b''
            set_ssv(c, context); set_ssv(c, context)
            s.contexts[(100003,4)][0] = old
            reject(s, s.packet(100003,4,0,b''))
            s.contexts[(100003,4)][0] = context
            passed(f'SHA-{hash_bits}: handles have independent RPC counters, share key rotations, accept the negotiated old-key window and reject expired versions')

            next_create = 2
            if hash_bits == 256:
                callback_handles = exchange(s,owner,handles=3).eir_state_protect.spr_ssv_info.spi_handles
                set_ssv(c,context)
                for service in (1,2,3):
                    use(second,context,callback_handles[service-1])
                    offer = second.offer(service)
                    created = expect(second, [op.create_session(c.cid,next_create,2,CHANNEL,CHANNEL,
                        second.program,[offer])], session=False)
                    second.sid = created.resarray[0].opcreate_session.csr_resok4.csr_sessionid
                    second.seq = 0; next_create += 1
                    for _ in range(50):
                        callback_flags = expect(second,[]).resarray[0].opsequence.sr_resok4.sr_status_flags
                        if not callback_flags & 1: break
                        time.sleep(.02)
                    assert not callback_flags & 1, callback_flags
                    assert second.received[-1]['service'] == service
                    assert not callback_flags & 6
                    expect(second, [op.destroy_session(second.sid)], session=False)
                passed('SSV CB_NULL and CB_SEQUENCE authenticate all three services across distinct handles with one non-repeating reverse counter for the shared context')
                root = c.root(); state, handle = c.open(root,b'ssv-cleanup',True)
                # Revoking user mapping must not prevent negotiated cleanup.
                export['principals'] = {'bob@'+REALM:dict(uid=1000,gid=1000)}
                f.api('nfs-exports',f.admin,export)
                s.seq = c.seq
                expect(s,[op.delegpurge(0)])
                expect(s,[op.putfh(handle),op.read(state,0,16)],13)
                expect(s,[op.putfh(handle),op.close(0,state)])
                c.seq = s.seq
                export['principals'] = {'alice@'+REALM:dict(uid=1000,gid=1000)}
                f.api('nfs-exports',f.admin,export)
                passed('SSV state-only credentials cannot read user data but can close negotiated state after user mapping revocation')
                foreign = client(other_credentials); foreign_owner = uuid.uuid4().hex.encode()
                foreign_policy = bitmap(40,41,43,44,57)
                foreign_result = exchange(foreign,foreign_owner,handles=0,enforce=foreign_policy)
                assert foreign_result.eir_state_protect.spr_ssv_info.spi_handles == []
                create(foreign,foreign_result.eir_clientid)
                foreign_context = SsvContext(256,256); set_ssv(foreign,foreign_context)
                extra = exchange(foreign,foreign_owner,handles=1,enforce=foreign_policy)
                use(foreign,foreign_context,extra.eir_state_protect.spr_ssv_info.spi_handles[0])
                expect(foreign,[op.bind_conn_to_session(c.sid,1,False)],10082,False)
                expect(foreign,[op.destroy_clientid(c.cid)],10082,False)
                expect(foreign,[op.destroy_session(foreign.sid)],session=False)
                expect(foreign,[op.destroy_clientid(foreign.cid)],session=False)
                foreign.close()
                exchange(s,owner,hash_bits=512,status=10027)
                exchange(s,owner,window=2,status=22)
                passed('zero initial handles can be added after confirmation; foreign SSV credentials cannot bind or destroy another client; algorithms/window cannot silently change')

            s.seq = c.seq
            result, delta, digest = set_ssv(s, context)
            replay = expect(s, [op.set_ssv(delta,digest)], seq=s.seq)
            assert replay.resarray[1].opset_ssv.ssr_resok4.ssr_digest == result.resarray[1].opset_ssv.ssr_resok4.ssr_digest
            assert second.exchange(second.packet(100003,4,0,b'')) == b''
            # Subsequent EXCHANGE_ID creates additive handles without resetting the SSV.
            again = exchange(s, owner, hash_bits, aes_bits, enforce=[], allow=[])
            new_info = again.eir_state_protect.spr_ssv_info
            assert again.eir_clientid == c.cid and new_info.spi_ops.spo_must_enforce == ENFORCE
            assert not set(new_info.spi_handles).intersection(info.spi_handles)
            use(second, context, new_info.spi_handles[0])
            assert second.exchange(second.packet(100003,4,0,b'')) == b''
            assert second.exchange(second.packet(100003,4,0,b'',control=3)) == b''
            reject(second,second.packet(100003,4,0,b''))
            use(second,context,new_info.spi_handles[1])
            assert second.exchange(second.packet(100003,4,0,b'')) == b''
            reject(second,second.packet(100003,4,0,b'',sequence=0x80000000),14)
            reject(second,second.packet(100003,4,0,b''))
            extra = exchange(s,owner,hash_bits,aes_bits,handles=1).eir_state_protect.spr_ssv_info.spi_handles
            use(second,context,extra[0])
            exchange(c, owner, hash_bits, aes_bits, status=10082)
            create(c, c.cid, seq=next_create, status=10082)
            old_sid = s.sid; create(s, c.cid, seq=next_create)
            expect(s, [op.destroy_session(old_sid)], session=False)
            expect(s, [op.destroy_session(s.sid)], session=False)
            expect(s, [op.destroy_clientid(c.cid)], session=False)
            reject(second, second.packet(100003,4,0,b''))
            passed(f'SHA-{hash_bits}: self-protected SET_SSV and exact replay, immutable policy, additive handles, protected session maintenance and client destruction')
            c.close(); s.close(); second.close()
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush(); report['server_log'] = (f.base/'supervisor.log').read_text(errors='replace')[-16000:]
    finally:
        for c in clients:
            try: c.close()
            except Exception: pass
        if f:
            try: f.close()
            except Exception: report['status']='failed'; report['cleanup_error']=traceback.format_exc()
        if kdc: kdc.close()
        a.output.parent.mkdir(parents=True, exist_ok=True); a.output.write_text(json.dumps(report,indent=2)+'\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(main())
