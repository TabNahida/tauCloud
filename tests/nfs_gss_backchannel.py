#!/usr/bin/env python3
"""Real KDC, independent GSS reverse RPC client, callback lifecycle and tampering."""
import argparse
import json
import socket
import struct
import time
import traceback
from pathlib import Path
import xdrlib3 as xdr
from nfs_gss_integration import GssClient, Kdc, REALM, SERVICE, RpcError, uints, opaque
from nfs_backchannel_integration import CallbackClient
from nfs_notify_lock_integration import NotifyClient
from m7_integration import op, t4, p4
from pynfs_acceptance import fixture


class SecureCallbackClient(GssClient, NotifyClient):
    def __init__(self, port, credentials):
        NotifyClient.__init__(self, port)
        self.credentials, self.service, self.target = credentials, 3, SERVICE
        self.contexts, self.requests = {}, {}
        self.reverse, self.pending, self.received, self.last_reverse = {}, {}, [], {}
        self.corrupt = None

    def offer(self, service, source=None, handle=None):
        source = source or self
        if (100003, 4) not in source.contexts:
            GssClient.establish(source, 100003, 4)
        context, fore, _ = source.contexts[100003, 4]
        back = handle if handle is not None else b'reverse-' + bytes([service]) + fore
        self.reverse[back] = (context, service)
        return t4.callback_sec_parms4(6, cbsp_gss_handles=t4.gss_cb_handles4(service, fore, back))

    def session_back(self, security, **kwargs):
        CallbackClient.establish(self, security, **kwargs)
        assert self.compound([op.reclaim_complete(False)]).status == 0

    def acknowledge(self, xid, suffix=b''):
        context, seq, service = self.pending[xid]
        if self.corrupt == 'unsigned':
            return self.frame(uints(xid, 1, 0, 0, 0, 0) + suffix)
        sequence = seq + 1 if self.corrupt == 'verifier-sequence' else seq
        verifier = context.get_signature(uints(sequence))
        packet = uints(xid, 1, 0, 6) + opaque(verifier) + uints(0)
        if service == 1:
            packet += suffix
        else:
            payload = uints(seq + 1 if self.corrupt == 'body-sequence' else seq) + suffix
            if service == 2:
                mic = context.get_signature(payload)
                if self.corrupt == 'body-mic': mic = mic[:-1] + bytes([mic[-1] ^ 1])
                packet += opaque(payload) + opaque(mic)
            else:
                wrapped = context.wrap(payload, encrypt=True)
                assert wrapped.encrypted
                token = wrapped.message
                if self.corrupt == 'ciphertext': token = token[:-1] + bytes([token[-1] ^ 1])
                packet += opaque(token)
        self.frame(packet)

    def receive(self, data):
        r = xdr.Unpacker(data)
        xid = r.unpack_uint()
        assert r.unpack_uint() == 0
        assert (r.unpack_uint(), r.unpack_uint(), r.unpack_uint()) == (2, self.program, 1)
        proc = r.unpack_uint(); assert proc in (0, 1)
        assert r.unpack_uint() == 6
        credential = r.unpack_bytes(); end = r.get_position()
        c = xdr.Unpacker(credential)
        assert (c.unpack_uint(), c.unpack_uint()) == (1, 0)
        seq, service, handle = c.unpack_uint(), c.unpack_uint(), c.unpack_bytes(); c.done()
        context, expected = self.reverse[handle]; assert service == expected
        assert 0 < seq < 0x80000000 and seq > self.last_reverse.get(id(context), 0)
        self.last_reverse[id(context)] = seq
        assert r.unpack_uint() == 6
        context.verify_signature(data[:end], r.unpack_bytes())
        if service == 1: clear = data[r.get_position():]
        else:
            token = r.unpack_bytes()
            if service == 2:
                context.verify_signature(token, r.unpack_bytes()); clear = token
            else:
                wrapped = context.unwrap(token); assert wrapped.encrypted; clear = wrapped.message
            r.done(); assert clear[:4] == uints(seq); clear = clear[4:]
        self.pending[xid] = context, seq, service
        self.received.append(dict(xid=xid, sequence=seq, service=service, handle=handle, body=clear))
        if proc:
            self.receive_sequence(xid, xdr.Unpacker(clear))
        else:
            assert clear == b''; self.probes.append(xid)
            if not self.hold: self.acknowledge(xid)

    def raw(self, packet):
        self.frame(packet)
        expected = struct.unpack_from('>I', packet)[0]
        def read(n):
            data = b''
            while len(data) < n:
                part = self.sock.recv(n-len(data)); assert part, 'connection closed'
                data += part
            return data
        while True:
            data = b''
            while True:
                marker, = struct.unpack('>I', read(4))
                assert 0 < marker & 0x7fffffff <= 262144
                data += read(marker & 0x7fffffff)
                if marker >> 31: break
            r = xdr.Unpacker(data); xid, direction = r.unpack_uint(), r.unpack_uint()
            if direction == 0:
                self.receive(data); continue
            assert direction == 1 and xid == expected
            if r.unpack_uint() == 1:
                assert r.unpack_uint() == 1
                raise RpcError('denied', r.unpack_uint())
            flavor, verifier, accepted = r.unpack_uint(), r.unpack_bytes(), r.unpack_uint()
            return flavor, verifier, accepted, data[r.get_position():]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--krb5-root', type=Path)
    p.add_argument('--sanitizers', action='store_true')
    args = p.parse_args()
    report = dict(status='failed', checks=[])
    kdc, f, clients = None, None, []
    def passed(message):
        report['checks'].append(message); print('PASS ' + message, flush=True)
    def expect(c, operations, status=0):
        r = c.compound(operations); assert r.status == status, r; return r
    try:
        kdc = Kdc(args.krb5_root)
        f, port = fixture(args.bin, 512 if args.sanitizers else 256)
        f.stop()
        cfg = json.loads((f.state / 'config.json').read_text())
        cfg.update(nfs_gss_service=SERVICE, nfs_gss_keytab=str(kdc.keytab))
        (f.state / 'config.json').write_text(json.dumps(cfg)); f.start()
        f.api('nfs-exports', f.admin, dict(id='nfs', update=True, trust='rpcsec-gss', anonymous='bob',
            uids={'1000': 'alice'}, gids={'1000': 'unix'},
            principals={'alice@'+REALM: dict(uid=1000, gid=1000)}, security=['krb5', 'krb5i', 'krb5p']))
        credentials = kdc.credentials()
        def client(creds=credentials):
            c = SecureCallbackClient(port, creds); clients.append(c); return c
        def bind(c):
            r = c.compound([op.bind_conn_to_session(c.sid, 3, False)], False); assert r.status == 0, r
        def ctl(c, offers, status=0):
            return expect(c, [op.backchannel_ctl(c.program, offers)], status)
        def destroy(source):
            assert source.exchange(source.packet(100003, 4, 0, b'', control=3)) == b''
        def lock(c, handle, state, owner, kind=2, status=0):
            locker = t4.locker4(True, open_owner=t4.open_to_lock_owner4(0, state, 0, t4.lock_owner4(0, owner)))
            r = expect(c, [op.putfh(handle), op.lock(kind, False, 0, 16, locker)], status)
            return r.resarray[-1].oplock.resok4.lock_stateid if not status else c.seq
        # One GSS context can serve many sessions and transports. Fill the
        # advertised RPC window with real authenticated, unanswered CB_NULLs.
        window = client(); window.hold = True; offer = window.offer(3)
        session_ids = []
        for _ in range(32):
            # No file state is needed here. Omit unrelated RECLAIM_COMPLETE
            # calls so all probes fit comfortably within their real deadline.
            CallbackClient.establish(window, [offer]); session_ids.append(window.sid)
        assert window.compound([], False).status == 0
        peer = client(); peer.reverse = window.reverse; peer.hold = True
        for sid in session_ids:
            r = peer.compound([op.bind_conn_to_session(sid, 3, False)], False)
            assert r.status == 0, r
        assert peer.compound([], False).status == 0
        assert len(window.probes) == len(peer.probes) == 32
        third = client(); third.reverse = window.reverse; third.hold = True
        r = third.compound([op.bind_conn_to_session(session_ids[0], 3, False)], False)
        assert r.status == 0, r
        assert third.compound([], False).status == 0 and not third.probes
        # Releasing one oldest request permits exactly one new RPC counter;
        # CB_SEQUENCE now occupies it, while the other original NULLs remain.
        window.acknowledge(window.probes[0]); window.hold_sequence = True
        assert window.compound([], False).status == 0
        for _ in range(10):
            if window.sequences: break
            assert window.compound([], False).status == 0
        assert window.sequences and window.received[-1]['sequence'] == 65
        for sid in session_ids:
            result = window.compound([op.destroy_session(sid)], False)
            assert result.status == 0, result
        window.close(); peer.close(); third.close()
        passed('one context shared across 32 sessions and three TCP paths admits only its 64-entry RPC window; completing the oldest request releases the next authenticated callback')
        holder = client(); holder.session(); root = holder.root()
        def mixed(offer):
            return [t4.callback_sec_parms4(0), offer,
                    t4.callback_sec_parms4(1, t4.authsys_parms(5, b'callback-client', 7, 11, [13, 17]))]
        for service in (1, 2, 3):
            c = client(); offer = c.offer(service)
            # Forward and reverse RPC replay windows cannot share their counters.
            c.contexts[(100003, 4)][2] = 256
            c.session_back(mixed(offer)); c.path(True)
            assert c.received[0]['sequence'] == 1 and len(c.sequences) == 1
            assert not c.flags() & 6
            name = ('secure-callback-' + str(service)).encode()
            hs, handle = holder.open(root, name, True)
            cs, _ = c.open(root, name)
            held = lock(holder, handle, hs, name)
            denied = lock(c, handle, cs, name, 4, 10010)
            expect(holder, [op.putfh(handle), op.locku(2, 0, held, 0, 16)])
            c.poll(count=1)
            event = c.notifications[-1]
            assert (event['handle'], event['owner'], event['reference']) == (handle, name, (c.sid, denied, 0))
            granted = lock(c, handle, cs, name)
            expect(c, [op.putfh(handle), op.locku(2, 0, granted, 0, 16), op.close(0, cs)])
            expect(holder, [op.putfh(handle), op.close(0, hs)])
            c.close()
        holder.close()
        passed('krb5/krb5i/krb5p CB_NULL, CB_SEQUENCE and CB_NOTIFY_LOCK use real Kerberos, independent RPC counters and exact referring calls; notifications grant no lock')

        c = client(); c.session_back([c.offer(3)]); c.path(True)
        bad = t4.callback_sec_parms4(6, cbsp_gss_handles=t4.gss_cb_handles4(3, b'missing', b'back'))
        channel = t4.channel_attrs4(0, 8192, 8192, 0, 16, 4, [])
        for security in (mixed(bad), list(reversed(mixed(bad)))):
            r = c.compound([op.create_session(c.cid, 2, 2, channel, channel, c.program, security)], False)
            assert r.status == 2, r
            c.path(True)
        r = c.compound([op.backchannel_ctl(c.program+1, [bad])]); assert r.status == 2, r
        c.path(True); bind(c); c.path(True)  # Reprobe must still use original program.
        invalid = c.offer(3); invalid.cbsp_gss_handles.gcbp_service = 0
        c.seq += 1
        packed = p4.NFS4Packer(check_enum=False)
        packed.pack_COMPOUND4args(t4.COMPOUND4args(b'invalid-service', 1,
            [op.sequence(c.sid, c.seq, 0, 0, True), op.backchannel_ctl(c.program, [invalid])]))
        assert c.decode4(c.exchange(c.packet(100003, 4, 1, packed.get_buffer()))).status == 22
        c.path(True)
        huge = c.offer(3, handle=b'x'*381); ctl(c, [huge], 22); c.path(True)
        # Adding an existing tuple is idempotent and does not reset its counter.
        previous = c.received[-1]['sequence']
        for _ in range(3): ctl(c, [c.offer(3)]); c.path(True)
        assert c.received[-1]['sequence'] > previous
        passed('BACKCHANNEL_CTL rejects unknown handles/invalid services/oversized RPC credentials atomically; existing handles are idempotent and counters never reset')

        newer = client(); GssClient.establish(newer, 100003, 4)
        old_handle = c.received[-1]['handle']
        ctl(c, [c.offer(2, newer)]); c.path(True)
        # Empty additions keep earlier GSS handles; destroying one fore context
        # must neither silently downgrade to AUTH_NONE nor lose another offer.
        ctl(c, []); c.path(True); assert c.received[-1]['handle'] == old_handle
        destroy(newer); bind(c); c.path(True); assert c.received[-1]['handle'] == old_handle
        c.close(); newer.close()
        passed('BACKCHANNEL_CTL adds handles instead of replacing them; empty additions retain GSS, and destruction of another context preserves the live path')

        # Sixteen live tuples are bounded; rejected additions cannot change the
        # working program/credential. The same tuple does not consume capacity.
        limited = client(); first = limited.offer(3, handle=b'capacity-0')
        limited.session_back([first]); limited.path(True)
        for i in range(1, 16): ctl(limited, [limited.offer(3, handle=f'capacity-{i}'.encode())])
        limited.path(True)
        ctl(limited, [limited.offer(3, handle=b'capacity-overflow')], 10018)
        ctl(limited, [first]); limited.path(True)
        limited.close()
        passed('sixteen live callback tuples are bounded; exhaustion preserves the existing channel and duplicate offers consume no extra capacity')

        for service in (1, 2, 3):
            c = client(); offer = c.offer(service)
            context, _, _ = c.contexts[(100003, 4)]
            handle = offer.cbsp_gss_handles.gcbp_handle_from_client
            pad = lambda n: (n + 3) & ~3
            mic = len(context.get_signature(b'size'))
            def envelope(size):
                if service == 1: return size
                if service == 2: return 12 + pad(size) + pad(mic)
                return 4 + pad(len(context.wrap(b'x'*(size+4), encrypt=True).message))
            request = 60 + pad(len(handle)) + pad(mic) + envelope(56)
            response = max(128, 24 + pad(mic) + envelope(52))
            channel = t4.channel_attrs4(0, request, response, 0, 2, 1, [])
            c.session_back([offer], back=channel); c.path(True)
            too_small = client(); other = too_small.offer(service, c, handle=handle)
            channel.ca_maxrequestsize = request - 1
            too_small.session_back([other], back=channel, expected_back=False)
            too_small.path(False); assert not too_small.received
            too_small.close(); c.close()
        passed('negotiated channel sizes include exact GSS credential, MIC and wrapped-body overhead; exact request limits succeed and one-byte-short channels send no oversized callbacks')

        for service, corruption in ((1, 'unsigned'), (2, 'body-mic'), (3, 'ciphertext'),
                                    (2, 'body-sequence'), (3, 'verifier-sequence')):
            c = client(); c.hold_sequence = True
            c.session_back([c.offer(service)]); c.path(False); assert len(c.sequences) == 1
            original = c.sequences[-1][1]; old_rpc_seq = c.received[-1]['sequence']
            c.corrupt = corruption; c.acknowledge_sequence(); c.wait_closed()
            c.corrupt = None; c.hold_sequence = False; c.reconnect(); c.path(True)
            assert c.sequences[-1][1] == original
            assert c.received[-1]['sequence'] > old_rpc_seq
            c.close()
        passed('unsigned, bad MIC/ciphertext and wrong authenticated sequences cannot complete callbacks; disconnect/rebind retries exact CB_SEQUENCE plaintext with fresh RPC authentication')

        c = client(); short = client(kdc.credentials(lifetime='5s'))
        c.session_back([c.offer(3, short)]); c.path(True)
        assert c.flags() & 2
        time.sleep(7)
        assert c.flags() & 5 == 5
        count = len(c.received); bind(c); c.path(False); assert len(c.received) == count
        renewed = client(); ctl(c, [c.offer(3, renewed)]); bind(c); c.path(True)
        assert not c.flags() & 6
        destroy(renewed); assert c.flags() & 5 == 5
        ctl(c, []); assert c.flags() & 5 == 5
        passed('nearly expired and expired contexts set SEQUENCE flags; expiry/destroy removes path authority without AUTH_NONE fallback, and fresh contexts restore it')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush()
            report['service_log_tail'] = (f.base/'supervisor.log').read_text(errors='replace')[-12000:]
    finally:
        for c in clients: c.close()
        try:
            if f: f.close()
            if kdc: kdc.close()
        except Exception:
            report['status'] = 'failed'; report['cleanup_error'] = traceback.format_exc()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2)+'\n')
    return report['status'] != 'passed'


if __name__ == '__main__':
    raise SystemExit(main())
