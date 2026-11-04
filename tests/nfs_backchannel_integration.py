#!/usr/bin/env python3
"""Independent bidirectional RPC probes on negotiated NFSv4.1 transports."""
import argparse
import json
import struct
import time
import uuid
from pathlib import Path
import xdrlib3 as xdr
from pynfs_acceptance import fixture
from m7_integration import Client, op, t4


class CallbackClient(Client):
    def __init__(self, port):
        super().__init__(port)
        self.program = 0x40000004
        self.flavor = 0
        self.credential = b''
        self.hold = False
        self.probes = []
        self.hold_sequence = False
        self.sequences = []
        self.callback_cache = {}

    def frame(self, packet):
        self.sock.sendall(struct.pack('>I', 0x80000000 | len(packet)) + packet)

    def acknowledge(self, xid, suffix=b''):
        self.frame(struct.pack('>6I', xid, 1, 0, 0, 0, 0) + suffix)

    def acknowledge_sequence(self, index=-1, body=None):
        xid, request, result = self.sequences[index]
        self.acknowledge(xid, result if body is None else body)

    def receive_sequence(self, xid, r):
        start = r.get_position()
        assert r.unpack_bytes() == b''
        assert (r.unpack_uint(), r.unpack_uint(), r.unpack_uint(), r.unpack_uint()) == (1, 0, 1, 11)
        sid = r.unpack_fopaque(16); seq = r.unpack_uint()
        assert (r.unpack_uint(), r.unpack_uint(), r.unpack_bool(), r.unpack_uint()) == (0, 0, False, 0)
        r.done(); request = r.get_buffer()[start:]
        previous = self.callback_cache.get(sid)
        if previous:
            if seq == previous[0]: assert request == previous[1], 'false callback retry'
            else: assert seq == (previous[0] + 1) & 0xffffffff, 'skipped callback sequence'
        else: assert seq == 1, 'first callback sequence must be one'
        self.callback_cache[sid] = (seq, request)
        p = xdr.Packer()
        p.pack_uint(0); p.pack_bytes(b''); p.pack_uint(1); p.pack_uint(11); p.pack_uint(0)
        p.pack_fopaque(16, sid); p.pack_uint(seq)
        for value in (0, 0, 0): p.pack_uint(value)
        self.sequences.append((xid, request, p.get_buffer()))
        if not self.hold_sequence: self.acknowledge_sequence()

    def exchange(self, packet, fragment=False):
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
                marker = struct.unpack('>I', read(4))[0]
                assert 0 < marker & 0x7fffffff <= 262144
                data += read(marker & 0x7fffffff)
                if marker >> 31: break
            r = xdr.Unpacker(data)
            xid, direction = r.unpack_uint(), r.unpack_uint()
            if direction == 0:
                assert (r.unpack_uint(), r.unpack_uint(), r.unpack_uint()) == (2, self.program, 1)
                procedure = r.unpack_uint(); assert procedure in (0, 1)
                assert r.unpack_uint() == self.flavor and r.unpack_bytes() == self.credential
                assert r.unpack_uint() == 0 and r.unpack_bytes() == b''
                if procedure == 1:
                    self.receive_sequence(xid, r)
                    continue
                r.done(); self.probes.append(xid)
                if not self.hold: self.acknowledge(xid)
                continue
            assert direction == 1 and xid == expected, (xid, expected)
            assert r.unpack_uint() == 0 and r.unpack_uint() == 0 and r.unpack_bytes() == b''
            assert r.unpack_uint() == 0
            return data[r.get_position():]

    def establish(self, security=None, back=None, expected_back=True):
        owner = t4.client_owner4(b'12345678', uuid.uuid4().hex.encode())
        r = self.compound([op.exchange_id(owner, 0, t4.state_protect4_a(0), [])], False)
        assert r.status == 0, r
        exchanged = r.resarray[0].opexchange_id.eir_resok4
        self.cid = exchanged.eir_clientid
        channel = t4.channel_attrs4(0, 131072, 131072, 131072, 16, 4, [])
        r = self.compound([op.create_session(self.cid, exchanged.eir_sequenceid, 2,
                           channel, back if back is not None else channel, self.program,
                           security if security is not None else [t4.callback_sec_parms4(0)])], False)
        assert r.status == 0, r
        result = r.resarray[0].opcreate_session.csr_resok4
        assert bool(result.csr_flags & 2) == expected_back
        self.sid = result.csr_sessionid; self.seq = 0

    def flags(self):
        r = self.compound([op.putrootfh(), op.getfh()])
        assert r.status == 0, r
        return r.resarray[0].opsequence.sr_resok4.sr_status_flags

    def path(self, up):
        for _ in range(50):
            flags = self.flags()
            if bool(flags & 1) != up: return
            time.sleep(.02)
        raise AssertionError(('callback path', up, flags))


def run(args):
    f, port = fixture(args.bin, 512 if args.sanitizers else 256)
    clients = []; checks = []
    def passed(check):
        checks.append(check); print("PASS " + check, flush=True)
    def client():
        c = CallbackClient(port); clients.append(c); return c
    try:
        c = client(); c.establish(); c.path(True)
        assert len(c.probes) == 1
        assert len(c.sequences) == 1 and len(c.sequences[0][1]) == 56
        for _ in range(30): assert not c.flags() & 1
        passed('CREATE_SESSION binds a bidirectional transport; CB_NULL uses the requested program/version and AUTH_NONE while forechannel RPC stays usable')

        # Replies on a different TCP connection cannot validate a probe, even
        # with the exact XID. Duplicates and stale XIDs cannot change state.
        h = client(); h.hold = True; h.establish(); h.path(False)
        assert len(h.probes) == 1
        wrong = client(); wrong.acknowledge(h.probes[-1]); h.path(False)
        h.acknowledge(h.probes[-1]); h.path(True)
        h.acknowledge(h.probes[-1], b'invalid duplicate'); h.path(True)
        passed('probe replies are bound to their exact TCP connection and XID; cross-connection, duplicate and unknown replies cannot change path state')

        # A new callback program invalidates outstanding probes before sending
        # its own probe, and successful validation can recover a down path.
        h.program += 1
        r = h.compound([op.backchannel_ctl(h.program, [t4.callback_sec_parms4(0)])]); assert r.status == 0, r
        h.path(False); old = h.probes[-1]
        h.program += 1
        r = h.compound([op.backchannel_ctl(h.program, [t4.callback_sec_parms4(0)])]); assert r.status == 0, r
        h.path(False); assert h.probes[-1] != old
        h.acknowledge(old); h.path(False)
        h.acknowledge(h.probes[-1], b'bad trailing XDR'); h.path(False)
        r = h.compound([op.bind_conn_to_session(h.sid, 3, False)], False); assert r.status == 0, r
        h.path(False); h.acknowledge(h.probes[-1]); h.path(True)
        passed('BACKCHANNEL_CTL changes program and invalidates old probes; malformed matched replies keep path down and idempotent rebinding reprobes it')

        # Removing usable callback credentials must also invalidate an older
        # pending reply, even though no replacement probe can be sent.
        r = h.compound([op.backchannel_ctl(h.program, [t4.callback_sec_parms4(0)])]); assert r.status == 0, r
        h.path(False); stale = h.probes[-1]
        r = h.compound([op.backchannel_ctl(h.program, [])]); assert r.status == 0, r
        h.acknowledge(stale); h.path(False)
        r = h.compound([op.destroy_session(h.sid)], False); assert r.status == 0, r
        r = h.compound([op.destroy_clientid(h.cid)], False); assert r.status == 0, r
        h.establish(); h.path(False)
        h.acknowledge(stale); h.path(False)
        h.acknowledge(h.probes[-1]); h.path(True)
        passed('cleared callback credentials and destroyed/recreated sessions cannot be validated by a stale probe response')

        # Explicit back-only and both-channel bindings on new connections.
        b = client(); b.program = c.program; b.callback_cache = c.callback_cache
        r = b.compound([op.bind_conn_to_session(c.sid, 2, False)], False)
        assert r.status == 0 and r.resarray[0].opbind_conn_to_session.bctsr_resok4.bctsr_dir == 2, r
        # A fore request drains and acknowledges any queued probe on b.
        assert b.compound([], False).status == 0
        assert len(b.probes) == 1
        r = b.compound([op.bind_conn_to_session(c.sid, 1, False)], False); assert r.status == 22, r
        both = client(); both.program = c.program; both.callback_cache = c.callback_cache
        r = both.compound([op.bind_conn_to_session(c.sid, 7, False)], False)
        assert r.status == 0 and r.resarray[0].opbind_conn_to_session.bctsr_resok4.bctsr_dir == 3, r
        both.sid = c.sid; both.seq = c.seq; both.path(True); c.seq = both.seq
        for direction in (0, 4, 5, 6, 8):
            packet = bytearray(both.compound([op.bind_conn_to_session(c.sid, 1, False)], False, packet_only=True))
            struct.pack_into('>I', packet, len(packet)-8, direction)
            r = both.decode4(both.exchange(packet)); assert r.status == 22, r
        passed('BIND_CONN_TO_SESSION supports BACK and BACK_OR_BOTH on new transports, rejects invalid directions and changes to existing channel roles')

        # AUTH_SYS callbacks must use the credential the client supplied.
        sys_client = client(); sys_client.flavor = 1
        p = xdr.Packer(); p.pack_uint(42); p.pack_string(b'callback-client'); p.pack_uint(1000); p.pack_uint(1000)
        p.pack_array([3, 17], p.pack_uint); sys_client.credential = p.get_buffer()
        sec = t4.callback_sec_parms4(1, t4.authsys_parms(42, b'callback-client', 1000, 1000, [3, 17]))
        sys_client.establish([sec]); sys_client.path(True)
        assert len(sys_client.probes) == 1
        passed('AUTH_SYS CB_NULL carries the offered timestamp, machine name, UID/GID and supplementary groups exactly')

        timeout = client(); timeout.hold = True; timeout.establish(); timeout.path(False)
        late = timeout.probes[-1]; time.sleep(5.2)
        timeout.acknowledge(late); timeout.path(False)
        timeout.hold = False
        r = timeout.compound([op.bind_conn_to_session(timeout.sid, 3, False)], False); assert r.status == 0, r
        timeout.path(True)
        passed('five-second probe timeout ignores late success; rebind recovers the path without recreating the session')

        # The client-wide status tracks all of its sessions/connections.
        observer = client(); observer.sid = sys_client.sid; observer.seq = sys_client.seq
        r = observer.compound([op.bind_conn_to_session(observer.sid, 1, False)], False); assert r.status == 0, r
        sys_client.close(); observer.path(False)
        passed('losing the only callback transport sets CB_PATH_DOWN on a surviving forechannel connection')

        q = client(); q.hold_sequence = True; q.establish(); q.path(False)
        assert len(q.sequences) == 1
        original = q.sequences[0][1]
        valid = q.sequences[0][2]
        wrong.acknowledge(q.sequences[0][0], valid); q.path(False)
        passed('CB_NULL success alone does not validate the sequenced backchannel; CB_SEQUENCE success on the wrong transport is ignored')

        # An untrusted reply must not commit slot state until every field and
        # the complete XDR record have been validated. The client caches seq 1
        # throughout these simulated lost/corrupted replies.
        malformed = [valid + b'junk', valid[:-1]]
        for offset, value in ((0, 10008), (4, 4), (8, 0), (8, 2), (12, 3),
                              (16, 10052), (20, 0), (36, 2), (40, 1)):
            bad = bytearray(valid); struct.pack_into('>I', bad, offset, value); malformed.append(bytes(bad))
        # A well-formed CB_SEQUENCE error also leaves the slot unchanged.
        malformed.append(struct.pack('>5I', 10008, 0, 1, 11, 10008))
        for bad in malformed:
            q.acknowledge_sequence(body=bad); q.path(False)
            r = q.compound([op.bind_conn_to_session(q.sid, 3, False)], False); assert r.status == 0, r
            q.path(False)
            assert q.sequences[-1][1] == original, 'failed reply advanced or changed the callback'
        q.acknowledge_sequence(); q.path(True)
        old_reply = q.sequences[-1]
        q.acknowledge(old_reply[0], old_reply[2]); q.path(True)
        passed('truncated/trailing XDR, bad status/tag/count/op/session/sequence/slot and valid CB_SEQUENCE errors preserve the exact pending request; only a valid reply advances it')

        r = q.compound([op.backchannel_ctl(q.program, [t4.callback_sec_parms4(0)])]); assert r.status == 0, r
        q.path(False)
        assert struct.unpack_from('>I', q.sequences[-1][1], 36)[0] == 2
        q.acknowledge(old_reply[0], old_reply[2]); q.path(False)
        q.acknowledge_sequence(); q.path(True)
        passed('successful CB_SEQUENCE advances exactly once; BACKCHANNEL_CTL retains the session sequence and ignores old duplicate replies')

        q.program += 1
        r = q.compound([op.backchannel_ctl(q.program, [t4.callback_sec_parms4(0)])]); assert r.status == 0, r
        q.path(False); unresolved = q.sequences[-1]
        q.program += 1
        r = q.compound([op.backchannel_ctl(q.program, [t4.callback_sec_parms4(0)])]); assert r.status == 0, r
        q.path(False); assert q.sequences[-1][1] == unresolved[1]
        q.acknowledge(unresolved[0], unresolved[2]); q.path(False)
        q.acknowledge_sequence(); q.path(True)
        passed('callback program replacement cancels the old RPC XID while replaying the unresolved CB_COMPOUND with the same session slot and sequence')

        r = q.compound([op.backchannel_ctl(q.program, [t4.callback_sec_parms4(0)])]); assert r.status == 0, r
        q.path(False); expired = q.sequences[-1]; time.sleep(5.2)
        q.acknowledge_sequence(); q.path(False)
        r = q.compound([op.bind_conn_to_session(q.sid, 3, False)], False); assert r.status == 0, r
        q.path(False); assert q.sequences[-1][1] == expired[1]
        q.acknowledge_sequence(); q.path(True)
        passed('CB_COMPOUND timeout ignores late success and rebinding replays the exact unresolved sequence')

        r = q.compound([op.backchannel_ctl(q.program, [t4.callback_sec_parms4(0)])]); assert r.status == 0, r
        q.path(False); lost = q.sequences[-1]
        replacement = client(); replacement.sid = q.sid; replacement.seq = q.seq
        replacement.program = q.program; replacement.callback_cache = q.callback_cache
        replacement.hold_sequence = True
        r = replacement.compound([op.bind_conn_to_session(q.sid, 7, False)], False); assert r.status == 0, r
        replacement.path(False)
        assert not replacement.sequences, 'slot was reused while its request was still outstanding'
        q.close()
        for _ in range(50):
            replacement.flags()
            if replacement.sequences: break
            time.sleep(.02)
        assert replacement.sequences[-1][1] == lost[1]
        replacement.acknowledge_sequence(); replacement.path(True)
        passed('one callback slot serializes multiple bound paths; transport loss retries the unresolved request on another bound connection')

        stranded = client(); stranded.hold_sequence = True; stranded.establish(); stranded.path(False)
        observe = client(); observe.sid = stranded.sid; observe.seq = stranded.seq
        r = observe.compound([op.bind_conn_to_session(observe.sid, 1, False)], False); assert r.status == 0, r
        assert not observe.flags() & 0x200
        stranded.close()
        for _ in range(50):
            flags = observe.flags()
            if flags & 0x200: break
            time.sleep(.02)
        assert flags & 0x201 == 0x201, flags
        recover = client(); recover.callback_cache = stranded.callback_cache; recover.hold_sequence = True
        r = recover.compound([op.bind_conn_to_session(observe.sid, 2, False)], False); assert r.status == 0, r
        for _ in range(4): assert recover.compound([], False).status == 0
        assert recover.sequences[-1][1] == stranded.sequences[-1][1]
        assert not observe.flags() & 0x200
        recover.acknowledge_sequence(); observe.path(True)
        passed('loss of the only backchannel with an unanswered CB_COMPOUND reports CB_PATH_DOWN_SESSION; binding a replacement clears that flag and preserves the pending sequence')

        grow = client(); grow.hold_sequence = True; grow.establish(); grow.path(False)
        expanded = bytearray(grow.sequences[-1][2])
        struct.pack_into('>II', expanded, 44, 0xffffffff, 0xffffffff)
        grow.acknowledge_sequence(body=bytes(expanded)); grow.path(True)
        r = grow.compound([op.backchannel_ctl(grow.program, [t4.callback_sec_parms4(0)])]); assert r.status == 0, r
        grow.path(False); grow.acknowledge_sequence(); grow.path(True)
        passed('client-advertised slot growth beyond CREATE_SESSION and shrink back to zero are accepted without allocation or increasing callback concurrency')

        gone = client(); gone.hold_sequence = True; gone.establish(); gone.path(False)
        obsolete = gone.sequences[-1]
        r = gone.compound([op.destroy_session(gone.sid)], False); assert r.status == 0, r
        r = gone.compound([op.destroy_clientid(gone.cid)], False); assert r.status == 0, r
        gone.establish(); gone.path(False)
        assert gone.sequences[-1][1][20:36] != obsolete[1][20:36]
        assert struct.unpack_from('>I', gone.sequences[-1][1], 36)[0] == 1
        gone.acknowledge(obsolete[0], obsolete[2]); gone.path(False)
        gone.acknowledge_sequence(); gone.path(True)
        passed('destroying and recreating a session starts a distinct callback slot at sequence one; old CB_COMPOUND success cannot validate it')

        large = client()
        large.establish(back=t4.channel_attrs4(0, 128, 128, 0, 0xffffffff, 0xffffffff, []))
        large.path(True)
        assert len(large.sequences) == 1
        small = client(); small.flavor = sys_client.flavor; small.credential = sys_client.credential
        small.establish([sec], back=t4.channel_attrs4(0, 128, 128, 0, 1, 1, []), expected_back=False)
        small.path(False); assert not small.probes and not small.sequences
        passed('UINT32_MAX offered callback slots require only slot zero; AUTH_SYS credentials must fit the negotiated complete CB_COMPOUND request size')
        report = dict(status='passed', checks=checks, sanitizers=args.sanitizers)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2)+'\n'); print(json.dumps(report))
    finally:
        for c in clients: c.close()
        f.close()


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true'); run(p.parse_args())
