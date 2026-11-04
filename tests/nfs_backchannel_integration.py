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

    def frame(self, packet):
        self.sock.sendall(struct.pack('>I', 0x80000000 | len(packet)) + packet)

    def acknowledge(self, xid, suffix=b''):
        self.frame(struct.pack('>6I', xid, 1, 0, 0, 0, 0) + suffix)

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
                assert (r.unpack_uint(), r.unpack_uint(), r.unpack_uint(), r.unpack_uint()) == (2, self.program, 1, 0)
                assert r.unpack_uint() == self.flavor and r.unpack_bytes() == self.credential
                assert r.unpack_uint() == 0 and r.unpack_bytes() == b''
                r.done(); self.probes.append(xid)
                if not self.hold: self.acknowledge(xid)
                continue
            assert direction == 1 and xid == expected, (xid, expected)
            assert r.unpack_uint() == 0 and r.unpack_uint() == 0 and r.unpack_bytes() == b''
            assert r.unpack_uint() == 0
            return data[r.get_position():]

    def establish(self, security=None):
        owner = t4.client_owner4(b'12345678', uuid.uuid4().hex.encode())
        r = self.compound([op.exchange_id(owner, 0, t4.state_protect4_a(0), [])], False)
        assert r.status == 0, r
        exchanged = r.resarray[0].opexchange_id.eir_resok4
        self.cid = exchanged.eir_clientid
        channel = t4.channel_attrs4(0, 131072, 131072, 131072, 16, 4, [])
        r = self.compound([op.create_session(self.cid, exchanged.eir_sequenceid, 2,
                           channel, channel, self.program,
                           security if security is not None else [t4.callback_sec_parms4(0)])], False)
        assert r.status == 0, r
        result = r.resarray[0].opcreate_session.csr_resok4
        assert result.csr_flags & 2
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
        b = client(); b.program = c.program
        r = b.compound([op.bind_conn_to_session(c.sid, 2, False)], False)
        assert r.status == 0 and r.resarray[0].opbind_conn_to_session.bctsr_resok4.bctsr_dir == 2, r
        # A fore request drains and acknowledges any queued probe on b.
        assert b.compound([], False).status == 0
        assert len(b.probes) == 1
        r = b.compound([op.bind_conn_to_session(c.sid, 1, False)], False); assert r.status == 22, r
        both = client(); both.program = c.program
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
