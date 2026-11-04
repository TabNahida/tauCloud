#!/usr/bin/env python3
"""Independent CB_NOTIFY_LOCK semantics, authority and exact callback replay."""
import argparse
import json
import struct
import time
from pathlib import Path
import xdrlib3 as xdr
from nfs_backchannel_integration import CallbackClient
from m7_integration import Client, op, t4
from pynfs_acceptance import fixture


class NotifyClient(CallbackClient):
    def __init__(self, port):
        super().__init__(port)
        self.notifications = []
        self.hold_notifications = False
        self.notify_status = 0

    def receive_sequence(self, xid, r):
        start = r.get_position()
        assert r.unpack_bytes() == b''
        assert (r.unpack_uint(), r.unpack_uint()) == (1, 0)
        count = r.unpack_uint()
        if count == 1:
            r.set_position(start)
            return super().receive_sequence(xid, r)
        assert count == 2 and r.unpack_uint() == 11
        sid = r.unpack_fopaque(16); sequence = r.unpack_uint()
        assert (r.unpack_uint(), r.unpack_uint(), r.unpack_bool()) == (0, 0, False)
        assert r.unpack_uint() == 1
        referring_session = r.unpack_fopaque(16)
        assert r.unpack_uint() == 1
        referring_sequence, referring_slot = r.unpack_uint(), r.unpack_uint()
        assert referring_slot == 0 and r.unpack_uint() == 13
        handle, client, owner = r.unpack_bytes(), r.unpack_uhyper(), r.unpack_bytes()
        r.done(); request = r.get_buffer()[start:]
        previous = self.callback_cache[sid]
        if sequence == previous[0]: assert request == previous[1], 'false callback retry'
        else: assert sequence == (previous[0] + 1) & 0xffffffff
        self.callback_cache[sid] = (sequence, request)
        p = xdr.Packer()
        p.pack_uint(self.notify_status); p.pack_bytes(b''); p.pack_uint(2); p.pack_uint(11); p.pack_uint(0)
        p.pack_fopaque(16, sid); p.pack_uint(sequence)
        for value in (0, 0, 0): p.pack_uint(value)
        p.pack_uint(13); p.pack_uint(self.notify_status)
        self.notifications.append(dict(xid=xid, request=request, result=p.get_buffer(),
                                       handle=handle, client=client, owner=owner,
                                       reference=(referring_session, referring_sequence, referring_slot)))
        if not self.hold_notifications: self.acknowledge_notification()

    def acknowledge_notification(self, body=None):
        item = self.notifications[-1]
        self.acknowledge(item['xid'], item['result'] if body is None else body)

    def poll(self, seconds=0, count=None):
        deadline = time.monotonic() + (seconds if count is None else 5)
        while True:
            r = self.compound([]); assert r.status == 0, r
            if count is not None and len(self.notifications) >= count: return
            if time.monotonic() >= deadline:
                assert count is None, (count, len(self.notifications))
                return
            time.sleep(.05)


def run(args):
    f, port = fixture(args.bin, 512 if args.sanitizers else 256)
    clients, checks = [], []
    def passed(message):
        checks.append(message); print('PASS ' + message, flush=True)
    def client(notify=False, uid=1000, back=None):
        c = NotifyClient(port) if notify else Client(port)
        c.uid = uid; clients.append(c)
        if notify:
            c.establish(back=back); c.path(True)
            assert c.compound([op.reclaim_complete(False)]).status == 0
        else: c.session()
        return c
    def expect(c, operations, status=0):
        r = c.compound(operations); assert r.status == status, r; return r
    def opened(c, root, name, create=False):
        how = t4.openflag4(1, t4.createhow4(1, t4.fattr4([], b''))) if create else t4.openflag4(0)
        r = expect(c, [op.putfh(root), op.open(0, 3, 0, t4.open_owner4(c.cid, name), how,
                                            t4.open_claim4(0, file=name)), op.getfh()])
        result = r.resarray[2].opopen.resok4
        assert result.rflags & 0x20
        return result.stateid, r.resarray[3].opgetfh.resok4.object
    def lock(c, handle, state, owner, kind=2, offset=0, length=16, status=0):
        locker = t4.locker4(True, open_owner=t4.open_to_lock_owner4(0, state, 0, t4.lock_owner4(0, owner)))
        r = expect(c, [op.putfh(handle), op.lock(kind, False, offset, length, locker)], status)
        return r.resarray[-1].oplock.resok4.lock_stateid if status == 0 else c.seq
    def unlock(c, handle, state, offset=0, length=16):
        return expect(c, [op.putfh(handle), op.locku(2, 0, state, offset, length)]).resarray[-1].oplocku.lock_stateid
    try:
        a, b, rival = client(), client(True), client()
        root = a.root()
        sa, h = opened(a, root, b'advisory', True); sb, _ = opened(b, root, b'advisory'); sr, _ = opened(rival, root, b'advisory')
        held = lock(a, h, sa, b'holder')
        denied = lock(b, h, sb, b'reader', 3, 4, 4, 10010)
        b.poll(.2); assert not b.notifications
        unlock(a, h, held); b.poll(count=1)
        event = b.notifications[-1]
        assert (event['handle'], event['client'], event['owner'], event['reference']) == (h, b.cid, b'reader', (b.sid, denied, 0))
        # Receiving the notification has not reserved or granted the range.
        race = lock(rival, h, sr, b'rival', 2, 4, 4)
        lock(b, h, sb, b'reader', 3, 4, 4, 10010)
        unlock(rival, h, race, 4, 4); b.poll(count=2)
        acquired = lock(b, h, sb, b'reader', 3, 4, 4)
        unlock(b, h, acquired, 4, 4)
        passed('OPEN advertises MAY_NOTIFY_LOCK; READW conflict release delivers exact handle/owner/referring request; the hint neither grants nor reserves the lock')

        sa, h = opened(a, root, b'nonblocking', True); sb, _ = opened(b, root, b'nonblocking')
        held = lock(a, h, sa, b'holder'); count = len(b.notifications)
        lock(b, h, sb, b'cancelled', 4, status=10010)
        lock(b, h, sb, b'cancelled', 2, status=10010)
        lock(b, h, sb, b'poller', 2, status=10010)
        unlock(a, h, held); b.poll(1.4); assert len(b.notifications) == count
        passed('nonblocking LOCK denial does not enroll a waiter and cancels a previous blocking request for the same owner/file')

        sa, h = opened(a, root, b'closed-waiter', True); sb, _ = opened(b, root, b'closed-waiter')
        held = lock(a, h, sa, b'holder'); count = len(b.notifications)
        lock(b, h, sb, b'closed', 4, status=10010)
        expect(b, [op.putfh(h), op.close(0, sb)])
        unlock(a, h, held); b.poll(1.4); assert len(b.notifications) == count
        passed('closing the waiting OPEN removes its unsent notification without granting lock state')

        f.api('memberships', f.admin, dict(username='bob', group='unix'))
        f.api('grants', f.admin, dict(space='nfsdata', subject_type='user', subject='bob', rights='rw'))
        f.api('nfs-exports', f.admin, dict(id='nfs', trust='loopback-auth-sys', anonymous='bob', update=True,
                                          uids={'1000':'alice', '1001':'bob'}, gids={'1000':'unix'}))
        restricted = client(True, 1001)
        sa, h = opened(a, root, b'revoked-waiter', True)
        # Make the file writable by both enrolled users via the shared group.
        attrs = xdr.Packer(); attrs.pack_uint(0o660)
        expect(a, [op.putfh(h), op.setattr(sa, t4.fattr4([0, 2], attrs.get_buffer()))])
        sb, _ = opened(restricted, root, b'revoked-waiter')
        held = lock(a, h, sa, b'holder'); lock(restricted, h, sb, b'revoked', 4, status=10010)
        f.api('grants', f.admin, dict(space='nfsdata', subject_type='user', subject='bob', rights='r'))
        unlock(a, h, held); restricted.poll(1.4); assert not restricted.notifications
        f.api('grants', f.admin, dict(space='nfsdata', subject_type='user', subject='bob', rights='rw'))
        restricted.poll(1.4); assert not restricted.notifications
        passed('fresh write-policy authority is required before dispatch; revocation drops the waiter and restoring rights does not resurrect it')

        sa, h = opened(a, root, b'replay-notify', True); sb, _ = opened(b, root, b'replay-notify')
        held = lock(a, h, sa, b'holder'); b.hold_notifications = True; count = len(b.notifications)
        lock(b, h, sb, b'replay', 4, status=10010); unlock(a, h, held); b.poll(count=count+1)
        original = b.notifications[-1]
        malformed = bytearray(original['result']); struct.pack_into('>I', malformed, len(malformed)-4, 10004)
        b.acknowledge_notification(bytes(malformed)); b.wait_closed()
        b.reconnect(); b.poll(count=count+2)
        assert b.notifications[-1]['request'] == original['request']
        original = b.notifications[-1]
        b.wait_closed() # Five-second timeout must disconnect before retry.
        b.notify_status = 10068 # Client retained CB_SEQUENCE but not the optional hint's result.
        b.reconnect(); b.poll(count=count+3)
        assert b.notifications[-1]['request'] == original['request']
        b.acknowledge(original['xid'], original['result']); b.poll(.1)
        b.acknowledge_notification(); b.hold_notifications = False; b.notify_status = 0; b.path(True)
        b.poll(1.2); assert len(b.notifications) == count+3
        passed('inconsistent operation status and lost notification reply cause disconnect then exact two-operation replay; RETRY_UNCACHED_REP consumes the slot without granting a lock')

        sa, h = opened(a, root, b'ordered-notify', True); sb, _ = opened(b, root, b'ordered-notify')
        held = lock(a, h, sa, b'holder'); b.hold_notifications = True; count = len(b.notifications)
        for owner in (b'one', b'two'): lock(b, h, sb, owner, 4, status=10010)
        unlock(a, h, held); b.poll(count=count+1); b.poll(1.2)
        assert len(b.notifications) == count+1
        b.acknowledge_notification(); b.poll(count=count+2)
        assert {e['owner'] for e in b.notifications[-2:]} == {b'one', b'two'}
        b.acknowledge_notification(); b.hold_notifications = False; b.path(True)
        passed('multiple waiting owners share one bounded callback slot and no second notification is sent before the first completes')

        sa, h = opened(a, root, b'unsupported-notify', True); sb, _ = opened(b, root, b'unsupported-notify')
        held = lock(a, h, sa, b'holder'); b.notify_status = 10004; count = len(b.notifications)
        lock(b, h, sb, b'optional', 4, status=10010); unlock(a, h, held); b.poll(count=count+1); b.path(True)
        b.poll(1.2); assert len(b.notifications) == count+1
        b.notify_status = 0
        acquired = lock(b, h, sb, b'optional', 4); unlock(b, h, acquired)
        passed('client NOTSUPP completes the optional callback; foreground polling and explicit lock acquisition remain usable')

        for name, channel in ((b'one-operation', t4.channel_attrs4(0,4096,4096,0,1,4,[])),
                              (b'small-record', t4.channel_attrs4(0,128,128,0,16,4,[]))):
            limited = client(True, back=channel)
            sa, h = opened(a, root, name, True); sb, _ = opened(limited, root, name)
            held = lock(a, h, sa, b'holder'); lock(limited, h, sb, b'limited', 4, status=10010)
            unlock(a, h, held); limited.poll(1.4); assert not limited.notifications
            acquired = lock(limited, h, sb, b'limited', 4); unlock(limited, h, acquired)
        passed('two-operation callbacks respect negotiated operation and full RPC size limits; constrained clients can still poll for locks')

        doomed = client(True)
        sa, h = opened(a, root, b'expired-waiter', True); sb, _ = opened(doomed, root, b'expired-waiter')
        held = lock(a, h, sa, b'holder'); lock(doomed, h, sb, b'expired', 4, status=10010)
        print('Checking the real 60-second lease expiration while renewing the competing owner', flush=True)
        deadline = time.monotonic() + 63
        while time.monotonic() < deadline:
            expect(a, [])
            time.sleep(.25)
        unlock(a, h, held)
        deadline = time.monotonic() + 1.4
        while time.monotonic() < deadline:
            # A sessionless RPC drains callbacks without renewing expired state.
            assert doomed.compound([], False).status == 0
            time.sleep(.05)
        assert not doomed.notifications
        assert doomed.compound([]).status == 10052
        passed('expired client and OPEN state remove the queued hint; releasing the competing lock never notifies or revives the expired session')
        report = dict(status='passed', checks=checks, sanitizers=args.sanitizers)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report))
    finally:
        for c in clients: c.close()
        f.close()


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true'); run(p.parse_args())
