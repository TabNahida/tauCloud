#!/usr/bin/env python3
"""Real Kerberos NFSv4.1 machine state protection, binding and state cleanup."""
import argparse
import json
from pathlib import Path
import traceback
import uuid

from nfs_gss_integration import Kdc, GssClient, REALM, SERVICE
from pynfs_acceptance import fixture
from m7_integration import Client, op, t4


def bitmap(*operations):
    result = [0, 0]
    for operation in operations: result[operation // 32] |= 1 << (operation % 32)
    return result


ENFORCE = bitmap(7, 40, 41, 42, 43, 44, 57)
ALLOW = bitmap(4, 14, 21, 45)
CHANNEL = t4.channel_attrs4(0, 262144, 262144, 262144, 16, 4, [])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--krb5-root', type=Path); p.add_argument('--sanitizers', action='store_true')
    a = p.parse_args(); f = kdc = None; clients = []; report = dict(status='failed', checks=[])
    def passed(message): report['checks'].append(message); print('PASS '+message, flush=True)
    def expect(c, operations, status=0, session=True, seq=None):
        r = c.compound(operations, session, seq=seq)
        assert r.status == status, r
        return r
    def client(credentials, service=3):
        c = GssClient(port, credentials, service); clients.append(c); return c
    def exchange(c, owner, flags=0, enforce=ENFORCE, allow=ALLOW, protection=1, status=0):
        state = t4.state_protect4_a(protection, t4.state_protect_ops4(enforce, allow) if protection else None)
        r = expect(c, [op.exchange_id(t4.client_owner4(b'12345678', owner), flags, state, [])], status, False)
        return r.resarray[0].opexchange_id.eir_resok4 if not status else r
    def create_session(c, cid, sequence=1, status=0):
        r = expect(c, [op.create_session(cid, sequence, 0, CHANNEL, CHANNEL, 0, [])], status, False)
        if not status:
            c.cid = cid; c.sid = r.resarray[0].opcreate_session.csr_resok4.csr_sessionid; c.seq = 0
        return r
    def switch(c, credentials):
        c.credentials = credentials; c.contexts.clear()
    def bind(c, source, status=0):
        c.cid, c.sid = source.cid, source.sid
        return expect(c, [op.bind_conn_to_session(c.sid, 1, False)], status, False)
    try:
        kdc = Kdc(a.krb5_root); f, port = fixture(a.bin, 1024 if a.sanitizers else 256)
        f.stop(); cfg = json.loads((f.state/'config.json').read_text())
        cfg.update(nfs_gss_service=SERVICE, nfs_gss_keytab=str(kdc.keytab))
        (f.state/'config.json').write_text(json.dumps(cfg)); f.start()
        f.api('memberships', f.admin, dict(username='bob', group='unix'))
        f.api('grants', f.admin, dict(space='nfsdata', subject_type='user', subject='bob', rights='r'))
        export = dict(id='nfs', update=True, trust='rpcsec-gss', anonymous='bob',
            uids={'1000':'alice', '1001':'bob'}, gids={'1000':'unix'},
            principals={'alice@'+REALM:dict(uid=1000,gid=1000), 'bob@'+REALM:dict(uid=1001,gid=1000)},
            security=['krb5', 'krb5i', 'krb5p'])
        f.api('nfs-exports', f.admin, export)
        machine = kdc.credentials('unmapped'); alice = kdc.credentials(); bob = kdc.credentials('bob')
        for service in (2, 3):
            c = client(machine, service); owner = uuid.uuid4().hex.encode()
            result = exchange(c, owner, allow=bitmap(4, 14, 21, 25, 45))
            protection = result.eir_state_protect
            assert result.eir_flags & 0x100  # BIND_PRINC_STATEID, with negotiated cleanup exceptions.
            assert protection.spr_how == 1 and protection.spr_mach_ops.spo_must_enforce == ENFORCE
            assert protection.spr_mach_ops.spo_must_allow == ALLOW
            cid = result.eir_clientid
            other = client(bob, service); weak = client(machine, 1)
            create_session(other, cid, status=10082); create_session(weak, cid, status=10082)
            created = create_session(c, cid)
            expect(c, [op.reclaim_complete(False)])
            repeated = create_session(c, cid)
            assert repeated.resarray[0].opcreate_session.csr_resok4.csr_sessionid == created.resarray[0].opcreate_session.csr_resok4.csr_sessionid
            c.seq = 1
            create_session(other, cid, status=10082)  # Replay never bypasses credential validation.
            passed(f'krb5 service {service}: negotiates exact enforced operations and cleanup-only allow set; confirmation and CREATE_SESSION replay require the machine')

            again = exchange(c, owner, enforce=[], allow=[])
            assert again.eir_clientid == cid and again.eir_state_protect.spr_mach_ops.spo_must_enforce == ENFORCE
            exchange(other, owner, status=10017); exchange(weak, owner, status=1)
            exchange(c, owner, flags=0x40000000, protection=0, status=10027)
            exchange(other, owner, flags=0x40000000, status=1)
            passed(f'krb5 service {service}: confirmed EXCHANGE_ID retains its policy and rejects credential or protection downgrade')

            newcomer = client(machine, service); newcomer.cid, newcomer.sid = cid, c.sid
            expect(newcomer, [], 10055, seq=c.seq+1)
            bind(other, c, 10082); bind(weak, c, 10082); bind(newcomer, c)
            expect(newcomer, [], seq=c.seq+1); c.seq = newcomer.seq
            switch(other, machine); bind(other, c); switch(other, bob)
            other.seq = c.seq
            expect(other, [op.backchannel_ctl(0, [])], 10082); c.seq = other.seq
            expect(other, [op.delegpurge(cid)], 10082); c.seq = other.seq
            expect(c, [op.delegpurge(0)])
            expect(other, [op.destroy_session(c.sid)], 10082, False)
            expect(other, [op.destroy_clientid(cid)], 10082, False)
            c.service = 1; expect(c, [op.backchannel_ctl(0, [])], 10082)
            expect(c, [op.delegpurge(cid)], 10082)
            c.service = service
            expect(c, [])
            passed(f'krb5 service {service}: unbound SEQUENCE cannot attach a connection; authenticated bind works; user session maintenance is denied without damaging the live session')

            # A mapped user may use the protected session after the machine has
            # bound this transport. Machine credentials themselves have no export mapping.
            user = client(machine, service); bind(user, c); switch(user, alice); user.seq = c.seq
            root = user.root(); state, handle = user.open(root, b'machine-cleanup-'+bytes([48+service]), True)
            locker = t4.locker4(True, open_owner=t4.open_to_lock_owner4(0, state, 0, t4.lock_owner4(cid,b'user-lock')))
            r = expect(user, [op.putfh(handle), op.lock(2, False, 0, 16, locker)])
            lockstate = r.resarray[-1].oplock.resok4.lock_stateid; c.seq = user.seq
            other.seq = c.seq
            expect(other, [op.putfh(handle), op.close(0, state)], 10082)
            expect(other, [op.free_stateid(lockstate)], 10082)
            c.seq = other.seq
            # Revoking Alice's export mapping must not strand her client state.
            revoked = dict(export, principals={'bob@'+REALM:dict(uid=1001,gid=1000)})
            f.api('nfs-exports', f.admin, revoked)
            expect(c, [op.free_stateid(lockstate)], 10037)
            expect(c, [op.putfh(handle), op.close(0, state)], 10037)
            foreign = client(machine, service)
            foreign_id = exchange(foreign, uuid.uuid4().hex.encode()).eir_clientid
            create_session(foreign, foreign_id)
            attempted = foreign.compound([op.putfh(handle), op.close(0, state)])
            assert attempted.status != 0, attempted
            expect(foreign, [op.destroy_session(foreign.sid)], session=False)
            expect(foreign, [op.destroy_clientid(foreign_id)], session=False)
            r = expect(c, [op.putfh(handle), op.open_downgrade(state, 0, 1, 0)])
            state = r.resarray[-1].opopen_downgrade.open_stateid
            r = expect(c, [op.putfh(handle), op.locku(2, 0, lockstate, 0, 16)])
            lockstate = r.resarray[-1].oplocku.lock_stateid
            expect(c, [op.free_stateid(lockstate)])
            denied_read = c.compound([op.putfh(handle), op.read(state, 0, 1)])
            assert denied_read.status != 0, denied_read
            update = exchange(c, owner, flags=0x40000000, enforce=[], allow=[])
            assert update.eir_state_protect.spr_mach_ops.spo_must_enforce == ENFORCE
            assert update.eir_state_protect.spr_mach_ops.spo_must_allow == ALLOW
            expect(c, [op.putfh(handle), op.close(0, state)])
            f.api('nfs-exports', f.admin, export)
            passed(f'krb5 service {service}: an unmapped machine releases user locks/open state after mapping revocation, but cannot read user data')
            passed(f'krb5 service {service}: cleanup cannot cross client IDs, confirmed protection lists are immutable, and write locks remain releasable after OPEN_DOWNGRADE')

            strict = client(machine, service)
            strict_id = exchange(strict, uuid.uuid4().hex.encode(), enforce=bitmap(7, 40, 41, 42, 43, 44, 53, 57)).eir_clientid
            create_session(strict, strict_id); switch(strict, bob)
            expect(strict, [], 10082, seq=1)
            switch(strict, machine); expect(strict, [], seq=1)
            expect(strict, [op.destroy_session(strict.sid)], session=False)
            expect(strict, [op.destroy_clientid(strict_id)], session=False)
            passed(f'krb5 service {service}: negotiated SEQUENCE protection rejects a user before slot consumption')

            # Replay with authentication-only GSS must not recover a protected
            # cached success. The failed replay leaves the slot usable.
            result = expect(c, [op.backchannel_ctl(0, [])]); replay_seq = c.seq
            c.service = 1
            expect(c, [op.backchannel_ctl(0, [])], 10076, seq=replay_seq)
            c.service = 3 if service == 2 else 2
            replay = expect(c, [op.backchannel_ctl(0, [])], seq=replay_seq)
            assert replay.status == result.status
            expect(c, [op.destroy_session(c.sid)], session=False)
            expect(c, [op.destroy_clientid(cid)], session=False)
            passed(f'krb5 service {service}: cached success cannot be downgraded to authentication-only; integrity/privacy replay and authorized destruction succeed')
            for finished in (c, other, weak, newcomer, user, foreign, strict): finished.close()

        limited = client(machine)
        limited_id = exchange(limited, uuid.uuid4().hex.encode(), allow=[]).eir_clientid
        create_session(limited, limited_id); expect(limited, [op.reclaim_complete(False)])
        switch(limited, alice)
        root = limited.root(); state, handle = limited.open(root, b'no-machine-cleanup', True)
        switch(limited, machine)
        denied = limited.compound([op.putfh(handle), op.close(0, state)])
        assert denied.status != 0, denied
        switch(limited, alice); expect(limited, [op.putfh(handle), op.close(0, state)])
        switch(limited, machine)
        expect(limited, [op.destroy_session(limited.sid)], session=False)
        expect(limited, [op.destroy_clientid(limited_id)], session=False)
        limited.close()
        passed('machine state cleanup requires an agreed allow bit; ordinary owner cleanup remains usable')

        plain = Client(port); clients.append(plain)
        exchange(plain, uuid.uuid4().hex.encode(), status=1)
        weak = client(machine, 1); exchange(weak, uuid.uuid4().hex.encode(), status=1)
        # SP4_NONE continues to support ordinary AUTH_SYS sessions and implicit binding.
        plain.session(); second = Client(port); clients.append(second); second.sid = plain.sid
        expect(second, [], seq=plain.seq+1)
        passed('AUTH_SYS and authentication-only GSS cannot negotiate machine protection; SP4_NONE implicit binding remains available')
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
        a.output.parent.mkdir(parents=True, exist_ok=True); a.output.write_text(json.dumps(report, indent=2)+'\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(main())
