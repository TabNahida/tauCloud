#!/usr/bin/env python3
"""Adversarial NFS state, share reservations and durable byte-lock recovery."""
import argparse
import json
from pathlib import Path
from pynfs_acceptance import fixture
from m7_integration import Client, op, t4, t3

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args(); f,port=fixture(args.bin); clients=[];checks=[]
    def connect(owner=None,reclaim=False):
        c=Client(port);clients.append(c);c.session(owner,reclaim=reclaim);return c
    def expect(c,operations,status=0):
        r=c.compound(operations);assert r.status==status,r;return r
    def lock(c,h,state,owner,start,length,reclaim=False):
        locker=t4.locker4(True,open_owner=t4.open_to_lock_owner4(0,state,0,t4.lock_owner4(0,owner)))
        return expect(c,[op.putfh(h),op.lock(2,reclaim,start,length,locker)]).resarray[-1].oplock.resok4.lock_stateid
    try:
        a=connect();b=connect();root=a.root()
        state,h=a.open(root,b'lock-file',True)
        f.api('memberships',f.admin,dict(username='bob',group='unix'))
        f.api('grants',f.admin,dict(space='nfsdata',subject_type='user',subject='bob',rights='rw'))
        f.api('nfs-exports',f.admin,dict(id='nfs',trust='loopback-auth-sys',anonymous='bob',update=True,
                                       uids={'1000':'alice','1001':'bob'},gids={'1000':'unix'}))
        other=Client(port,uid=1001);clients.append(other);other.sid=a.sid;other.seq=a.seq
        stolen=other.compound([op.putfh(root),op.open(0,3,0,t4.open_owner4(a.cid,b'writer'),
                       t4.openflag4(1,t4.createhow4(1,t4.fattr4([],b''))),t4.open_claim4(0,file=b'lock-file')),
                       op.getfh()],seq=a.seq)
        assert stolen.status==10076,stolen
        expect(other,[op.putfh(h),op.getattr([16])])
        expect(other,[op.putfh(h),op.read(state,0,1)],10025)
        a.seq=other.seq
        checks.append('one kernel-style session accepts multiple mapped users without sharing their open authority')
        bstate,bh=b.open(root,b'lock-file',owner=b'other-open')
        expect(a,[op.putfh(h),op.write(state,0,2,b'_'*80)])
        locked=lock(a,h,state,b'lock-owner',10,20)
        denied=expect(b,[op.putfh(h),op.lockt(2,12,1,t4.lock_owner4(0,b'other-lock'))],10010)
        assert denied.resarray[-1].oplockt.denied.owner.owner==b'lock-owner',denied
        expect(b,[op.putfh(h),op.write(bstate,12,2,b'x')],10012)
        expect(b,[op.putfh(h),op.write(bstate,40,2,b'x')])
        expect(a,[op.putfh(h),op.close(0,state)],10037)
        checks.append('exclusive lock conflicts, denied owner details, disjoint writes and CLOSE with held locks')
        unlocked=expect(a,[op.putfh(h),op.locku(2,0,locked,15,5)]).resarray[-1].oplocku.lock_stateid
        expect(b,[op.putfh(h),op.write(bstate,17,2,b'x')])
        expect(b,[op.putfh(h),op.write(bstate,12,2,b'x')],10012)
        checks.append('partial unlock splits ranges and preserves neighboring conflicts')
        owner=a.owner
        for c in clients:c.close()
        f.stop();f.start();a=connect(owner,reclaim=True)
        state,h=a.open(h,b'',claim=1)
        locked=lock(a,h,state,b'lock-owner',10,5,True)
        locked=lock(a,h,state,b'lock-owner',20,10,True)
        expect(a,[op.reclaim_complete(False)])
        expect(a,[op.putfh(h),op.write(locked,10,2,b'recovered')])
        expect(a,[op.putfh(h),op.locku(2,0,locked,0,2**64-1)])
        expect(a,[op.putfh(h),op.close(0,state)])
        checks.append('process restart persists split lock ranges; matching client reclaims OPEN and locks before RECLAIM_COMPLETE')
        # A new disposable server state avoids waiting for the real recovery grace.
        report=dict(status='passed',checks=checks)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
    finally:
        for c in clients:c.close()
        f.close()

if __name__=='__main__':main()
