#!/usr/bin/env python3
"""NFS attribute persistence, export aliases and native timestamp verification."""
import argparse
import time
import json
import os
from pathlib import Path
from pynfs_acceptance import fixture
from m7_integration import Client, op, t3, t4, p4
from native_allocation import native_allocation

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--sanitizers',action='store_true')
    args=parser.parse_args();f,port=fixture(args.bin,512 if args.sanitizers else 256);clients=[];checks=[]
    def connect():
        c=Client(port);clients.append(c);return c
    def getattr3(c,h):
        r=c.v3('GETATTR',t3.GETATTR3args(t3.nfs_fh3(h)),1)
        assert r.status==0,r
        return r.resok.obj_attributes
    def change(c,h):
        r=c.compound([op.putfh(h),op.getattr([1<<3])]);assert r.status==0,r
        return int.from_bytes(r.resarray[-1].opgetattr.resok4.obj_attributes.attr_vals,'big')
    try:
        c=connect();status,root=c.mount();assert status==0
        attrs=t3.sattr3(t3.set_mode3(True,0o640),t3.set_uid3(True,1000),t3.set_gid3(True,1000),
                       t3.set_size3(True,0),t3.set_atime(2,t3.nfstime3(1700000000,123456700)),
                       t3.set_mtime(2,t3.nfstime3(1700000001,987654300)))
        r=c.v3('CREATE',t3.CREATE3args(t3.diropargs3(t3.nfs_fh3(root),b'attributes'),t3.createhow3(1,attrs)),8)
        assert r.status==0,r;h=r.resok.obj.handle.data
        a=getattr3(c,h)
        assert (a.mode,a.uid,a.gid,a.size)==(0o640,1000,1000,0),a
        assert (a.atime.seconds,a.atime.nseconds)==(1700000000,123456700),a
        assert (a.mtime.seconds,a.mtime.nseconds)==(1700000001,987654300),a
        checks.append('v3 CREATE preserves mode, mapped ownership and explicit atime/mtime on native handles')
        f.api('shares',f.admin,dict(id='alias',space='nfsdata',exposures={'nfs':'rw'}))
        f.api('nfs-exports',f.admin,dict(id='alias',trust='loopback-auth-sys',anonymous='bob',
                                       uids={'1000':'alice'},gids={'1000':'unix'}))
        status,alias=c.mount(b'/alias');assert status==0
        r=c.v3('LOOKUP',t3.LOOKUP3args(t3.diropargs3(t3.nfs_fh3(alias),b'attributes')),3)
        assert r.status==0,r;alias_h=r.resok.object.data
        assert getattr3(c,alias_h).mode==0o640
        c.session();state,_=c.open(root,b'attributes')
        initial_change=change(c,h)
        p=p4.NFS4Packer();p.pack_uint(0o600);p.pack_uint(1);p.pack_hyper(1700000002);p.pack_uint(123456700)
        value=t4.fattr4([0,(1<<1)|(1<<22)],p.get_buffer())
        r=c.compound([op.putfh(h),op.setattr(state,value)])
        assert r.status==0,r
        a=getattr3(c,alias_h)
        assert a.mode==0o600 and (a.mtime.seconds,a.mtime.nseconds)==(1700000002,123456700),a
        assert change(c,h)>initial_change and change(c,h)==change(c,alias_h)
        r=c.compound([op.putfh(h),op.getattr([0,1<<22])]);assert r.status==22,r
        assert (a.ctime.seconds,a.ctime.nseconds)!=(a.mtime.seconds,a.mtime.nseconds),a
        previous_ctime=(a.ctime.seconds,a.ctime.nseconds);time.sleep(0.02)
        p=p4.NFS4Packer();p.pack_uint(0o600)
        r=c.compound([op.putfh(h),op.setattr(state,t4.fattr4([0,1<<1],p.get_buffer()))]);assert r.status==0,r
        a=getattr3(c,alias_h)
        assert (a.ctime.seconds,a.ctime.nseconds)>previous_ctime,a
        assert (a.mtime.seconds,a.mtime.nseconds)==(1700000002,123456700),a
        checks.append('v3 ctime differs from preserved mtime and advances for mode-only metadata changes across export aliases')
        checks.append('v4 SETATTR updates aliases consistently; GETATTR rejects write-only time attributes')
        r=c.compound([op.putfh(h),op.close(0,state)]);assert r.status==0,r
        native=f.root/'nfsdata/attributes';times=native.stat()
        before_change=change(c,h);native.write_bytes(b'a');os.utime(native,ns=(times.st_atime_ns,times.st_mtime_ns))
        saved_change=change(c,h);assert saved_change>before_change
        # Equal size and restored mtime still must invalidate a data cache.
        native.write_bytes(b'b');os.utime(native,ns=(times.st_atime_ns,times.st_mtime_ns))
        assert change(c,h)>saved_change;saved_change=change(c,h)
        r=c.v3('READ',t3.READ3args(t3.nfs_fh3(h),0,1),6);assert r.status==0 and r.resok.data==b'b'
        assert change(c,h)==saved_change==change(c,alias_h)
        parent_before=change(c,root)
        r=c.compound([op.putfh(root),op.create(t4.createtype4(2),b'cache-change-dir',t4.fattr4([],b''))]);assert r.status==0,r
        ci=r.resarray[-1].opcreate.resok4.cinfo
        assert not ci.atomic and ci.before==parent_before and ci.after>ci.before and change(c,root)==ci.after
        parent_before=ci.after
        r=c.compound([op.putfh(root),op.remove(b'cache-change-dir')]);assert r.status==0,r
        ci=r.resarray[-1].opremove.resok4.cinfo
        assert not ci.atomic and ci.before==parent_before and ci.after>ci.before and change(c,root)==ci.after
        checks.append('durable change counters detect equal-size writes with restored mtime, share alias state and return real namespace change_info; reads do not advance them')
        r=c.v3('CREATE',t3.CREATE3args(t3.diropargs3(t3.nfs_fh3(root),b'allocation'),t3.createhow3(1,attrs)),8)
        assert r.status==0,r;allocated_h=r.resok.obj.handle.data
        allocation_path=f.root/'nfsdata/allocation'
        def check_allocation(expected_size):
            native_bytes=native_allocation(allocation_path)
            attributes=getattr3(c,allocated_h)
            assert (attributes.size,attributes.used)==(expected_size,native_bytes),(attributes,native_bytes)
            r=c.compound([op.putfh(allocated_h),op.getattr([1<<4,1<<13])]);assert r.status==0,r
            values=r.resarray[-1].opgetattr.resok4.obj_attributes.attr_vals
            assert len(values)==16 and int.from_bytes(values[:8],'big')==expected_size
            assert int.from_bytes(values[8:],'big')==native_bytes,(values,native_bytes)
        check_allocation(0)
        r=c.v3('WRITE',t3.WRITE3args(t3.nfs_fh3(allocated_h),0,3,2,b'abc'),7);assert r.status==0,r
        check_allocation(3)
        r=c.v3('WRITE',t3.WRITE3args(t3.nfs_fh3(allocated_h),1024*1024,1,2,b'z'),7);assert r.status==0,r
        check_allocation(1024*1024+1)
        if os.name!='nt':assert native_allocation(allocation_path)<1024*1024
        resized=t3.sattr3(t3.set_mode3(False),t3.set_uid3(False),t3.set_gid3(False),
                         t3.set_size3(True,0),t3.set_atime(0),t3.set_mtime(0))
        r=c.v3('SETATTR',t3.SETATTR3args(t3.nfs_fh3(allocated_h),resized,t3.sattrguard3(False)),2)
        assert r.status==0,r;check_allocation(0)
        checks.append('v3 used and v4 space_used match independent native allocation for empty, small, sparse/extended and truncated files, separately from logical size')
        for i in range(24): (f.root/'nfsdata'/('entry-%02d'%i)).write_bytes(b'x')
        cookie=0;verifier=b'\0'*8;names=[];pages=0
        r=c.compound([op.putfh(root),op.get_dir_delegation(False,[],t4.nfstime4(0,0),t4.nfstime4(0,0),[],[])])
        assert r.status==0 and r.resarray[-1].opget_dir_delegation.gddr_res_non_fatal4.gddrnf_status==1,r
        while True:
            r=c.compound([op.putfh(root),op.readdir(cookie,verifier,512,512,[2])]);assert r.status==0,r
            page=r.resarray[-1].opreaddir.resok4;verifier=page.cookieverf;entries=page.reply.entries
            pages+=1
            while entries:
                entry=entries[0];assert entry.cookie>=3 and entry.cookie>cookie
                cookie=entry.cookie;names.append(entry.name);entries=entry.nextentry
            if page.reply.eof:break
            assert pages<16 and cookie>0
        assert pages>1 and len(names)==len(set(names)) and all(('entry-%02d'%i).encode() in names for i in range(24))
        for reserved in (1,2):
            r=c.compound([op.putfh(root),op.readdir(reserved,verifier,512,512,[2])]);assert r.status==10003,r
        checks.append('paged v4 READDIR skips reserved cookies 1/2 and resumes without duplicate or missing entries')
        for client in clients:client.close()
        f.stop();f.start();c=connect()
        c.session();assert change(c,h)==saved_change==change(c,alias_h)
        a=getattr3(c,alias_h)
        assert (a.mode,a.uid,a.gid)==(0o600,1000,1000),a
        assert (a.mtime.seconds,a.mtime.nseconds)==(1700000002,123456700),a
        checks.append('mode/ownership and exact timestamps survive server restart through stable alias handles')
        report=dict(status='passed',checks=checks,sanitizers=args.sanitizers)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
    finally:
        for client in clients:client.close()
        f.close()

if __name__=='__main__':main()
