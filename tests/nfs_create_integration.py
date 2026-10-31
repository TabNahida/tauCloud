#!/usr/bin/env python3
"""NFSv4.1 exclusive creation, returned attributes and safe unchecked truncation."""
import argparse
import json
import traceback
from pathlib import Path
from pynfs_acceptance import fixture
from m7_integration import Client, op, t4, p4, t3

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();f,port=fixture(a.bin);clients=[];checks=[]
    def client():
        c=Client(port);clients.append(c);c.session();return c
    def call(c,ops,status=0):
        r=c.compound(ops);assert r.status==status,r;return r
    def attrs(size,mode):
        p=p4.NFS4Packer();p.pack_uhyper(size);p.pack_uint(mode)
        return t4.fattr4([16,2],p.get_buffer())
    def opening(c,root,name,how,access=3,deny=0,status=0):
        r=call(c,[op.putfh(root),op.open(0,access,deny,t4.open_owner4(c.cid,b'owner'),
                how,t4.open_claim4(0,file=name)),op.getfh()],status)
        if status:return
        return r.resarray[2].opopen.resok4,r.resarray[3].opgetfh.resok4.object
    def close(c,h,result):call(c,[op.putfh(h),op.close(0,result.stateid)])
    try:
        c=client();d=client();root=c.root()
        directory_attrs=t3.sattr3(t3.set_mode3(True,0o755),t3.set_uid3(True,1000),
            t3.set_gid3(True,1000),t3.set_size3(True,0),t3.set_atime(1),t3.set_mtime(1))
        result=c.v3('MKDIR',t3.MKDIR3args(t3.diropargs3(t3.nfs_fh3(root),b'zero-size-directory'),directory_attrs),9)
        assert result.status==0,result
        assert c.v3('GETATTR',t3.GETATTR3args(result.resok.obj.handle),1).status==0
        checks.append('NFSv3 MKDIR accepts zero size hints without attempting to truncate a directory')
        r=call(c,[op.putfh(root),op.getattr([0,0,1<<11])])
        val=r.resarray[-1].opgetattr.resok4.obj_attributes
        assert val.attrmask==[0,0,1<<11],val
        u=p4.NFS4Unpacker(val.attr_vals);assert u.unpack_bitmap4()==[16,0x410032];u.done()
        checks.append('required suppattr_exclcreat advertises actual writable creation attributes')
        how=t4.openflag4(1,t4.createhow4(3,ch_createboth=t4.creatverfattr(b'abcdefgh',attrs(32,0o600))))
        result,h=opening(c,root,b'exclusive',how);assert result.attrset==[16,2],result
        call(c,[op.putfh(h),op.write(result.stateid,0,2,b'keep')]);close(c,h,result)
        result,h=opening(c,root,b'exclusive',how);assert not result.attrset
        close(c,h,result)
        native=f.root/'nfsdata/exclusive';assert native.read_bytes()==b'keep'+b'\0'*28
        mismatch=t4.openflag4(1,t4.createhow4(3,ch_createboth=t4.creatverfattr(b'wrongver',attrs(0,0o700))))
        opening(c,root,b'exclusive',mismatch,status=17)
        bad=t4.openflag4(1,t4.createhow4(3,ch_createboth=t4.creatverfattr(b'abcdefgh',t4.fattr4([2],b'\0\0\0\1'))))
        opening(c,root,b'invalid-attribute',bad,status=22)
        assert not (f.root/'nfsdata/invalid-attribute').exists()
        checks.append('exclusive verifier retry preserves content; mismatched verifier and unsupported exclusive attributes reject without creation')
        ignored=t4.openflag4(1,t4.createhow4(0,attrs(5,0o700)))
        result,h=opening(c,root,b'exclusive',ignored);assert not result.attrset
        close(c,h,result);assert native.stat().st_size==32
        r=call(c,[op.putfh(h),op.getattr([0,2])]);assert r.resarray[-1].opgetattr.resok4.obj_attributes.attr_vals==b'\0\0\1\x80'
        held,_=opening(c,root,b'exclusive',t4.openflag4(0),access=1,deny=2)
        truncate=t4.openflag4(1,t4.createhow4(0,attrs(0,0o700)))
        opening(d,root,b'exclusive',truncate,status=10015)
        assert native.stat().st_size==32 and native.read_bytes().startswith(b'keep')
        close(c,h,held)
        result,h=opening(d,root,b'exclusive',truncate);assert result.attrset==[16]
        close(d,h,result);assert native.stat().st_size==0
        checks.append('UNCHECKED ignores nonzero size and mode on existing files; zero size truncates only after share reservations permit it')
        p=p4.NFS4Packer();p.pack_uint(0o750)
        r=call(c,[op.putfh(root),op.create(t4.createtype4(2),b'attr-directory',t4.fattr4([0,2],p.get_buffer()))])
        assert r.resarray[-1].opcreate.resok4.attrset==[0,2]
        checks.append('CREATE and OPEN return the attributes actually applied')
        report=dict(status='passed',checks=checks)
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
    except Exception:
        report=dict(status='failed',checks=checks,error=traceback.format_exc(),
            worker_logs={role:path.read_text()[-16384:] for role in ('native','nfs','file')
                         if (path:=f.state/'logs'/(role+'.jsonl')).exists()})
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2),flush=True)
        raise
    finally:
        for c in clients:c.close()
        f.close()
    return 0

if __name__=='__main__':raise SystemExit(main())
