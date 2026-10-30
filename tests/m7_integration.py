#!/usr/bin/env python3
"""NFS experimental profile, using pinned linux-nfs/pynfs generated wire codecs.
This is interoperability of the selected operations, not the full pynfs conformance suite.
"""
import argparse, hashlib, json, os, socket, sqlite3, struct, sys, time, uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/nfs-client'))
from xdrdef import nfs4_type as t4, nfs4_pack as p4, nfs3_type as t3, nfs3_pack as p3
from nfs_ops import NFS4ops
from m3_integration import Fixture as Base
from m1_integration import wait
import xdrlib3 as xdrlib
op=NFS4ops()

class Client:
    def __init__(self,port,uid=1000,gid=1000,groups=()):
        self.port,self.uid,self.gid,self.groups=port,uid,gid,groups
        self.sock=socket.create_connection(('127.0.0.1',port),timeout=10)
        self.xid=int.from_bytes(os.urandom(4),'big'); self.seq=0
    def close(self):self.sock.close()
    def packet(self,program,version,proc,body,xid=None):
        p=xdrlib.Packer();p.pack_uint(self.xid if xid is None else xid)
        for x in (0,2,program,version,proc):p.pack_uint(x)
        a=xdrlib.Packer();a.pack_uint(0);a.pack_string(b'pynfs-codec');a.pack_uint(self.uid);a.pack_uint(self.gid);a.pack_array(self.groups,a.pack_uint)
        p.pack_uint(1);p.pack_bytes(a.get_buffer());p.pack_uint(0);p.pack_bytes(b'')
        self.xid=(self.xid+1)&0xffffffff
        return p.get_buffer()+body
    def exchange(self,packet,fragment=False):
        if fragment:
            cut=len(packet)//2
            self.sock.sendall(struct.pack('>I',cut)+packet[:cut]+struct.pack('>I',0x80000000|len(packet[cut:]))+packet[cut:])
        else:self.sock.sendall(struct.pack('>I',0x80000000|len(packet))+packet)
        def read(n):
            b=b''
            while len(b)<n:
                v=self.sock.recv(n-len(b));assert v,'connection closed';b+=v
            return b
        data=b''
        while True:
            marker=struct.unpack('>I',read(4))[0];data+=read(marker&0x7fffffff)
            if marker>>31:break
        u=xdrlib.Unpacker(data);assert u.unpack_uint()==struct.unpack('>I',packet[:4])[0]
        assert u.unpack_uint()==1;assert u.unpack_uint()==0
        assert u.unpack_uint()==0;assert u.unpack_bytes()==b''
        accepted=u.unpack_uint();assert accepted==0,('RPC status',accepted,data.hex())
        return data[u.get_position():]
    def mount(self,name=b'/nfs'):
        p=xdrlib.Packer();p.pack_string(name)
        u=xdrlib.Unpacker(self.exchange(self.packet(100005,3,1,p.get_buffer()),True));status=u.unpack_uint()
        if status:return status,None
        h=u.unpack_bytes();assert u.unpack_array(u.unpack_uint)==[1];u.done();return 0,h
    def v3(self,name,args,proc,packet_only=False):
        p=p3.NFS3Packer();getattr(p,'pack_'+name+'3args')(args)
        packet=self.packet(100003,3,proc,p.get_buffer())
        if packet_only:return packet
        return self.decode3(name,self.exchange(packet))
    def decode3(self,name,body):
        u=p3.NFS3Unpacker(body);v=getattr(u,'unpack_'+name+'3res')();u.done();return v
    def compound(self,ops,session=True,packet_only=False,seq=None):
        if session:
            self.seq=self.seq+1 if seq is None else seq
            ops=[op.sequence(self.sid,self.seq,0,0,True)]+ops
        p=p4.NFS4Packer();p.pack_COMPOUND4args(t4.COMPOUND4args(b'tc7',1,ops))
        packet=self.packet(100003,4,1,p.get_buffer())
        if packet_only:return packet
        return self.decode4(self.exchange(packet))
    def decode4(self,body):
        u=p4.NFS4Unpacker(body);v=u.unpack_COMPOUND4res();u.done();return v
    def session(self,owner=None,reclaim=False):
        self.owner=owner or uuid.uuid4().hex.encode()
        r=self.compound([op.exchange_id(t4.client_owner4(b'12345678',self.owner),0,t4.state_protect4_a(0),[])],False)
        assert r.status==0,r;self.cid=r.resarray[0].opexchange_id.eir_resok4.eir_clientid
        channel=t4.channel_attrs4(0,262144,262144,262144,16,4,[])
        r=self.compound([op.create_session(self.cid,1,0,channel,channel,0,[])],False)
        assert r.status==0,r;self.sid=r.resarray[0].opcreate_session.csr_resok4.csr_sessionid
        if not reclaim:
            r=self.compound([op.reclaim_complete(False)]);assert r.status==0,r
    def root(self):
        r=self.compound([op.putrootfh(),op.lookup(b'nfs'),op.getfh()]);assert r.status==0,r
        return r.resarray[-1].opgetfh.resok4.object
    def open(self,root,name,create=False,claim=0,owner=b'writer'):
        how=t4.openflag4(1,t4.createhow4(1,t4.fattr4([],b''))) if create else t4.openflag4(0)
        c=t4.open_claim4(claim,file=name if claim==0 else None,delegate_type=0 if claim==1 else None)
        r=self.compound([op.putfh(root),op.open(0,3,0,t4.open_owner4(self.cid,owner),how,c),op.getfh()])
        assert r.status==0,r
        return r.resarray[2].opopen.resok4.stateid,r.resarray[3].opgetfh.resok4.object

def run(args):
    checks=[];clients=[];f=Base(args.bin,512 if args.sanitizers else 256)
    def client(**kw):
        c=Client(port,**kw);clients.append(c);return c
    try:
        f.stop()
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        config=json.loads((f.state/'config.json').read_text());config['nfs_port']=port;(f.state/'config.json').write_text(json.dumps(config))
        f.start()
        f.api('spaces',f.admin,dict(id='nfsdata',root='data',path='nfsdata',owner='alice',quota=2*1024**3))
        f.api('shares',f.admin,dict(id='nfs',space='nfsdata',exposures={'nfs':'rw'}))
        f.api('groups',f.admin,dict(name='unix'))
        f.api('memberships',f.admin,dict(username='alice',group='unix'))
        export=dict(id='nfs',trust='loopback-auth-sys',anonymous='bob',uids={'1000':'alice'},gids={'1000':'unix'})
        f.api('nfs-exports',f.admin,export)
        c=client();status,root=c.mount();assert status==0,(status,root);assert len(root)==50
        checks.append('TCP record fragmentation and MOUNT v3 with independent XDR codecs')
        for kwargs in ({'uid':1234},{'uid':0},{'gid':1234},{'groups':[1234]}):
            denied=client(**kwargs);assert denied.mount()[0]==13;denied.close()
        checks.append('unknown UID/GID/groups rejected; root squashed to explicitly unprivileged subject')
        f.api('grants',f.admin,dict(space='nfsdata',subject_type='user',subject='bob',rights='r'))
        squashed=client(uid=0,gid=0,groups=[4294967295]);assert squashed.mount()[0]==0
        assert squashed.v3('GETATTR',t3.GETATTR3args(t3.nfs_fh3(root)),1).status==0
        assert squashed.v3('WRITE',t3.WRITE3args(t3.nfs_fh3(root),0,1,2,b'x'),7).status==13
        f.api('grants',f.admin,dict(space='nfsdata',subject_type='user',subject='bob',rights=''))
        assert squashed.mount()[0]==13;squashed.close()
        checks.append('root squash uses anonymous read rights, strips privileged groups and rejects writes/revoked rights')
        for program,expected in ((100003,port),(100021,0)):
            p=xdrlib.Packer()
            for value in (program,3,6,0):p.pack_uint(value)
            u=xdrlib.Unpacker(c.exchange(c.packet(100000,2,3,p.get_buffer())));assert u.unpack_uint()==expected;u.done()
        checks.append('read-only TCP portmapper advertises NFS and does not advertise unsupported NLM')

        attr=t3.sattr3(t3.set_mode3(False),t3.set_uid3(False),t3.set_gid3(False),t3.set_size3(False),t3.set_atime(0),t3.set_mtime(0))
        create=t3.CREATE3args(t3.diropargs3(t3.nfs_fh3(root),b'roundtrip'),t3.createhow3(1,attr))
        r=c.v3('CREATE',create,8);assert r.status==0,r;handle=r.resok.obj.handle.data
        data=bytes(range(256))*256
        packet=c.v3('WRITE',t3.WRITE3args(t3.nfs_fh3(handle),0,len(data),0,data),7,True)
        first=c.exchange(packet);r=c.decode3('WRITE',first);assert r.status==0 and r.resok.committed==2 and r.resok.count==len(data),r
        assert c.exchange(packet)==first
        malformed=c.v3('WRITE',t3.WRITE3args(t3.nfs_fh3(handle),0,3,2,b'bad'),7,True)+b'x'
        try:c.exchange(malformed);raise RuntimeError('trailing XDR accepted')
        except AssertionError as e:assert e.args[0][0]=='RPC status' and e.args[0][1]==4,e
        checks.append('trailing XDR rejected before WRITE; previously persisted bytes remain intact')
        r=c.v3('READ',t3.READ3args(t3.nfs_fh3(handle),0,65536),6);assert r.status==0 and r.resok.data==data and r.resok.eof,r
        r=c.v3('COMMIT',t3.COMMIT3args(t3.nfs_fh3(handle),0,0),21);assert r.status==0,r;oldverf=r.resok.verf
        checks.append('v3 guarded CREATE, 64 KiB UNSTABLE upgraded to FILE_SYNC, READ, COMMIT, exact duplicate WRITE')
        bad=bytearray(handle);bad[-1]^=1
        assert c.v3('GETATTR',t3.GETATTR3args(t3.nfs_fh3(bytes(bad))),1).status==70
        (f.root/'nfsdata/roundtrip').rename(f.root/'nfsdata/moved')
        assert c.v3('READ',t3.READ3args(t3.nfs_fh3(handle),0,65536),6).resok.data==data
        c.close();f.stop();f.start();c=client()
        assert c.v3('READ',t3.READ3args(t3.nfs_fh3(handle),0,65536),6).resok.data==data
        assert c.exchange(packet)==first
        assert c.v3('COMMIT',t3.COMMIT3args(t3.nfs_fh3(handle),0,0),21).resok.verf!=oldverf
        checks.append('MAC tamper rejected; file handle survives external rename and all-service restart; durable v3 replay and new write verifier')
        (f.root/'nfsdata/moved').unlink();(f.root/'nfsdata/moved').write_bytes(b'replacement')
        assert c.v3('GETATTR',t3.GETATTR3args(t3.nfs_fh3(handle)),1).status==70
        checks.append('deleted/recreated path cannot revive an old file handle')
        made=c.v3('MKDIR',t3.MKDIR3args(t3.diropargs3(t3.nfs_fh3(root),b'dir'),attr),9);assert made.status==0,made
        assert c.v3('GETATTR',t3.GETATTR3args(t3.nfs_fh3(root)),1).status==0,'root stale after mkdir'
        assert c.v3('GETATTR',t3.GETATTR3args(made.resok.obj.handle),1).status==0,'directory stale after mkdir'
        r=c.v3('RENAME',t3.RENAME3args(t3.diropargs3(t3.nfs_fh3(root),b'moved'),t3.diropargs3(made.resok.obj.handle,b'child')),14);assert r.status==0,r
        listing=c.v3('READDIRPLUS',t3.READDIRPLUS3args(made.resok.obj.handle,0,b'\0'*8,4096,65536),17)
        assert listing.status==0 and listing.resok.reply.entries[0].name==b'child',listing
        assert c.v3('REMOVE',t3.REMOVE3args(t3.diropargs3(t3.nfs_fh3(root),b'dir')),12).status==21
        assert c.v3('REMOVE',t3.REMOVE3args(t3.diropargs3(made.resok.obj.handle,b'child')),12).status==0
        assert c.v3('RMDIR',t3.RMDIR3args(t3.diropargs3(t3.nfs_fh3(root),b'dir')),13).status==0
        checks.append('v3 MKDIR, cross-directory RENAME, READDIRPLUS, REMOVE/RMDIR type separation')

        v=client();v.session();root4=v.root();state,h=v.open(root4,b'v4',True)
        payload=b'nfs4.1-stateful-data'
        packet4=v.compound([op.putfh(h),op.write(state,0,0,payload)],packet_only=True)
        reply=v.exchange(packet4);r=v.decode4(reply);assert r.status==0,r;assert r.resarray[-1].opwrite.resok4.committed==2
        assert v.exchange(packet4)==reply
        r=v.compound([op.putfh(h),op.read(state,0,4096)]);assert r.status==0 and r.resarray[-1].opread.resok4.data==payload,r
        checks.append('pynfs v4.1 EXCHANGE_ID/CREATE_SESSION/SEQUENCE, guarded OPEN, WRITE/READ, exact slot replay')
        seq=v.seq
        wrong=v.compound([op.putfh(h),op.read(state,1,4096)],seq=seq);assert wrong.status==10076,wrong
        # SET-only time attributes must not be requested by GETATTR.
        r=v.compound([op.putfh(h),op.getattr([0xffffffff,0xffffffff & ~((1<<16)|(1<<22))])]);assert r.status==0,r
        stranger=client();stranger.session();r=stranger.compound([op.putfh(h),op.read(state,0,4096)]);assert r.status==10025,r
        checks.append('false slot replay and foreign stateid rejected; GETATTR subset independently decoded')
        oldowner=v.owner
        v.close();stranger.close();f.stop();f.start();v=client();v.session(oldowner,reclaim=True)
        r=v.compound([op.putfh(h),op.read(state,0,4096)]);assert r.status==10025,r
        state,h=v.open(h,b'',claim=1)
        r=v.compound([op.putfh(h),op.read(state,0,4096)]);assert r.status==0 and r.resarray[-1].opread.resok4.data==payload,r
        r=v.compound([op.putfh(h),op.close(0,state)]);assert r.status==0,r
        checks.append('old sessions/stateids invalidated on reboot; persisted owner can reclaim OPEN during grace; CLOSE releases recovery record')
        denied=client();denied.session(reclaim=True);r=denied.compound([op.putfh(h),op.open(0,3,0,t4.open_owner4(denied.cid,b'writer'),t4.openflag4(0),t4.open_claim4(1,delegate_type=0))]);assert r.status==10034,r
        checks.append('unrelated client cannot reclaim another owner after restart')
        f.api('nfs-exports',f.admin,dict(export,update=True,enabled=False))
        assert client().mount()[0]==13
        assert client().v3('GETATTR',t3.GETATTR3args(t3.nfs_fh3(root)),1).status==13
        checks.append('export disable revokes existing handles through fresh identity grants')
        for connection in clients:connection.close()
        f.stop();backup=f.base/'backup';f.ctl('backup','--output',str(backup))
        manifest=json.loads((backup/'manifest.json').read_text())
        assert not manifest['nfs_exports'] and not manifest['nfs_handles_and_state']
        assert 'nfs.db' not in manifest['files'] and not any(name.endswith('.nfs.db') for name in manifest['files'])
        db=sqlite3.connect(backup/'identity.db')
        try:assert db.execute("SELECT count(*) FROM records WHERE kind='nfs-exports'").fetchone()[0]==0
        finally:db.close()
        checks.append('offline metadata backup strips NFS enrollment and excludes persistent capability/recovery databases')

        return {'status':'passed','checks':checks,'client':'linux-nfs/pynfs cd4701827a8261fedbfb4c6e39029fb9671321a6 generated NFSv3/v4.1 codecs','full_conformance':False,'test_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'data_sha256':hashlib.sha256(data).hexdigest()}
    finally:
        for c in clients:c.close()
        try:
            if args.output and (f.base/'supervisor.log').exists():Path(args.output).with_suffix('.log').write_bytes((f.base/'supervisor.log').read_bytes())
        finally:f.close()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--bin',required=True);p.add_argument('--sanitizers',action='store_true');p.add_argument('--output');a=p.parse_args()
    result=run(a);print(json.dumps(result,indent=2))
    if a.output:Path(a.output).parent.mkdir(parents=True,exist_ok=True);Path(a.output).write_text(json.dumps(result,indent=2)+'\n')
