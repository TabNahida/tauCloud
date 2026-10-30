#!/usr/bin/env python3
"""Disposable SMB 2.1 acceptance using unmodified smbprotocol/pyspnego clients."""
import argparse, hashlib, json, os, socket, time, uuid, sys, struct, signal, platform, sqlite3, subprocess
from collections import OrderedDict
from smbprotocol.structure import Structure, IntField, BytesField
from smbprotocol.exceptions import SMBResponseException
from m5_wire import hostile, shares
from pathlib import Path
from m3_integration import Fixture as Base
from m1_integration import wait
from smbprotocol.connection import Connection, Dialects
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import SMB2QueryInfoRequest, SMB2QueryInfoResponse, SMB2SetInfoRequest, Open, ImpersonationLevel, CreateDisposition, CreateOptions, FilePipePrinterAccessMask, ShareAccess
from smbprotocol.file_info import FileAttributes, FileInformationClass, FileEndOfFileInformation, FileRenameInformation, FileDispositionInformation

class Fixture(Base):
    def __init__(self,binary,memory=512):
        super().__init__(binary,memory)
        self.stop()
        # Exercise upgrading an M4 schema/key set without changing the actual data.
        db=sqlite3.connect(self.state/'identity.db');db.executescript('DROP TABLE smb_credentials; PRAGMA user_version=3;');db.close()
        for role in ['file','file_1','file_2','file_3']:
            db=sqlite3.connect(self.state/(role+'.db'));db.executescript('DROP TABLE smb_pending; PRAGMA user_version=2;');db.close()
        keys=json.loads((self.state/'ipc-keys.json').read_text());keys.pop('smb');(self.state/'ipc-keys.json').write_text(json.dumps(keys))
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));self.smbport=sock.getsockname()[1]
        config=json.loads((self.state/'config.json').read_text());config['smb_port']=self.smbport
        (self.state/'config.json').write_text(json.dumps(config));self.start()
        self.api('spaces',self.admin,dict(id='smbdata',root='data',path='smbdata',owner='alice',quota=2*1024**3))
        self.api('shares',self.admin,dict(id='smb',space='smbdata',exposures={'smb':'rw'}))
        self.api('smb/credentials',self.admin,dict(username='alice',password=self.password))
        self.api('users',self.admin,dict(username='wire',password=self.password))
        self.api('smb/credentials',self.admin,dict(username='wire',password=self.password))
        self.api('smb/credentials',self.admin,dict(username='bob',password=self.password))
    def connect(self,user='alice',password=None,protocol='ntlm',share='smb'):
        c=Connection(uuid.uuid4(),'127.0.0.1',self.smbport,require_signing=True);c.connect(dialect=Dialects.SMB_2_1_0,timeout=10)
        s=Session(c,username='TAUCLOUD\\'+user,password=password or self.password,require_encryption=False,auth_protocol=protocol);s.connect()
        t=TreeConnect(s,'\\\\127.0.0.1\\'+share);t.connect();return c,s,t

def create(tree,name,access=0x13019f,share=7,disposition=3,options=0x40):
    h=Open(tree,name);h.create(ImpersonationLevel.Impersonation,access,FileAttributes.FILE_ATTRIBUTE_NORMAL,share,disposition,options);return h

def query(h,klass,info_type=1,limit=65536):
    q=SMB2QueryInfoRequest();q['info_type']=info_type;q['file_info_class']=klass;q['output_buffer_length']=limit;q['file_id']=h.file_id
    request=h.connection.send(q,h.tree_connect.session.session_id,h.tree_connect.tree_connect_id)
    response=h.connection.receive(request);r=SMB2QueryInfoResponse();r.unpack(response['data'].get_value());return r['buffer'].get_value()

def setinfo(h,info):
    q=SMB2SetInfoRequest();q['info_type']=info.INFO_TYPE;q['file_info_class']=info.INFO_CLASS;q['file_id']=h.file_id;q['buffer']=info
    request=h.connection.send(q,h.tree_connect.session.session_id,h.tree_connect.tree_connect_id);return h.connection.receive(request)

class Lock(Structure):
    COMMAND=10
    def __init__(self,fid,items):
        self.fields=OrderedDict([('size',IntField(size=2,default=48)),('count',IntField(size=2,default=len(items))),('sequence',IntField(size=4)),('fid',BytesField(size=16,default=fid)),('locks',BytesField(size=24*len(items),default=b''.join(struct.pack('<QQII',a,b,c,0) for a,b,c in items)))])
        super().__init__()
def lock(h,*items):
    q=Lock(h.file_id,items);return h.connection.receive(h.connection.send(q,h.tree_connect.session.session_id,h.tree_connect.tree_connect_id))
def denied(fn,*statuses):
    try:fn()
    except SMBResponseException as e:
        assert e.status in statuses,(hex(e.status),statuses);return
    raise AssertionError('expected rejection')
def run(args):
    f=Fixture(args.bin,512 if args.sanitizers else 256);checks=[];clients=[]
    def passed(text):checks.append(text);print('PASS '+text,flush=True)
    try:
        for _ in range(8):
            repeated,_,_=f.connect();repeated.disconnect()
        passed('verified repeated logins do not exhaust the failed-authentication budget')
        c,s,t=f.connect(share='SmB');clients.append(c)
        db=sqlite3.connect(f.state/'identity.db')
        try:
            cipher=db.execute("SELECT cipher FROM smb_credentials WHERE name='alice'").fetchone()[0]
            assert len(bytes.fromhex(cipher))==44 and f.password not in cipher
        finally:db.close()
        assert (f.state/'identity.pre-v4.db').exists()
        assert all((f.state/(role+'.pre-v3.db')).exists() for role in ['file','file_1','file_2','file_3'])
        h=create(t,'中文.txt')
        data=b'hello SMB'+bytes(range(256))*300
        for off in range(0,len(data),65536):assert h.write(data[off:off+65536],off)==len(data[off:off+65536])
        h.flush();assert h.read(0,65536)+h.read(65536,len(data)-65536)==data
        info=query(h,FileInformationClass.FILE_STANDARD_INFORMATION);assert int.from_bytes(info[8:16],"little")==len(data)
        assert query(h,22)[24:].decode('utf-16-le')=='::$DATA'
        h.close();root=create(t,'',access=0x120089,disposition=1,options=1)
        entries=root.query_directory('??.txt',FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION);assert [x['file_name'].get_value().decode('utf-16-le') for x in entries]==['中文.txt'];root.close()
        passed('signed NTLMv2 MIC authentication, UTF-16 create/read/write/flush/query/directory/close')
        ipc=TreeConnect(s,r'\\127.0.0.1\IPC$');ipc.connect();pipe=create(ipc,'srvsvc',access=0x12019f,disposition=1,options=0);assert shares(pipe)==['smb'];assert shares(pipe,transceive=True)==['smb'];pipe.close();ipc.disconnect()
        bob,bs,bt=f.connect(user='bob',share='IPC$');clients.append(bob);pipe=create(bt,'srvsvc',access=0x12019f,disposition=1,options=0);assert shares(pipe)==[];pipe.close();bob.disconnect()
        passed('authenticated srvsvc NDR32 share enumeration filters inaccessible and non-SMB shares')
        # Preserve API identifier spelling, while resolving SMB names without
        # case sensitivity. A non-SMB alias must not shadow the SMB exposure.
        f.api('shares',f.admin,dict(id='SMB',space='smbdata',exposures={'core':'r'}))
        f.api('shares',f.admin,dict(id='SMB',space='smbdata',exposures={'smb':'rw'},update=True),expected=409)
        f.api('shares',f.admin,dict(id='MixCase',space='smbdata',exposures={'smb':'rw'}))
        f.api('shares',f.admin,dict(id='mixcase',space='smbdata',exposures={'smb':'rw'}),expected=409)
        for alias in ('SMB','MIXCASE','mixcase'):
            alias_tree=TreeConnect(s,'\\\\127.0.0.1\\'+alias);alias_tree.connect()
            opened=create(alias_tree,'中文.txt',access=0x120089,disposition=1)
            assert opened.read(0,9)==b'hello SMB';opened.close();alias_tree.disconnect()
        denied(lambda:TreeConnect(s,r'\\127.0.0.1\missing-share').connect(),0xc00000cc)
        passed('SMB share lookup ignores case, preserves canonical grants and rejects ambiguous publication without non-SMB shadowing')
        h=create(t,'sharing',share=1);denied(lambda:create(t,'sharing'),0xc0000043);h.close()
        h=create(t,'sharing');other=create(t,'sharing');h.write(b'abcdef')
        lock(h,(0,3,0x12));denied(lambda:other.read(0,3),0xc0000054);denied(lambda:other.write(b'x',1),0xc0000054);assert other.read(3,3)==b'def';lock(h,(0,3,4))
        lock(h,(0,3,0x11));assert other.read(0,3)==b'abc';denied(lambda:other.write(b'x'),0xc0000054);lock(h,(0,3,4))
        rename=FileRenameInformation();rename['file_name']='renamed';setinfo(h,rename);assert other.read(0,6)==b'abcdef'
        eof=FileEndOfFileInformation();eof['end_of_file']=3;setinfo(h,eof);assert other.read(0,6)==b'abc'
        delete=FileDispositionInformation();delete['delete_pending']=True;setinfo(h,delete);denied(lambda:create(t,'renamed'),0xc0000056);h.close();assert (f.root/'smbdata/renamed').exists();other.close();assert not (f.root/'smbdata/renamed').exists()
        passed('share access conflicts, exclusive/shared byte locks, rename with live handles, truncate and last-close deletion')
        # Related CREATE/WRITE/READ/CLOSE, with placeholder file IDs and independent client signing.
        compound=Open(t,'compound');requests=[];receivers=[]
        pairs=[compound.create(ImpersonationLevel.Impersonation,0x13019f,FileAttributes.FILE_ATTRIBUTE_NORMAL,7,3,0x40,send=False),compound.write(b'compound',send=False),compound.read(0,8,send=False),compound.close(send=False)]
        requests=c.send_compound([x[0] for x in pairs],s.session_id,t.tree_connect_id,related=True)
        results=[pair[1](request) for pair,request in zip(pairs,requests)];assert results[1]==8 and results[2]==b'compound'
        passed('signed related compound CREATE/WRITE/READ/CLOSE and credit accounting')
        directory=create(t,'folder',options=1);child=create(t,'folder/child');child.close();denied(lambda:setinfo(directory,delete),0xc0000101);directory.close()
        h=create(t,'folder/child');setinfo(h,delete);h.close();directory=create(t,'folder',options=1);setinfo(directory,delete);directory.close();assert not (f.root/'smbdata/folder').exists()
        for name in ['../escape','bad:stream','e\u0301']:
            denied(lambda name=name:create(t,name),0xc000000d)
        h=create(t,'中文.txt',access=0x120089,disposition=1);denied(lambda:query(h,0,info_type=3),0xc00000bb);h.close()
        passed('directory deletion is nonrecursive; traversal/ADS/non-NFC denied; unsupported persistent ACL query rejected')
        h=create(t,'large');chunk=bytes(range(256))*256;expected=hashlib.sha256();actual=hashlib.sha256();total=args.large_mib*1024*1024
        for off in range(0,total,len(chunk)):h.write(chunk,off);expected.update(chunk)
        h.flush()
        for off in range(0,total,len(chunk)):actual.update(h.read(off,len(chunk)))
        assert actual.digest()==expected.digest();h.close();passed(f'{args.large_mib} MiB streamed binary roundtrip with SHA-256')
        hostile(f.smbport,f.password);passed('client-clock NTLMv2 with valid proof/MIC accepted; excessive skew, bad MIC/proof, unsigned/tampered signing and malformed packets rejected')
        # New credentials immediately invalidate existing SMB access, while management passwords remain separate.
        h=create(t,'revoked');f.api('smb/credentials',f.admin,dict(username='alice',enabled=False));denied(lambda:h.write(b'forbidden'),0xc000006d,0xc0000022)
        c.disconnect(close=False);f.api('smb/credentials',f.admin,dict(username='alice',password=f.password))
        c,s,t=f.connect(protocol='negotiate');clients.append(c);h=create(t,'revoked');h.write(b'restored');h.close();passed('SMB credential revocation invalidates live access; re-enrollment and SPNEGO reconnect succeed')
        before=f.ctl('status');h=create(t,'crash-delete',options=0x1040);h.write(b'pending')
        pid=before['smb']['identity']['pid']
        if os.name=='nt':subprocess.run(['taskkill','/F','/PID',str(pid)],capture_output=True,check=True)
        else:os.kill(pid,signal.SIGKILL)
        wait(lambda:(entry:=f.ctl('status')['smb'])['status']=='running' and entry['identity']['pid']!=pid);wait(lambda:not (f.root/'smbdata/crash-delete').exists())
        after=f.ctl('status');assert all(after[role]['identity']['pid']==before[role]['identity']['pid'] for role in ['api','file','identity','webdav'])
        c,s,t=f.connect();clients.append(c);h=create(t,'recovered');h.write(b'after restart');assert h.read(0,13)==b'after restart';h.close()
        passed('SMB worker kill/restart reclaims handles and durable delete intent without restarting API, identity or files')
        report={'status':'passed','checks':checks,'client':'smbprotocol 1.15.0 / pyspnego 0.12.4','host':platform.platform(),'authentication_provider':'Windows SSPI (sspilib)' if os.name=='nt' else 'pyspnego NTLM','large_mib':args.large_mib,'sha256':actual.hexdigest(),'port':f.smbport,'sanitizers':args.sanitizers}
        if args.output:Path(args.output).parent.mkdir(parents=True,exist_ok=True);Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report))
    except Exception:
        print((f.base/'supervisor.log').read_text()[-12000:],file=sys.stderr)
        raise
    finally:
        for client in clients:
            try:client.disconnect(close=False)
            except Exception:pass
        f.close()
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--bin',required=True);p.add_argument('--large-mib',type=int,default=1);p.add_argument('--output');p.add_argument('--sanitizers',action='store_true');run(p.parse_args())
