#!/usr/bin/env python3
"""SMB3 independent-client interop and adversarial wire tests, disposable loopback only."""
import argparse, hashlib, json, os, platform, signal, socket, struct, subprocess, sys, uuid
from pathlib import Path
from m5_integration import Fixture, create, denied, lock, setinfo, query
from m5_wire import header, exchange, rejected_connection, shares, status
from m1_integration import wait
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open, ImpersonationLevel, SMB2CreateRequest, SMB2WriteRequest
from smbprotocol.file_info import FileAttributes, FileDispositionInformation, FileRenameInformation, FileEndOfFileInformation
from smbprotocol.ioctl import SMB2IOCTLRequest
from smbprotocol.create_contexts import SMB2CreateDurableHandleRequestV2, SMB2CreateDurableHandleReconnectV2, SMB2CreateRequestLease
from smbprotocol.change_notify import SMB2ChangeNotifyRequest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers.algorithms import AES
import spnego


def negotiate_packet(dialect=0x311, signing=1, cipher=2, hash_id=1):
    dialects = [0x210, 0x300, 0x302, 0x311] if dialect == 0x311 else [dialect]
    body = struct.pack('<HHHHI16sIHH',36,len(dialects),3,0,0x40,uuid.uuid4().bytes,0,0,0)
    p = bytearray(header(0)+body+b''.join(struct.pack('<H',d) for d in dialects))
    if dialect == 0x311:
        p += bytes(-len(p)%8); struct.pack_into('<IH',p,92,len(p),3)
        for i,(kind,data) in enumerate([(1,struct.pack('<HHH',1,0,hash_id)),(2,struct.pack('<HH',1,cipher)),(8,struct.pack('<HH',1,signing))]):
            if i: p += bytes(-len(p)%8)
            p += struct.pack('<HHI',kind,len(data),0)+data
    return bytes(p)


def sign(packet, key):
    c=CMAC(AES(key)); c.update(packet[:48]+bytes(16)+packet[64:])
    return packet[:48]+c.finalize()+packet[64:]


def wire_auth(port,password,user,dialect=0x311,alter_transcript=False):
    sock=socket.create_connection(('127.0.0.1',port),timeout=10)
    try:
        req=negotiate_packet(dialect);resp=exchange(sock,req);assert status(resp)==0
        transcript=hashlib.sha512(bytes(64)+req).digest();transcript=hashlib.sha512(transcript+resp).digest()
        if alter_transcript:transcript=bytes(64)
        ctx=spnego.client(username='TAUCLOUD\\'+user,password=password,protocol='ntlm',hostname='127.0.0.1',service='cifs')
        def setup(token,mid,sid):return header(1,mid,sid,flags=0x10 if dialect==0x311 else 0)+struct.pack('<HBBIIHHQ',25,0,1,0,0,88,len(token),0)+token
        req=setup(ctx.step(),1,0);resp=exchange(sock,req);assert status(resp)==0xc0000016
        transcript=hashlib.sha512(transcript+req).digest();transcript=hashlib.sha512(transcript+resp).digest()
        sid=struct.unpack_from('<Q',resp,40)[0];off,n=struct.unpack_from('<HH',resp,68)
        req=setup(ctx.step(resp[off:off+n]),2,sid);resp=exchange(sock,req);assert status(resp)==0
        transcript=hashlib.sha512(transcript+req).digest()
        derive=lambda label,context:Session._smb3kdf(None,ctx.session_key,label+b'\0',context)
        if dialect==0x311:
            signing=derive(b'SMBSigningKey',transcript);sending=derive(b'SMBC2SCipherKey',transcript);receiving=derive(b'SMBS2CCipherKey',transcript)
        else:
            signing=derive(b'SMB2AESCMAC',b'SmbSign\0');sending=derive(b'SMB2AESCCM',b'ServerIn \0');receiving=derive(b'SMB2AESCCM',b'ServerOut\0')
        assert (sign(resp,signing)[48:64]==resp[48:64]) != alter_transcript
        return sock,sid,signing,sending,receiving,req
    except Exception:sock.close();raise


def encrypted(packet,key,sid,cipher=2,nonce=None):
    nonce=nonce or os.urandom(12 if cipher==2 else 11)
    aad=nonce+bytes(16-len(nonce))+struct.pack('<IHHQ',len(packet),0,1,sid)
    data=(AESGCM if cipher==2 else AESCCM)(key).encrypt(nonce,packet,aad)
    return b'\xfdSMB'+data[-16:]+aad+data[:-16]


def fatal_compound(f, user, share, local_path):
    sock,sid,key,_,_,_=wire_auth(f.smbport,f.password,user,0x300)
    unc=r'\\127.0.0.1\smb'.replace('smb',share).encode('utf-16-le')
    response=exchange(sock,sign(header(3,3,sid,flags=8)+struct.pack('<HHHH',9,0,72,len(unc))+unc,key))
    assert status(response)==0
    tid=struct.unpack_from('<I',response,36)[0]
    create=SMB2CreateRequest();create['impersonation_level']=2;create['desired_access']=0x13019f;create['file_attributes']=0x80;create['share_access']=7;create['create_disposition']=3;create['create_options']=0x40;create['buffer_path']='compound-security'.encode('utf-16-le')
    response=exchange(sock,sign(header(5,4,sid,tid,flags=8)+create.pack(),key));assert status(response)==0
    fid=response[128:144]
    validate=SMB2IOCTLRequest();validate['ctl_code']=0x140204;validate['file_id']=b'\xff'*16;validate['max_output_response']=24;validate['flags']=1;validate['buffer']=b'\0'*26
    first=bytearray(header(11,5,sid,tid,flags=8)+validate.pack());first+=bytes(-len(first)%8);struct.pack_into('<I',first,20,len(first))
    write=SMB2WriteRequest();write['file_id']=fid;write['buffer']=b'not-authorized-after-fatal-error'
    last=header(9,6,sid,tid,flags=8)+write.pack()
    rejected_connection(sock,sign(first,key)+sign(last,key))
    # A fresh open with exclusive sharing is a cleanup barrier: the failed connection's
    # handle must have been released before this open can succeed on the file authority.
    from m5_integration import create as open_file
    from m1_integration import wait
    c,s,t=f.connect(user=user,share=share)
    try:
        handles=[]
        def cleaned():
            try:handles.append(open_file(t,'compound-security',share=0,disposition=1));return True
            except Exception:return False
        wait(cleaned);h=handles[0];h.close()
        assert (f.root/local_path/'compound-security').read_bytes()==b'', 'later compound WRITE executed after fatal security failure'
    finally:c.disconnect(close=False)

def run(args):
    f=Fixture(args.bin,512 if args.sanitizers else 256);checks=[];clients=[];index=0
    def passed(text):checks.append(text);print('PASS '+text,flush=True)
    def user():
        nonlocal index
        index+=1;name='m6user'+str(index)
        f.api('users',f.admin,dict(username=name,password=f.password))
        f.api('smb/credentials',f.admin,dict(username=name,password=f.password))
        return name
    def connect(dialect=None,ciphers=None,encrypted_session=False):
        c=Connection(uuid.uuid4(),'127.0.0.1',f.smbport,require_signing=True);clients.append(c)
        c.connect(dialect=dialect,preferred_encryption_algos=ciphers)
        s=Session(c,username='TAUCLOUD\\alice',password=f.password,require_encryption=encrypted_session,auth_protocol='ntlm');s.connect()
        t=TreeConnect(s,r'\\127.0.0.1\smb');t.connect()
        return c,s,t
    try:
        for dialect in (0x300,0x302,0x311):
            c,s,t=connect(dialect)
            assert c.dialect==dialect and c.supports_encryption and not c.supports_file_leasing and not c.supports_multi_channel
            h=create(t,'signed-'+hex(dialect));h.write(b'signed');assert h.read(0,6)==b'signed';h.close()
            passed(f'{hex(dialect)} AES-CMAC signed login and operations; validate-negotiate for 3.0/3.0.2')
            s.encrypt_data=True
            name='加密-'+hex(dialect);h=create(t,name);h.write(bytes(range(256))*256);h.flush();assert h.read(0,65536)==bytes(range(256))*256
            eof=FileEndOfFileInformation();eof['end_of_file']=8;setinfo(h,eof);assert len(h.read(0,100))==8
            rename=FileRenameInformation();rename['file_name']=name+'-renamed';setinfo(h,rename)
            assert int.from_bytes(query(h,5)[8:16],'little')==8
            delete=FileDispositionInformation();delete['delete_pending']=True;setinfo(h,delete);h.close()
            compound=Open(t,'compound-'+hex(dialect))
            pairs=[compound.create(ImpersonationLevel.Impersonation,0x13019f,FileAttributes.FILE_ATTRIBUTE_NORMAL,7,3,0x40,send=False),compound.write(b'compound',send=False),compound.read(0,8,send=False),compound.close(send=False)]
            requests=c.send_compound([p[0] for p in pairs],s.session_id,t.tree_connect_id,related=True)
            results=[p[1](r) for p,r in zip(pairs,requests)];assert results[1]==8 and results[2]==b'compound'
            ipc=TreeConnect(s,r'\\127.0.0.1\IPC$');ipc.connect();pipe=create(ipc,'srvsvc',access=0x12019f,disposition=1,options=0)
            assert shares(pipe,True)==['smb'];pipe.close();ipc.disconnect()
            h=create(t,'large-'+hex(dialect));chunk=bytes(range(256))*256;digest=hashlib.sha256()
            for off in range(0,args.large_mib*1024*1024,len(chunk)):h.write(chunk,off)
            h.flush()
            for off in range(0,args.large_mib*1024*1024,len(chunk)):digest.update(h.read(off,len(chunk)))
            expected=hashlib.sha256()
            for _ in range(args.large_mib*16):expected.update(chunk)
            assert digest.digest()==expected.digest();h.close()
            passed(f'{hex(dialect)} encrypted Unicode IO, metadata, rename/delete, compound, srvsvc and {args.large_mib} MiB SHA-256 stream')
            c.disconnect(close=False)
        c,s,t=connect(None,[1],True);assert c.dialect==0x311 and c.cipher_id==1
        h=create(t,'fallback-ccm');h.write(b'CCM');assert h.read(0,3)==b'CCM';h.close();c.disconnect(close=False)
        passed('default highest common dialect is 3.1.1; explicit CCM-only offer and encryption-required client work')
        modern,ms,mt=connect(None,encrypted_session=True);assert modern.dialect==0x311 and modern.cipher_id==2
        lease=SMB2CreateRequestLease();lease['lease_key']=os.urandom(16);lease['lease_state']=7
        durable=SMB2CreateDurableHandleRequestV2();durable['create_guid']=uuid.uuid4()
        h=Open(mt,'ordinary-open');contexts=h.create(ImpersonationLevel.Impersonation,0x13019f,FileAttributes.FILE_ATTRIBUTE_NORMAL,7,3,0x40,create_contexts=[lease,durable],oplock_level=0xff)
        assert not contexts and h.oplock_level==0;fid=h.file_id;h.close()
        reconnect=SMB2CreateDurableHandleReconnectV2();reconnect['file_id']=fid;reconnect['create_guid']=durable['create_guid'].get_value()
        denied(lambda:Open(mt,'ordinary-open').create(ImpersonationLevel.Impersonation,0x13019f,FileAttributes.FILE_ATTRIBUTE_NORMAL,7,1,0x40,create_contexts=[reconnect]),0xc00000bb)
        directory=create(mt,'',access=0x120089,disposition=1,options=1)
        notify=SMB2ChangeNotifyRequest();notify['file_id']=directory.file_id;notify['output_buffer_length']=1024;notify['completion_filter']=1
        denied(lambda:modern.receive(modern.send(notify,ms.session_id,mt.tree_connect_id)),0xc00000bb);directory.close()
        passed('leases and durable handles are not granted; durable reconnect and change notifications explicitly unsupported; multichannel absent')
        # A separate disposable owner keeps login throttling active during the matrix.
        legacy=Connection(uuid.uuid4(),'127.0.0.1',f.smbport,require_signing=True);clients.append(legacy);legacy.connect(dialect=0x210)
        mixed_user=user()
        f.api('spaces',f.admin,dict(id='mixeddata',root='data',path='mixeddata',owner=mixed_user,quota=1024**2))
        f.api('shares',f.admin,dict(id='mixed',space='mixeddata',exposures={'smb':'rw'}))
        ls=Session(legacy,username='TAUCLOUD\\'+mixed_user,password=f.password,require_encryption=False,auth_protocol='ntlm');ls.connect()
        lt=TreeConnect(ls,r'\\127.0.0.1\mixed');lt.connect()
        mixed=Connection(uuid.uuid4(),'127.0.0.1',f.smbport,require_signing=True);clients.append(mixed);mixed.connect()
        xs=Session(mixed,username='TAUCLOUD\\'+mixed_user,password=f.password,require_encryption=True,auth_protocol='ntlm');xs.connect()
        xt=TreeConnect(xs,r'\\127.0.0.1\mixed');xt.connect()
        h=create(xt,'shared');other=create(lt,'shared');h.write(b'new');assert other.read(0,3)==b'new'
        lock(h,(0,3,0x12));denied(lambda:other.write(b'bad'),0xc0000054);lock(h,(0,3,4));other.write(b'old');assert h.read(0,3)==b'old';other.close();h.close()
        legacy.disconnect(close=False);mixed.disconnect(close=False)
        passed('SMB2.1 signed and SMB3.1.1 encrypted sessions share immediate data visibility and byte-range locks')
        # Hostile negotiation contexts, before credential access.
        for packet,expected in [(negotiate_packet(signing=2),0xc00000bb),(negotiate_packet(cipher=4),0xc00000bb),(negotiate_packet(hash_id=2),0xc05d0000)]:
            with socket.create_connection(('127.0.0.1',f.smbport),timeout=10) as sock:assert status(exchange(sock,packet))==expected
        for field,value in [(92,100),(96,17)]:
            bad=bytearray(negotiate_packet());struct.pack_into('<I' if field==92 else '<H',bad,field,value)
            with socket.create_connection(('127.0.0.1',f.smbport),timeout=10) as sock:assert status(exchange(sock,bad))==0xc000000d
        passed('unsupported signing/cipher/hash and malformed contexts fail without dialect fallback')
        for dialect,cipher in [(0x300,1),(0x302,1),(0x311,2)]:
            sock,sid,sk,ek,dk,_=wire_auth(f.smbport,f.password,user(),dialect)
            echo=header(13,3,sid)+struct.pack('<HH',4,0);packet=encrypted(echo,ek,sid,cipher)
            response=exchange(sock,packet);assert response[:4]==b'\xfdSMB'
            plain=(AESGCM if cipher==2 else AESCCM)(dk).decrypt(response[20:32 if cipher==2 else 31],response[52:]+response[4:20],response[20:52]);assert status(plain)==0
            rejected_connection(sock,packet)
        passed('independent AES-CCM/GCM transform decoding and replayed ciphertext rejected for each SMB3 dialect')
        for mode in ['tag','ciphertext','aad','sid','size','nonce','signature','unsigned','preauth','reused_nonce','validate','validate311']:
            dialect=0x300 if mode=='validate' else 0x311
            sock,sid,sk,ek,dk,_=wire_auth(f.smbport,f.password,user(),dialect,mode=='preauth')
            echo=header(13,3,sid)+struct.pack('<HH',4,0)
            if mode in ('signature','preauth'):
                packet=bytearray(sign(header(13,3,sid,flags=8)+struct.pack('<HH',4,0),sk))
                if mode=='signature':packet[-1]^=1
            elif mode=='unsigned':packet=echo
            elif mode=='reused_nonce':
                nonce=os.urandom(12);exchange(sock,encrypted(echo,ek,sid,nonce=nonce))
                packet=encrypted(header(13,4,sid)+struct.pack('<HH',4,0),ek,sid,nonce=nonce)
            elif mode.startswith('validate'):
                unc=r'\\127.0.0.1\IPC$'.encode('utf-16-le')
                response=exchange(sock,sign(header(3,3,sid,flags=8)+struct.pack('<HHHH',9,0,72,len(unc))+unc,sk))
                assert status(response)==0
                tid=struct.unpack_from('<I',response,36)[0]
                q=SMB2IOCTLRequest();q['ctl_code']=0x140204;q['file_id']=b'\xff'*16;q['max_output_response']=24;q['flags']=1;q['buffer']=b'\0'*26
                packet=sign(header(11,4,sid,tid,flags=8)+q.pack(),sk)
            else:
                packet=bytearray(encrypted(echo,ek,sid));packet[{'tag':4,'ciphertext':52,'aad':20,'sid':44,'size':36,'nonce':32}[mode]]^=1
            rejected_connection(sock,packet)
        passed('tampered tags/ciphertext/AAD/session/size/nonce/signatures, unsigned requests, altered preauth chain, reused nonce and invalid validate-negotiate disconnect')
        fatal_compound(f,mixed_user,'mixed','mixeddata')
        passed('fatal negotiate validation stops subsequent unrelated compound WRITE; exclusive-open cleanup barrier confirms unchanged file')
        h=create(mt,'crash-delete',options=0x1040);h.write(b'pending')
        before=f.ctl('status');pid=before['smb']['identity']['pid']
        if os.name=='nt':subprocess.run(['taskkill','/F','/PID',str(pid)],capture_output=True,check=True)
        else:os.kill(pid,signal.SIGKILL)
        wait(lambda:(entry:=f.ctl('status')['smb'])['status']=='running' and entry['identity']['pid']!=pid)
        wait(lambda:not (f.root/'smbdata/crash-delete').exists());denied_status=False
        try:h.read(0,7)
        except Exception:denied_status=True
        assert denied_status
        after=f.ctl('status');assert all(before[r]['identity']['pid']==after[r]['identity']['pid'] for r in ['api','identity','file','webdav'])
        # Fresh user already owns mixeddata; new keys must be negotiated after restart.
        c=Connection(uuid.uuid4(),'127.0.0.1',f.smbport,require_signing=True);clients.append(c);c.connect()
        s=Session(c,username='TAUCLOUD\\'+mixed_user,password=f.password,require_encryption=True,auth_protocol='ntlm');s.connect();t=TreeConnect(s,r'\\127.0.0.1\mixed');t.connect()
        h=create(t,'shared',disposition=1);assert h.read(0,3)==b'old';h.close()
        passed('SMB worker crash closes old sessions, recovers delete intent, preserves other workers and permits encrypted reconnect with new keys')
        report=dict(status='passed',checks=checks,client='smbprotocol 1.15.0 / pyspnego 0.12.4',host=platform.platform(),authentication_provider='Windows SSPI (sspilib)' if os.name=='nt' else 'pyspnego NTLM',large_mib=args.large_mib,sha256=digest.hexdigest(),port=f.smbport,sanitizers=args.sanitizers)
        if args.output:Path(args.output).parent.mkdir(parents=True,exist_ok=True);Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report))
    except Exception:
        print((f.base/'supervisor.log').read_text()[-6000:],file=sys.stderr);raise
    finally:
        for c in clients:
            try:c.disconnect(close=False)
            except Exception:pass
        f.close()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--bin',required=True);p.add_argument('--large-mib',type=int,default=1);p.add_argument('--output');p.add_argument('--sanitizers',action='store_true');run(p.parse_args())
