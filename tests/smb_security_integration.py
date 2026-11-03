#!/usr/bin/env python3
"""Independent signed SMB security-descriptor and cross-protocol access checks."""
import argparse, base64, hashlib, json, socket, sqlite3, struct, traceback
from pathlib import Path
from m5_integration import Fixture, create, query, setinfo, denied
from smbprotocol.open import SMB2QueryInfoRequest, SMB2QueryInfoResponse, SMB2SetInfoRequest, Open, ImpersonationLevel
from smbprotocol.create_contexts import SMB2CreateContextRequest
from smbprotocol.file_info import FileRenameInformation, FileDispositionInformation
from m7_integration import Client, t3, op, t4

FULL = 0x1f01ff
EVERYONE = bytes.fromhex('010100000000000100000000')
CREATOR = bytes.fromhex('010100000000000300000000')
OWNER_RIGHTS = bytes.fromhex('010100000000000304000000')

def ace(sid, mask=FULL, deny=False, flags=0):
    return struct.pack('<BBHI', int(deny), flags, 8+len(sid), mask)+sid

def descriptor(entries=None, owner=b'', group=b'', control=0x8004):
    body = bytearray(20);struct.pack_into('<BBH',body,0,1,0,control)
    for offset, value in ((4,owner),(8,group)):
        if value:struct.pack_into('<I',body,offset,len(body));body.extend(value)
    if entries is not None:
        acl=b''.join(entries);struct.pack_into('<I',body,16,len(body))
        body.extend(struct.pack('<BBHHH',2,0,len(acl)+8,len(entries),0)+acl)
    return bytes(body)

def parse(raw):
    _,_,control,owner,group,sacl,dacl=struct.unpack_from('<BBHIIII',raw)
    def sid(offset):return raw[offset:offset+8+4*raw[offset+1]] if offset else b''
    entries=[]
    if dacl:
        count=struct.unpack_from('<H',raw,dacl+4)[0];pos=dacl+8
        for _ in range(count):
            kind,flags,size,mask=struct.unpack_from('<BBHI',raw,pos)
            entries.append((kind,flags,mask,sid(pos+8)));pos+=size
    return dict(owner=sid(owner),group=sid(group),control=control,dacl=entries if dacl else None)

def request(h, packet):
    packet['file_id']=h.file_id
    return h.connection.receive(h.connection.send(packet,h.tree_connect.session.session_id,h.tree_connect.tree_connect_id))

def get_sd(h, information=7, limit=65536):
    q=SMB2QueryInfoRequest();q['info_type']=3;q['additional_information']=information;q['output_buffer_length']=limit
    r=SMB2QueryInfoResponse();r.unpack(request(h,q)['data'].get_value());return r['buffer'].get_value()

def set_sd(h, raw, information=4):
    q=SMB2SetInfoRequest();q['info_type']=3;q['additional_information'].flag_strict=False;q['additional_information']=information;q['buffer']=raw
    request(h,q)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bin',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    report=dict(status='failed',checks=[]);f=None;clients=[]
    def passed(text):report['checks'].append(text);print('PASS '+text,flush=True)
    try:
        f=Fixture(a.bin)
        f.stop()
        for role in ('file','file_1','file_2','file_3'):
            db=sqlite3.connect(f.state/(role+'.db'));db.executescript('DROP TABLE security_descriptors; PRAGMA user_version=5;');db.close()
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        cfg=json.loads((f.state/'config.json').read_text());cfg['nfs_port']=port
        (f.state/'config.json').write_text(json.dumps(cfg));f.start()
        assert all((f.state/(role+'.pre-v6.db')).exists() for role in ('file','file_1','file_2','file_3'))
        passed('schema 5 migration backs up each file authority before adding persistent security descriptors')
        f.api('grants',f.admin,dict(space='smbdata',subject_type='user',subject='bob',rights='rw'))
        f.api('groups',f.admin,dict(name='unix'))
        for user in ('alice','bob'):f.api('memberships',f.admin,dict(username=user,group='unix'))
        f.api('shares',f.admin,dict(id='nfs',space='smbdata',exposures={'nfs':'r'}))
        f.api('nfs-exports',f.admin,dict(id='nfs',trust='loopback-auth-sys',anonymous='bob',uids={'1000':'alice','1001':'bob'},gids={'1000':'unix'}))
        f.api('shares',f.admin,dict(id='acl-dav',space='smbdata',exposures={'webdav':'r'}))
        def connect(user='alice'):
            c,s,t=f.connect(user=user);clients.append(c);return t
        t=connect();bt=connect('bob')
        bobfile=create(bt,'bob',access=FULL);bob=parse(get_sd(bobfile))['owner'];bobfile.close()
        h=create(t,'private',access=FULL);h.write(b'secret');initial=parse(get_sd(h));alice=initial['owner']
        assert alice and alice!=bob and initial['dacl'][0][3]==EVERYONE
        assert parse(get_sd(h,1))['owner']==alice and parse(get_sd(h,1))['dacl'] is None
        denied(lambda:get_sd(h,7,1),0xc0000023)
        denied(lambda:get_sd(h,8),0xc0000022)
        limited=create(t,'private',access=0x80,disposition=1)
        denied(lambda:get_sd(limited),0xc0000022)
        denied(lambda:set_sd(limited,descriptor([])),0xc0000022);limited.close()
        passed('self-relative owner/group/DACL query, requested sections, required buffer size and READ_CONTROL/WRITE_DAC/SACL boundaries')
        live=create(bt,'private',access=1,disposition=1)
        protected=[ace(bob,1,deny=True),ace(alice),ace(EVERYONE,0x120089)]
        set_sd(h,descriptor(protected))
        assert parse(get_sd(h))['dacl'][0][:3]==(1,0,1)
        denied(lambda:create(bt,'private',access=1,disposition=1),0xc0000022)
        assert live.read(0,6)==b'secret';live.close()
        maximum=create(bt,'private',access=0x02000000,disposition=1)
        rights=struct.unpack('<I',query(maximum,8))[0];assert not rights&1 and rights&0x20000
        maximum.close()
        denied(lambda:create(bt,'private',access=0x02000001,disposition=1),0xc0000022)
        passed('ordered deny/allow access checks, MAXIMUM_ALLOWED and explicit-right intersection; existing handles retain granted rights')
        n=Client(port,uid=1001);clients.append(n);status,root=n.mount();assert status==0
        r=n.v3('LOOKUP',t3.LOOKUP3args(t3.diropargs3(t3.nfs_fh3(root),b'private')),3);assert r.status==0,r
        fh=r.resok.object.data
        r=n.v3('READ',t3.READ3args(t3.nfs_fh3(fh),0,6),6);assert r.status==13,r
        r=n.v3('ACCESS',t3.ACCESS3args(t3.nfs_fh3(fh),0x3f),4);assert r.status==0 and not r.resok.access&1,r
        n.session();r=n.compound([op.putfh(fh),op.access(0x3f)]);assert r.status==0 and not r.resarray[-1].opaccess.resok4.access&1,r
        login=f.api('auth/login',data=dict(username='bob',password=f.password,scope='files'))['token']
        f.api('files/open',login,dict(space='smbdata',path='private'),expected=403)
        import http.client
        conn=http.client.HTTPSConnection('127.0.0.1',f.davport,context=f.context,timeout=10)
        auth='Basic '+base64.b64encode(('bob:'+f.password).encode()).decode()
        conn.request('GET','/dav/acl-dav/private',headers={'Authorization':auth});res=conn.getresponse();res.read();assert res.status==403,res.status;conn.close()
        passed('SMB denial enforced by NFSv3 READ/ACCESS, NFSv4 ACCESS, core API and WebDAV readonly aliases')
        set_sd(h,descriptor([ace(EVERYONE,1),ace(EVERYONE,1,deny=True)]))
        reader=create(bt,'private',access=1,disposition=1);assert reader.read(0,6)==b'secret';reader.close()
        set_sd(h,descriptor([]))
        denied(lambda:create(bt,'private',access=0x20000,disposition=1),0xc0000022)
        owner=create(t,'private',access=0x60000,disposition=1);owner.close()
        denied(lambda:create(t,'private',access=1,disposition=1),0xc0000022)
        set_sd(h,descriptor([ace(OWNER_RIGHTS,0x20000)]))
        denied(lambda:create(t,'private',access=0x40000,disposition=1),0xc0000022)
        set_sd(h,descriptor(None));reader=create(bt,'private',access=1,disposition=1);reader.close()
        passed('ACE order, empty versus NULL DACL, implicit owner rights and OWNER RIGHTS SID')
        set_sd(h,descriptor(protected))
        before=get_sd(h)
        invalid=[b'',descriptor([])[:19],descriptor([ace(EVERYONE)])[:-1]]
        overlap=bytearray(descriptor([],owner=alice));struct.pack_into('<I',overlap,8,22);invalid.append(bytes(overlap))
        for raw in invalid:denied(lambda raw=raw:set_sd(h,raw),0xc0000079)
        unsupported=bytearray(descriptor([ace(EVERYONE)]));unsupported[28]=9
        denied(lambda:set_sd(h,bytes(unsupported)),0xc00000bb)
        denied(lambda:set_sd(h,descriptor(owner=bob),1),0xc000005a)
        denied(lambda:set_sd(h,descriptor([],control=0x8014),8),0xc0000022)
        assert get_sd(h)==before
        passed('malformed offsets, overlaps, truncation and unsupported ACEs rejected atomically; ownership cannot be assigned to another user')
        # New objects inherit an immutable descriptor snapshot, bound to native identity.
        d=create(t,'parent',access=FULL,options=1)
        set_sd(d,descriptor([ace(alice),ace(CREATOR,flags=3),ace(bob,1,deny=True,flags=3),ace(EVERYONE,0x120089,flags=3)],control=0x8504),0x80000004)
        child=create(t,'parent/child',access=FULL);child.write(b'inherited')
        child_sd=parse(get_sd(child));assert child_sd['owner']==alice
        assert all(entry[1]&16 for entry in child_sd['dacl'])
        denied(lambda:create(bt,'parent/child',access=1,disposition=1),0xc0000022)
        sub=create(t,'parent/sub',access=FULL,options=1);grand=create(t,'parent/sub/grand',access=FULL);grand.close();sub.close()
        denied(lambda:create(bt,'parent/sub/grand',access=1,disposition=1),0xc0000022)
        d.close();ren=FileRenameInformation();ren['replace_if_exists']=False;ren['file_name']='renamed-private';setinfo(child,ren);child.close()
        denied(lambda:create(bt,'renamed-private',access=1,disposition=1),0xc0000022)
        passed('file/directory inheritance with CREATOR OWNER substitution and multi-generation propagation; ACL follows rename')
        def secure_create(name, raw, duplicate=False):
            ctx=SMB2CreateContextRequest();ctx['buffer_name']=b'SecD';ctx['buffer_data']=raw
            new=Open(t,name);new.create(ImpersonationLevel.Impersonation,FULL,0x80,7,3,0x40,create_contexts=[ctx,ctx] if duplicate else [ctx]);return new
        created=secure_create('with-sd',descriptor([ace(alice),ace(bob,1,deny=True)],owner=alice,control=0x9004))
        assert parse(get_sd(created))['control']&0x1000;created.write(b'created');created.close()
        denied(lambda:create(bt,'with-sd',access=1,disposition=1),0xc0000022)
        denied(lambda:secure_create('bad-sd',b'bad'),0xc0000079)
        denied(lambda:secure_create('bad-owner',descriptor(owner=bob)),0xc000005a)
        denied(lambda:secure_create('duplicate-sd',descriptor(),True),0xc000000d)
        assert all(not (f.root/'smbdata'/name).exists() for name in ('bad-sd','bad-owner','duplicate-sd'))
        passed('SecD CREATE persists protected initial ACL, validates ownership and rejects duplicate/malformed contexts before mutation')
        # Group SID membership comes from the signed identity grant.
        group_sid=bytes.fromhex('010500000000000515000000')+hashlib.sha256(b'tauCloud/group/unix').digest()[:16]
        set_sd(h,descriptor([ace(alice),ace(group_sid,1)]));reader=create(bt,'private',access=1,disposition=1);reader.close()
        h.close()
        f.api('memberships',f.admin,dict(username='bob',group='unix',enabled=False))
        t=connect();bt=connect('bob');denied(lambda:create(bt,'private',access=1,disposition=1),0xc0000022)
        h=create(t,'private',access=FULL,disposition=1);set_sd(h,descriptor(protected));h.close()
        passed('group ACE enforcement and membership revocation use freshly signed identity grants')
        for client in clients:
            if isinstance(client,Client):client.close()
            else:client.disconnect()
        clients=[];f.stop()
        db=sqlite3.connect(f.state/'file.db');assert db.execute('PRAGMA user_version').fetchone()[0]==6;db.close()
        f.start();t=connect();bt=connect('bob')
        denied(lambda:create(bt,'private',access=1,disposition=1),0xc0000022)
        denied(lambda:create(bt,'renamed-private',access=1,disposition=1),0xc0000022)
        h=create(t,'private',access=FULL,disposition=1);assert parse(get_sd(h))['dacl'][0][0]==1
        deletion=FileDispositionInformation();deletion['delete_pending']=True;setinfo(h,deletion);h.close()
        h=create(bt,'private',access=FULL);assert parse(get_sd(h))['owner']==bob;h.close()
        passed('schema 6 durability across process restart; replacement object receives fresh owner and ACL')
        # Change the single writer protocol so write-denial is tested at the file
        # DACL rather than stopped by the earlier readonly share policy.
        f.api('shares',f.admin,dict(id='smb',space='smbdata',exposures={'smb':'r'},update=True))
        f.api('shares',f.admin,dict(id='nfs',space='smbdata',exposures={'nfs':'rw'},update=True))
        f.api('memberships',f.admin,dict(username='bob',group='unix'))
        n=Client(port,uid=1001);clients.append(n);status,root=n.mount();assert status==0
        r=n.v3('LOOKUP',t3.LOOKUP3args(t3.diropargs3(t3.nfs_fh3(root),b'with-sd')),3);assert r.status==0,r
        fh=r.resok.object.data
        r=n.v3('WRITE',t3.WRITE3args(t3.nfs_fh3(fh),0,1,2,b'!'),7);assert r.status==13,r
        attrs=t3.sattr3(t3.set_mode3(True,0o777),t3.set_uid3(False),t3.set_gid3(False),t3.set_size3(False),t3.set_atime(0),t3.set_mtime(0))
        r=n.v3('SETATTR',t3.SETATTR3args(t3.nfs_fh3(fh),attrs,t3.sattrguard3(False)),2);assert r.status==13,r
        assert (f.root/'smbdata/with-sd').read_bytes()==b'created'
        passed('NFS writer publication still enforces file DACL; WRITE and chmod cannot bypass SMB restrictions')
        report['status']='passed' 
    except Exception:
        report['error']=traceback.format_exc();raise
    finally:
        for client in clients:
            try:
                if isinstance(client,Client):client.close()
                else:client.disconnect()
            except Exception:pass
        if f:f.close()
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
