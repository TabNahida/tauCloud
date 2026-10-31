#!/usr/bin/env python3
"""Independent SMB client checks for persistent DOS metadata and readonly access."""
import argparse,json,struct,sys,traceback
from pathlib import Path
from m5_integration import Fixture,create,query,setinfo,denied
from smbprotocol.create_contexts import SMB2CreateContextRequest
from smbprotocol.open import SMB2SetInfoRequest,Open,ImpersonationLevel
from smbprotocol.file_info import FileRenameInformation,FileDispositionInformation

def run():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bin',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    f=Fixture(a.bin);clients=[];report=dict(status='failed',checks=[])
    def connect():
        c,s,t=f.connect();clients.append(c);return c,s,t
    def attrs(h,value,times=(0,0,0,0)):
        q=SMB2SetInfoRequest();q['info_type']=1;q['file_info_class']=4;q['file_id']=h.file_id;q['buffer']=struct.pack('<QQQQII',*times,value,0)
        r=h.connection.send(q,h.tree_connect.session.session_id,h.tree_connect.tree_connect_id);h.connection.receive(r)
    def ea(name,value,flags=0):return struct.pack('<IBBH',0,flags,len(name),len(value))+name+b'\0'+value
    def seteas(h,raw):
        q=SMB2SetInfoRequest();q['info_type']=1;q['file_info_class']=15;q['file_id']=h.file_id;q['buffer']=raw
        r=h.connection.send(q,h.tree_connect.session.session_id,h.tree_connect.tree_connect_id);h.connection.receive(r)
    def read_eas(h):
        raw=query(h,15);items={};offset=0
        while True:
            nxt,flags,n,size=struct.unpack_from('<IBBH',raw,offset);name=raw[offset+8:offset+8+n];value=raw[offset+9+n:offset+9+n+size];items[name]=(flags,value)
            if not nxt:return items
            offset+=nxt
    def readattrs(h):return struct.unpack_from('<I',query(h,4),32)[0]
    def new(t,name,value,options=0x40):
        h=Open(t,name);h.create(ImpersonationLevel.Impersonation,0x13019f,value,7,3,options);return h
    try:
        c,s,t=connect();h=new(t,'attributes',0x2|0x4);assert readattrs(h)==0x26
        attrs(h,0x1|0x2|0x4|0x100|0x1000|0x2000);assert readattrs(h)==0x3107
        denied(lambda:create(t,'attributes',access=0x120116,disposition=1),0xc0000022)
        maximum=create(t,'attributes',access=0x02000000,disposition=1)
        assert not (struct.unpack_from('<I',query(maximum,8))[0] & 6)
        denied(lambda:maximum.write(b'denied'),0xc0000022);maximum.close()
        deletion=FileDispositionInformation();deletion['delete_pending']=True
        denied(lambda:setinfo(h,deletion),0xc0000121)
        attrs(h,0);assert readattrs(h)==0x3107
        # Rights already granted to this handle survive later readonly changes.
        h.write(b'persist');assert readattrs(h)==0x3127
        reader=create(t,'attributes',access=0x120089,disposition=1)
        denied(lambda:attrs(reader,0x80),0xc0000022);reader.close()
        attrs(h,0x80);assert readattrs(h)==0x80
        denied(lambda:attrs(h,0x10),0xc000000d);assert readattrs(h)==0x80
        attrs(h,0x200) # Filesystem-controlled attributes are not changed here.
        assert readattrs(h)==0x80
        report['checks'].append('CREATE/QUERY/SET persistent DOS attributes, zero/no-change and NORMAL semantics; readonly open/delete checks and granted-handle authority')
        epoch=116444736000000000
        timestamps=tuple(epoch+17000000000000000+i*1234567 for i in range(4))
        attrs(h,0,timestamps);assert struct.unpack_from('<QQQQ',query(h,4))==timestamps
        assert (f.root/'smbdata/attributes').stat().st_mtime_ns==(timestamps[2]-epoch)*100
        h.write(b'sticky');h.read(0,6);h.flush();assert struct.unpack_from('<QQQQ',query(h,4))==timestamps
        attrs(h,0,tuple([2**64-1]*4));h.write(b'frozen');assert struct.unpack_from('<QQQQ',query(h,4))==timestamps
        denied(lambda:attrs(h,2,(0,0,2**64-3,0)),0xc000000d)
        assert readattrs(h)==0x20
        attrs(h,0,(0,2**64-2,2**64-2,2**64-2));h.write(b'automatic')
        assert struct.unpack_from('<QQQQ',query(h,4))[2]!=timestamps[2]
        attrs(h,0,timestamps)
        report['checks'].append('four independent timestamps, native mtime, zero/no-change, per-handle explicit/-1 freeze and -2 re-enable; invalid times reject before attribute mutation')
        attrs(h,0x2002);ren=FileRenameInformation();ren['replace_if_exists']=False;ren['file_name']='renamed';setinfo(h,ren);h.close()
        d=new(t,'directory',0x2,1);assert readattrs(d)==0x12;attrs(d,0x80);assert readattrs(d)==0x10
        denied(lambda:attrs(d,0x100),0xc000000d);d.close()
        denied(lambda:new(t,'temporary-directory',0x100,1),0xc000000d)
        assert not (f.root/'smbdata/temporary-directory').exists()
        context=SMB2CreateContextRequest();context['buffer_name']=b'ExtA';context['buffer_data']=ea(b'Example',b'\x00binary\xff',128)
        extended=Open(t,'extended');extended.create(ImpersonationLevel.Impersonation,0x13019f,0x80,7,3,0x40,create_contexts=[context])
        assert read_eas(extended)=={b'EXAMPLE':(128,b'\x00binary\xff')}
        denied(lambda:create(t,'extended',options=0x240,disposition=1),0xc0000022)
        seteas(extended,ea(b'example',b'updated'));assert read_eas(extended)=={b'EXAMPLE':(0,b'updated')}
        no_ea=create(t,'extended',access=0x100080,disposition=1);denied(lambda:query(no_ea,15),0xc0000022);denied(lambda:seteas(no_ea,ea(b'x',b'y')),0xc0000022);no_ea.close()
        denied(lambda:seteas(extended,ea(b'bad/name',b'value')),0xc0000050)
        malformed=bytearray(ea(b'x',b'y'));struct.pack_into('<I',malformed,0,4)
        denied(lambda:seteas(extended,bytes(malformed)),0xc0000050)
        assert read_eas(extended)=={b'EXAMPLE':(0,b'updated')};extended.close()
        c.disconnect();f.stop();f.start();c,s,t=connect()
        h=create(t,'renamed',disposition=1);assert readattrs(h)==0x2002
        assert struct.unpack_from('<QQQQ',query(h,4))==timestamps
        extended=create(t,'extended',disposition=1);assert read_eas(extended)=={b'EXAMPLE':(0,b'updated')}
        seteas(extended,ea(b'example',b''));denied(lambda:query(extended,15),0xc0000052);extended.close()
        report['checks'].append('binary extended attributes on CREATE/QUERY/SET, case-insensitive updates, deletion, restart, NEED_EA and access rights; malformed chains reject atomically')
        setinfo(h,deletion);h.close();h=create(t,'renamed');assert readattrs(h)==0x20;h.close()
        report['checks'].append('attributes follow native object across rename/restart, directory invariants hold, replacement object does not inherit stale metadata')
        def mode(handle,value):
            q=SMB2SetInfoRequest();q['info_type']=1;q['file_info_class']=16;q['file_id']=handle.file_id;q['buffer']=struct.pack('<I',value)
            handle.connection.receive(handle.connection.send(q,handle.tree_connect.session.session_id,handle.tree_connect.tree_connect_id))
        h=create(t,'mode',options=0x42);other=create(t,'mode',disposition=1)
        assert struct.unpack('<I',query(h,16))[0]==2 and struct.unpack('<I',query(other,16))[0]==0
        mode(h,6);h.write(b'write through');assert struct.unpack_from('<I',query(h,18),88)[0]==6
        for invalid in (8,16,32,48,0x1000,0xffffffff):denied(lambda:mode(h,invalid),0xc000000d)
        assert struct.unpack('<I',query(h,16))[0]==6
        mode(h,0);assert struct.unpack('<I',query(h,16))[0]==0
        h.close();other.close()
        ignored=create(t,'sync-flags-ignored',options=0x70);assert struct.unpack('<I',query(ignored,16))[0]==0;ignored.close()
        report['checks'].append('per-open mode CREATE/QUERY/SET and FileAllInformation agreement, write-through writes, independent handles, invalid synchronous/immutable modes and SMB2 ignored synchronous CREATE flags')
        report['status']='passed'
    except Exception:report['error']=traceback.format_exc();raise
    finally:
        for c in clients:
            try:c.disconnect(close=False)
            except Exception:pass
        f.close();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report));return 0
if __name__=='__main__':raise SystemExit(run())
