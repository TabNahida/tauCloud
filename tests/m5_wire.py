"""Small hostile-wire probes; real NTLM tokens come from pyspnego."""
import socket, struct, hmac, hashlib, uuid
import spnego
from spnego._ntlm_raw.crypto import ntowfv1, ntowfv2, rc4k

def retime_authenticate(token, negotiate_token, challenge, session_key, user, password, delta_ms):
    """Re-sign an independent client's response with a client-clock timestamp."""
    token=bytearray(token)
    size,_,off=struct.unpack_from('<HHI',token,20)
    blob=bytearray(token[off+16:off+size])
    stamp=struct.unpack_from('<Q',blob,8)[0]
    struct.pack_into('<Q',blob,8,(stamp+delta_ms*10000)&((1<<64)-1))
    response_key=ntowfv2(user,ntowfv1(password),'TAUCLOUD')
    proof=hmac.new(response_key,challenge[24:32]+blob,hashlib.md5).digest()
    token[off:off+size]=proof+blob
    flags=struct.unpack_from('<I',token,60)[0]
    if flags&0x40000000:
        n,_,start=struct.unpack_from('<HHI',token,52);assert n==16
        base=hmac.new(response_key,proof,hashlib.md5).digest()
        token[start:start+n]=rc4k(base,session_key)
    else:
        session_key=hmac.new(response_key,proof,hashlib.md5).digest()
    micpos=72 if flags&0x2000000 else 64
    token[micpos:micpos+16]=bytes(16)
    token[micpos:micpos+16]=hmac.new(session_key,negotiate_token+challenge+token,hashlib.md5).digest()
    return token,session_key

def header(cmd,mid=0,sid=0,tid=0,flags=0):
    return struct.pack('<4sHHIHHIIQIIQ16s',b'\xfeSMB',64,1,0,cmd,1,flags,0,mid,0,tid,sid,b'\0'*16)
def exact(sock,n):
    out=b''
    while len(out)<n:
        part=sock.recv(n-len(out))
        if not part:raise EOFError('SMB peer closed')
        out+=part
    return out
def exchange(sock,packet):
    sock.sendall(len(packet).to_bytes(4,'big')+packet)
    n=int.from_bytes(exact(sock,4),'big');assert n<=1024*1024
    return exact(sock,n)
def status(packet):return struct.unpack_from('<I',packet,8)[0]
def negotiate(sock):
    body=struct.pack('<HHHHI16sQH',36,1,3,0,0,uuid.uuid4().bytes,0,0x210)
    r=exchange(sock,header(0)+body);assert status(r)==0 and struct.unpack_from('<H',r,68)[0]==0x210

def authenticate(port,user,password,tamper=None,timestamp_delta_ms=None):
    sock=socket.create_connection(('127.0.0.1',port),timeout=10);negotiate(sock)
    context=spnego.client(username='TAUCLOUD\\'+user,password=password,protocol='ntlm',hostname='127.0.0.1',service='cifs')
    def setup(token,mid,sid):return header(1,mid,sid)+struct.pack('<HBBIIHHQ',25,0,1,0,0,88,len(token),0)+token
    negotiate_token=context.step()
    r=exchange(sock,setup(negotiate_token,1,0));assert status(r)==0xc0000016
    sid=struct.unpack_from('<Q',r,40)[0];off,n=struct.unpack_from('<HH',r,68);challenge=r[off:off+n]
    token=bytearray(context.step(challenge))
    key=context.session_key
    if timestamp_delta_ms is not None:
        token,key=retime_authenticate(token,negotiate_token,challenge,key,user,password,timestamp_delta_ms)
    if tamper=='mic':
        flags=struct.unpack_from('<I',token,60)[0];token[72 if flags&0x2000000 else 64]^=1
    elif tamper=='proof':token[struct.unpack_from('<I',token,24)[0]]^=1
    r=exchange(sock,setup(token,2,sid))
    if tamper:
        assert status(r)==0xc000006d,hex(status(r));sock.close();return
    assert status(r)==0,hex(status(r))
    assert hmac.new(key,r[:48]+b'\0'*16+r[64:],hashlib.sha256).digest()[:16]==r[48:64]
    return sock,sid,key

def signed(packet,key):return packet[:48]+hmac.new(key,packet[:48]+b'\0'*16+packet[64:],hashlib.sha256).digest()[:16]+packet[64:]
def rejected_connection(sock,packet):
    try:exchange(sock,packet);raise AssertionError('malformed packet accepted')
    except (EOFError,ConnectionResetError,BrokenPipeError):pass
    finally:sock.close()

def hostile(port,password):
    sock,sid,key=authenticate(port,'wire',password)
    unknown=sid^0x100000000
    reply=exchange(sock,signed(header(2,3,unknown,flags=8)+struct.pack('<HH',4,0),key))
    assert status(reply)==0xc0000203 and struct.unpack_from('<Q',reply,40)[0]==unknown
    assert not struct.unpack_from('<I',reply,16)[0]&8
    # The rejected LOGOFF cannot affect the actual authenticated session.
    reply=exchange(sock,signed(header(13,4,sid,flags=8)+struct.pack('<HH',4,0),key))
    assert status(reply)==0 and signed(reply,key)[48:64]==reply[48:64];sock.close()
    # Non-identical client clocks still authenticate with correct proof/MIC;
    # excessive clock skew remains a failure, independently of cryptography.
    for delta in (-1000,1000,-290000,290000):
        sock,sid,key=authenticate(port,'wire',password,timestamp_delta_ms=delta)
        reply=exchange(sock,signed(header(13,3,sid,flags=8)+struct.pack('<HH',4,0),key))
        assert status(reply)==0;sock.close()
    for delta in (-301000,301000):
        authenticate(port,'wire',password,'clock',timestamp_delta_ms=delta)
    authenticate(port,'wire',password,'mic');authenticate(port,'wire',password,'proof')
    sock,sid,key=authenticate(port,'wire',password)
    rejected_connection(sock,header(13,3,sid)+struct.pack('<HH',4,0))
    sock,sid,key=authenticate(port,'wire',password)
    packet=bytearray(signed(header(13,3,sid,flags=8)+struct.pack('<HH',4,0),key));packet[-1]^=1
    rejected_connection(sock,packet)
    for data in (b'\0\x10\0\x01',b'\0\0\0\x3f'+b'x'*63,b'\0\0\0\x40'+b'x'*64):
        sock=socket.create_connection(('127.0.0.1',port),timeout=10);sock.sendall(data)
        try:assert sock.recv(1)==b''
        except ConnectionResetError:pass
        finally:sock.close()
    # Compound offsets are checked before execution, including an unaligned offset.
    sock=socket.create_connection(('127.0.0.1',port),timeout=10);packet=bytearray(header(0)+b'\0'*100);struct.pack_into('<I',packet,20,65);rejected_connection(sock,packet)

def dce(kind,body,call=1):return struct.pack('<BBBBIHHI',5,0,kind,3,0x10,16+len(body),0,call)+body

def shares(pipe,transceive=False):
    def request(packet):
        if not transceive:
            pipe.write(packet);return pipe.read(0,65535)
        from smbprotocol.ioctl import SMB2IOCTLRequest,SMB2IOCTLResponse
        q=SMB2IOCTLRequest();q['ctl_code']=0x11c017;q['file_id']=pipe.file_id;q['max_output_response']=65535;q['flags']=1;q['buffer']=packet
        pending=pipe.connection.send(q,pipe.tree_connect.session.session_id,pipe.tree_connect.tree_connect_id)
        response=pipe.connection.receive(pending);r=SMB2IOCTLResponse();r.unpack(response['data'].get_value());return r['buffer'].get_value()

    # NDR32 bind to the MS-SRVS v3.0 interface; all data travels in the signed SMB session.
    abstract=bytes.fromhex('c84f324b7016d30112785a47bf6ee18803000000')
    transfer=bytes.fromhex('045d888aeb1cc9119fe808002b10486002000000')
    bind=dce(11,struct.pack('<HHIB3xHBB',65535,65535,0,1,0,1,0)+abstract+transfer)
    ack=request(bind);assert ack[2]==12
    # ServerName NULL, level/switch 1, non-null empty level-1 container, no resume.
    stub=struct.pack('<IIIIIIII',0,1,1,0x20000,0,0,0xffffffff,0)
    reply=request(dce(0,struct.pack('<IHH',len(stub),0,15)+stub,2))
    assert reply[2]==2 and struct.unpack_from('<I',reply,len(reply)-4)[0]==0
    data=reply[24:];level,tag,ptr,count,buffer=struct.unpack_from('<IIIII',data)
    assert level==tag==1
    names=[];pos=20
    if count:
        assert struct.unpack_from('<I',data,pos)[0]==count;pos+=4
        rows=[struct.unpack_from('<III',data,pos+12*i) for i in range(count)];pos+=count*12
        for row in rows:
            values=[]
            for _ in range(2):
                maximum,off,n=struct.unpack_from('<III',data,pos);pos+=12;assert off==0 and n<=maximum
                values.append(data[pos:pos+n*2].decode('utf-16-le').rstrip('\0'));pos=(pos+n*2+3)//4*4
            names.append(values[0]);assert row[1]==0
    return names
