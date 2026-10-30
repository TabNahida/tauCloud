"""Disposable test-only SMB relay; records protocol metadata, never auth blobs."""
import select
import socket
import threading
import time

class HeaderProxy:
    def __init__(self, target):
        self.target=target;self.trace=[];self.stop=threading.Event();self.sockets=[]
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen(8)
        self.port=self.listener.getsockname()[1]
        self.thread=threading.Thread(target=self.accept,daemon=True);self.thread.start()

    def record(self,direction,buf,ntlm_state):
        while len(buf)>=4:
            size=int.from_bytes(buf[1:4],'big')
            if size>1024*1024+52:buf.clear();return
            if len(buf)<size+4:return
            frame=bytes(buf[4:4+size]);del buf[:4+size]
            if len(self.trace)>=512:continue
            item=dict(direction=direction,size=size,magic=frame[:4].hex(),time=time.monotonic())
            if frame[:4]==b'\xfeSMB' and len(frame)>=64:
                command=int.from_bytes(frame[12:14],'little')
                item.update(command=command,flags=int.from_bytes(frame[16:20],'little'),
                            message_id=int.from_bytes(frame[24:32],'little'),
                            credit_charge=int.from_bytes(frame[6:8],'little'),credits=int.from_bytes(frame[14:16],'little'))
                if direction=='response':item['status']=hex(int.from_bytes(frame[8:12],'little'))
                if command==1:
                    # Safe negotiation diagnostics only. Never retain the
                    # challenge, response proof, session key or raw auth token.
                    start=frame.find(b'NTLMSSP\0',64)
                    if start>=0:
                        token=frame[start:];kind=int.from_bytes(token[8:12],'little')
                        item['ntlm_type']=kind
                        flag_at={1:12,2:20,3:60}.get(kind)
                        if flag_at is not None and len(token)>=flag_at+4:
                            flags=int.from_bytes(token[flag_at:flag_at+4],'little');item['ntlm_flags']=hex(flags)
                        if kind==2 and len(token)>=48:
                            n=int.from_bytes(token[40:42],'little');off=int.from_bytes(token[44:48],'little')
                            if off>=48 and n<=4096 and off+n<=len(token):
                                ntlm_state['target']=self.av_pairs(token[off:off+n])
                        if kind==3 and len(token)>=64:
                            off=int.from_bytes(token[24:28],'little');size=int.from_bytes(token[20:22],'little')
                            micpos=72 if flags&0x02000000 else 64
                            item['ntlm_mic_present']=off>=micpos+16 and len(token)>=micpos+16 and any(token[micpos:micpos+16])
                            item['ntlm_response_bytes']=size
                            if size>=48 and off+size<=len(token):
                                blob=token[off+16:off+size];pairs=self.av_pairs(blob[28:])
                                offered=ntlm_state.get('target',{})
                                item['ntlm_target_echo']={str(k):pairs.get(k)==offered.get(k) for k in (1,2,7)}
                                item['ntlm_av_mic_flag']=bool(int.from_bytes(pairs.get(6,b''),'little')&2)
                                item['ntlm_channel_bindings_zero']=10 not in pairs or pairs[10]==bytes(16)
                                if len(offered.get(7,b''))==8:
                                    item['ntlm_clock_delta_ms']=(int.from_bytes(blob[8:16],'little')-int.from_bytes(offered[7],'little'))//10000
                            for label,index in [('fixture_domain',28),('fixture_user',36)]:
                                length=int.from_bytes(token[index:index+2],'little');offset=int.from_bytes(token[index+4:index+8],'little')
                                if length<=128 and offset>=64 and offset+length<=len(token):
                                    item[label]=token[offset:offset+length].decode('utf-16-le',errors='replace')
                elif direction=='request' and command==5 and len(frame)>=120:
                    item.update(access=hex(int.from_bytes(frame[88:92],'little')),
                                attributes=hex(int.from_bytes(frame[92:96],'little')),
                                disposition=int.from_bytes(frame[100:104],'little'),
                                options=hex(int.from_bytes(frame[104:108],'little')),
                                name_bytes=int.from_bytes(frame[110:112],'little'))
                    off=int.from_bytes(frame[108:110],'little');n=item['name_bytes']
                    if n<=512 and off>=120 and off+n<=len(frame):
                        item['fixture_path']=frame[off:off+n].decode('utf-16-le',errors='replace')
                elif direction=='request' and command in (16,17) and len(frame)>=96:
                    item.update(info_type=frame[66],info_class=frame[67],buffer_length=int.from_bytes(frame[68:72],'little'))
                if command==0 and len(frame)>=100:
                    if direction=='request':
                        count=int.from_bytes(frame[66:68],'little')
                        item['dialects']=[hex(int.from_bytes(frame[i:i+2],'little')) for i in range(100,min(100+count*2,len(frame)),2)]
                    else:item['dialect']=hex(int.from_bytes(frame[68:70],'little'))
            self.trace.append(item)

    @staticmethod
    def av_pairs(data):
        result={};pos=0
        while pos+4<=len(data) and len(result)<16:
            kind=int.from_bytes(data[pos:pos+2],'little');n=int.from_bytes(data[pos+2:pos+4],'little');pos+=4
            if kind==0 or pos+n>len(data):break
            result[kind]=data[pos:pos+n];pos+=n
        return result

    def accept(self):
        while not self.stop.is_set():
            try:
                if not select.select([self.listener],[],[],0.2)[0]:continue
                client,_=self.listener.accept()
                upstream=socket.create_connection(('127.0.0.1',self.target),timeout=10)
                self.sockets.extend([client,upstream])
                threading.Thread(target=self.relay,args=(client,upstream),daemon=True).start()
            except OSError:
                if not self.stop.is_set():self.trace.append(dict(error='relay_accept_failed'))
                break

    def relay(self,client,upstream):
        buffers={client:bytearray(),upstream:bytearray()};ntlm_state={}
        try:
            while not self.stop.is_set():
                for src in select.select([client,upstream],[],[],0.2)[0]:
                    data=src.recv(65536)
                    if not data:return
                    buffers[src].extend(data);self.record('request' if src is client else 'response',buffers[src],ntlm_state)
                    (upstream if src is client else client).sendall(data)
        except OSError:pass
        finally:client.close();upstream.close()

    def close(self):
        self.stop.set();self.thread.join(timeout=2);self.listener.close()
        for sock in self.sockets:sock.close()
