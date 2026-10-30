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

    def record(self,direction,buf):
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
                elif command==5 and len(frame)>=120:
                    item.update(access=hex(int.from_bytes(frame[88:92],'little')),
                                attributes=hex(int.from_bytes(frame[92:96],'little')),
                                disposition=int.from_bytes(frame[100:104],'little'),
                                options=hex(int.from_bytes(frame[104:108],'little')),
                                name_bytes=int.from_bytes(frame[110:112],'little'))
                    off=int.from_bytes(frame[108:110],'little');n=item['name_bytes']
                    if n<=512 and off>=120 and off+n<=len(frame):
                        item['fixture_path']=frame[off:off+n].decode('utf-16-le',errors='replace')
                elif command in (16,17) and len(frame)>=96:
                    item.update(info_type=frame[66],info_class=frame[67],buffer_length=int.from_bytes(frame[68:72],'little'))
                if command==0 and len(frame)>=100:
                    if direction=='request':
                        count=int.from_bytes(frame[66:68],'little')
                        item['dialects']=[hex(int.from_bytes(frame[i:i+2],'little')) for i in range(100,min(100+count*2,len(frame)),2)]
                    else:item['dialect']=hex(int.from_bytes(frame[68:70],'little'))
            self.trace.append(item)

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
        buffers={client:bytearray(),upstream:bytearray()}
        try:
            while not self.stop.is_set():
                for src in select.select([client,upstream],[],[],0.2)[0]:
                    data=src.recv(65536)
                    if not data:return
                    buffers[src].extend(data);self.record('request' if src is client else 'response',buffers[src])
                    (upstream if src is client else client).sendall(data)
        except OSError:pass
        finally:client.close();upstream.close()

    def close(self):
        self.stop.set();self.thread.join(timeout=2);self.listener.close()
        for sock in self.sockets:sock.close()
