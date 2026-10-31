#!/usr/bin/env python3
"""Disposable process-plugin lifecycle and typed Docker transport contracts."""
import argparse, hashlib, json, os, shutil, signal, socket, ssl, struct, threading, time, traceback, uuid
from pathlib import Path
from m3_integration import Fixture
from m1_integration import wait

class Engine:
    def __init__(self, f, tls=False):
        self.mode='normal';self.calls=[];self.closed=False;self.os='linux';self.maximum='1.52';self.minimum='1.44'
        self.tls=tls;self.pipe=os.name=='nt' and not tls
        if self.pipe:
            import ctypes
            from ctypes import wintypes as w
            self.ctypes=ctypes;self.k=ctypes.WinDLL('kernel32',use_last_error=True)
            self.k.CreateNamedPipeW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,ctypes.c_void_p];self.k.CreateNamedPipeW.restype=w.HANDLE
            self.k.ConnectNamedPipe.argtypes=[w.HANDLE,ctypes.c_void_p];self.k.ConnectNamedPipe.restype=w.BOOL
            self.k.ReadFile.argtypes=[w.HANDLE,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD),ctypes.c_void_p];self.k.ReadFile.restype=w.BOOL
            self.k.WriteFile.argtypes=self.k.ReadFile.argtypes;self.k.WriteFile.restype=w.BOOL
            self.k.CloseHandle.argtypes=[w.HANDLE];self.k.DisconnectNamedPipe.argtypes=[w.HANDLE]
            self.k.FlushFileBuffers.argtypes=[w.HANDLE]
            self.path=r'\\.\pipe\tc-docker-'+uuid.uuid4().hex
            self.endpoint=dict(id='engine',transport='pipe',path=self.path,platform='linux-vm',permissions=['docker.read','docker.logs','docker.control'])
            self.ready=threading.Event();self.thread=threading.Thread(target=self.pipe_loop,daemon=True);self.thread.start();assert self.ready.wait(5)
        else:
            self.sock=socket.socket(socket.AF_INET if tls else socket.AF_UNIX,socket.SOCK_STREAM)
            if tls:
                self.sock.bind(('127.0.0.1',0));self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self.context.load_cert_chain(f.state/'tls-cert.pem',f.state/'tls-key.pem')
                self.context.load_verify_locations(f.state/'tls-cert.pem');self.context.verify_mode=ssl.CERT_REQUIRED
                self.endpoint=dict(id='tls',transport='tls',address='127.0.0.1',port=self.sock.getsockname()[1],server_name='localhost',ca=str(f.state/'tls-cert.pem'),certificate=str(f.state/'tls-cert.pem'),key=str(f.state/'tls-key.pem'),platform='remote-linux',permissions=['docker.read','docker.logs','docker.control'])
            else:
                self.path=str(f.base/'docker.sock');self.sock.bind(self.path)
                self.endpoint=dict(id='engine',transport='unix',path=self.path,platform='linux-native',permissions=['docker.read','docker.logs','docker.control'])
            self.sock.listen(16);self.sock.settimeout(.2)
            self.thread=threading.Thread(target=self.loop,daemon=True);self.thread.start()
    def answer(self,request):
        method,path,_=request.split(b'\r\n',1)[0].decode().split(' ');self.calls.append((method,path))
        if path=='/version':data=dict(ApiVersion=self.maximum,MinAPIVersion=self.minimum)
        elif path.endswith('/info'):data=dict(OSType=self.os,Name='disposable-engine',ServerVersion='fixture')
        else:
            if self.mode=='disconnect':return b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}'
            if self.mode=='oversized':return b'HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n'
            if self.mode=='ambiguous':return b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}'
            if self.mode=='redirect':return b'HTTP/1.1 302 Found\r\nLocation: http://unapproved.invalid/\r\nContent-Length: 0\r\n\r\n'
            if self.mode=='forbidden':return b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'
            if self.mode=='slow':time.sleep(4);return b''
            if self.mode=='deep':return self.response(b'{\"x\":'*40+b'0'+b'}'*40)
            if '/logs?' in path:return self.response(b'\x01\0\0\0'+struct.pack('>I',6)+b'hello\n',content_type='application/vnd.docker.raw-stream')
            if '/stats?' in path:data=dict(cpu_stats=dict(cpu_usage=dict(total_usage=123)),memory_stats=dict(usage=456))
            elif path.endswith('/volumes'):data=dict(Volumes=[dict(Name='v',Mountpoint='/var/lib/docker/volumes/v')],Warnings=[])
            elif path.endswith('/networks'):data=[dict(Id='n',Name='bridge',Driver='bridge')]
            elif path.endswith('/images/json'):data=[dict(Id='i',RepoTags=['fixture:1'])]
            elif path.endswith('/containers/json?all=true'):data=[dict(Id='c',Names=['/fixture'],State='running',Mounts=[dict(Source='/engine/path')])]
            elif method in ('POST','DELETE'):return b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n'
            else:raise AssertionError((method,path))
        return self.response(json.dumps(data).encode())
    def response(self,payload,content_type='application/json'):
        if self.mode=='chunked':return ('HTTP/1.1 200 OK\r\nContent-Type: '+content_type+'\r\nTransfer-Encoding: chunked\r\n\r\n').encode()+('%x\r\n'%len(payload)).encode()+payload+b'\r\n0\r\n\r\n'
        return ('HTTP/1.1 200 OK\r\nContent-Type: '+content_type+'\r\nContent-Length: '+str(len(payload))+'\r\n\r\n').encode()+payload
    def handle(self,c):
        try:
            c.settimeout(5)
            if self.tls:c=self.context.wrap_socket(c,server_side=True)
            data=b''
            while b'\r\n\r\n' not in data:data+=c.recv(8192)
            c.sendall(self.answer(data))
        except (OSError,ssl.SSLError):pass
        finally:c.close()
    def loop(self):
        while not self.closed:
            try:c,_=self.sock.accept()
            except socket.timeout:continue
            except OSError:break
            threading.Thread(target=self.handle,args=(c,),daemon=True).start()
    def pipe_loop(self):
        import ctypes
        from ctypes import wintypes as w
        def serve(handle):
            try:
                data=b'';buf=ctypes.create_string_buffer(8192);n=w.DWORD()
                while b'\r\n\r\n' not in data:
                    if not self.k.ReadFile(handle,buf,len(buf),ctypes.byref(n),None):return
                    data+=buf.raw[:n.value]
                answer=self.answer(data)
                self.k.WriteFile(handle,answer,len(answer),ctypes.byref(n),None);self.k.FlushFileBuffers(handle)
            finally:self.k.DisconnectNamedPipe(handle);self.k.CloseHandle(handle)
        pending=self.k.CreateNamedPipeW(self.path,3,0,16,65536,65536,0,None);self.ready.set()
        while not self.closed:
            ok=self.k.ConnectNamedPipe(pending,None)
            if not ok and ctypes.get_last_error()!=535:break
            current=pending
            pending=self.k.CreateNamedPipeW(self.path,3,0,16,65536,65536,0,None)
            threading.Thread(target=serve,args=(current,),daemon=True).start()
        self.k.CloseHandle(pending)
    def close(self):
        self.closed=True
        if not self.pipe:self.sock.close()
        else:
            try:
                with open(self.path,'r+b',buffering=0):pass
            except OSError:pass
        self.thread.join(2)

def package(f,id,version='1.0.0',kind='generic',caps=None):
    path=f.base/(id+'-'+version);path.mkdir()
    name='taucloud_docker' if kind=='docker' else 'taucloud_m8_plugin_fixture'
    name+=f.suffix;shutil.copy2(f.binary/name,path/name)
    manifest=dict(schema=1,id=id,version=version,ipc_version=1,kind=kind,entry=name,files={name:hashlib.sha256((path/name).read_bytes()).hexdigest()},capabilities=caps or ['plugin.invoke'])
    (path/'manifest.json').write_text(json.dumps(manifest));return path

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bin',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    checks=[];f=Fixture(a.bin,512);engines=[];report=dict(status='failed',checks=checks)
    def api(op,b=None,expected=200,token=None):return f.api('plugins/'+op,token or f.admin,b,expected)
    def installed(id):return next(x for x in api('list')['plugins'] if x['id']==id)
    def install(path):
        plan=api('plan',dict(source=str(path)));m=plan['manifest']
        return api('install',dict(source=str(path),approved_digest=plan['digest'],approved_permissions=m['capabilities'],trusted_code=True))
    def enable(id):api('enable',dict(id=id));wait(lambda:installed(id)['status']=='running',timeout=20)
    def approve(e):
        plan=api('engine-plan',dict(endpoint=e));api('engine-approve',dict(endpoint=e,approved_digest=plan['digest']))
    def invoke(op,expected=200,**kwargs):return api('invoke',dict(id='docker',request=dict(engine=kwargs.pop('engine','engine'),operation=op,**kwargs)),expected)
    try:
        alice=f.api('auth/login',data=dict(username='alice',password=f.password,scope='read'))['token']
        api('list',expected=403,token=alice)
        admin_read=f.api('auth/login',data=dict(username='admin',password=f.password,scope='read'))['token']
        api('list',expected=403,token=admin_read)
        nested={}
        for _ in range(80):nested={'deep':nested}
        api('plan',nested,400)
        path=package(f,'echo');plan=api('plan',dict(source=str(path)));assert plan['os_confinement_verified'] is False
        assert api('install',dict(source=str(path)),503)['error']['code']=='approval_required'
        install(path);assert installed('echo')['enabled'] is False;enable('echo')
        answer=api('invoke',dict(id='echo',request=dict(value='persist')));assert answer['echo']==dict(value='persist') and answer['private_keys']==2 and answer['has_engines'] is False
        data=f.state/'plugins/state/echo/data/last.json';assert json.loads(data.read_text())==dict(value='persist')
        p2=package(f,'echo','1.1.0');install(p2);enable('echo');assert data.exists()
        plan=api('rollback-plan',dict(id='echo'))
        assert api('rollback',dict(id='echo'),503)['error']['code']=='approval_required'
        api('rollback',dict(id='echo',approved_digest=plan['digest'],approved_permissions=plan['manifest']['capabilities'],trusted_code=True));assert installed('echo')['version']=='1.0.0';enable('echo')
        instance=f.state/'plugins/state/echo/plugin.instance.json';before=json.loads(instance.read_text())
        manager_pid=f.ctl('status')['plugins']['identity']['pid']
        os.kill(manager_pid,signal.SIGTERM if os.name=='nt' else signal.SIGKILL)
        wait(lambda:f.ctl('status')['plugins']['status']=='running' and f.ctl('status')['plugins']['identity']['pid']!=manager_pid)
        wait(lambda:installed('echo')['status']=='running')
        after=json.loads(instance.read_text());assert (before['pid'],before['birth'])==(after['pid'],after['birth'])
        assert api('invoke',dict(id='echo',request=dict(value='adopted')))['echo']['value']=='adopted'
        f.stop();f.start();wait(lambda:installed('echo')['status']=='running');assert data.exists()
        slow=package(f,'slow');install(slow)
        (f.state/'plugins/state/slow/configuration/delay.json').write_text('{"ms":1500}')
        api('enable',dict(id='slow'))
        def starting():
            record=json.loads((f.state/'plugins/registry.json').read_text())['plugins']['slow']
            return record['status']=='starting' and record['identity'] is not None
        wait(starting)
        spawned=json.loads((f.state/'plugins/registry.json').read_text())['plugins']['slow']['identity']
        manager_pid=f.ctl('status')['plugins']['identity']['pid']
        os.kill(manager_pid,signal.SIGTERM if os.name=='nt' else signal.SIGKILL)
        wait(lambda:f.ctl('status')['plugins']['status']=='running' and f.ctl('status')['plugins']['identity']['pid']!=manager_pid)
        wait(lambda:installed('slow')['status']=='running')
        adopted=json.loads((f.state/'plugins/state/slow/plugin.instance.json').read_text())
        assert (spawned['pid'],spawned['birth'])==(adopted['pid'],adopted['birth'])
        api('uninstall',dict(id='slow'))
        checks.append('admin-only API, explicit hash/permission/trusted-code approval, private IPC keys, install/enable/upgrade/approved rollback and restart preserve data; manager crash adopts the same verified running or still-starting worker')
        bad=package(f,'bad');m=json.loads((bad/'manifest.json').read_text());m['files']['../escape']='0'*64;(bad/'manifest.json').write_text(json.dumps(m));api('plan',dict(source=str(bad)),400)
        tampered=package(f,'tampered');(tampered/('taucloud_m8_plugin_fixture'+f.suffix)).write_bytes(b'changed');assert api('plan',dict(source=str(tampered)),503)['error']['code']=='package_hash_mismatch'
        if os.name!='nt':
            linked=package(f,'linked');entry=linked/('taucloud_m8_plugin_fixture'+f.suffix);entry.unlink();entry.symlink_to(f.binary/entry.name);api('plan',dict(source=str(linked)),503)
        checks.append('invalid paths, changed hashes and platform-supported symlink escapes reject before activation')
        crash=f.state/'plugins/state/echo/configuration/crash';crash.write_text('fixture')
        api('invoke',dict(id='echo',request=dict(crash=True)),503)
        wait(lambda:installed('echo')['status']=='crash_loop',timeout=40);assert installed('echo')['failures']==5
        assert f.api('health/ready')['status']=='ready'
        crash.unlink();enable('echo');api('disable',dict(id='echo'));api('uninstall',dict(id='echo'));assert data.exists()
        checks.append('worker crash backoff/quarantine leaves management available; explicit recovery and uninstall preserve configuration/data')
        docker=package(f,'docker',kind='docker',caps=['plugin.invoke','docker.read']);install(docker);enable('docker')
        engine=Engine(f);engines.append(engine);approve(engine.endpoint)
        install(path);enable('echo')
        assert api('invoke',dict(id='echo',request=dict(value='no-engine-grant')))['has_engines'] is False
        api('disable',dict(id='echo'));api('uninstall',dict(id='echo'))
        for resource in ('containers','images','volumes','networks'):
            r=invoke('inventory',resource=resource);assert len(r['items'])==1 and r['complete']
        before=len(engine.calls);assert invoke('lifecycle',403,id='c',action='start')['error']['code']=='forbidden';assert len(engine.calls)==before
        expanded=package(f,'docker','1.1.0',kind='docker',caps=['plugin.invoke','docker.read','docker.logs','docker.control'])
        plan=api('plan',dict(source=str(expanded)));assert set(plan['added_permissions'])=={'docker.logs','docker.control'}
        api('install',dict(source=str(expanded),approved_digest=plan['digest'],approved_permissions=['plugin.invoke','docker.read'],trusted_code=True),503)
        install(expanded);enable('docker')
        assert invoke('stats',id='c')['memory_stats']['usage']==456
        assert bytes.fromhex(invoke('logs',id='c')['data']).endswith(b'hello\n')
        for action in ('start','stop','restart','remove'):assert invoke('lifecycle',id='c',action=action)['accepted']
        for resource in ('images','volumes','networks'):assert invoke('lifecycle',id='object',resource=resource,action='remove')['accepted']
        invoke('lifecycle',400,id='../escape',action='start')
        api('invoke',dict(id='docker',request=dict(engine='engine',operation='proxy',path='/containers/create')),400)
        invoke('lifecycle',400,id='c',action='create')
        info=invoke('info');assert info['capabilities']['api_version']=='1.52' and info['capabilities']['paths']=='engine-filesystem' and not info['capabilities']['host_path_translation']
        checks.append('typed Docker API negotiation, four inventories, one-shot stats, bounded multiplexed logs and authorized lifecycle; increased grants require approval, arbitrary routes/create/paths reject')
        for mode,code in [('disconnect','engine_disconnected'),('oversized','engine_response_limit'),('ambiguous','bad_http'),('redirect','engine_rejected'),('forbidden','engine_forbidden'),('deep','bad_engine_json')]:
            engine.mode=mode;assert invoke('inventory',503)['error']['code']==code,(mode,code)
        engine.mode='chunked';assert invoke('inventory')['complete'];engine.mode='normal'
        engine.minimum='1.53';assert invoke('info',503)['error']['code']=='engine_api_incompatible';engine.minimum='1.44'
        engine.os='windows';assert invoke('info',503)['error']['code']=='engine_platform_mismatch'
        if os.name=='nt':
            win=dict(engine.endpoint,platform='windows-native');approve(win);assert invoke('info')['capabilities']['os']=='windows';approve(engine.endpoint)
        engine.os='linux'
        missing=dict(engine.endpoint,id='missing',path=engine.endpoint['path']+'-missing');approve(missing);assert invoke('info',503,engine='missing')['error']['code']=='engine_unavailable'
        ro=dict(engine.endpoint,permissions=['docker.read']);approve(ro);assert invoke('logs',403,id='c')['error']['code']=='forbidden';approve(engine.endpoint)
        checks.append('missing/disconnected/forbidden/malformed/oversized engines, chunked responses, API range and OS mismatch; engine-level permissions apply independently of plugin grants')
        tls=Engine(f,True);engines.append(tls);approve(tls.endpoint);assert invoke('inventory',engine='tls')['complete']
        wrong=dict(tls.endpoint,server_name='wrong.invalid');approve(wrong);invoke('info',503,engine='tls');approve(tls.endpoint)
        engine.mode='slow';start=time.monotonic();invoke('inventory',503);assert time.monotonic()-start<6;engine.mode='normal'
        api('engine-remove',dict(id='engine'));assert invoke('info',403)['error']['code']=='forbidden'
        checks.append('mutually authenticated TLS, hostname verification, bounded cancellation deadline and endpoint revocation; Unix socket or Windows named pipe exercised on host')
        report['status']='passed'
    except Exception:report['error']=traceback.format_exc();raise
    finally:
        for e in engines:e.close()
        f.log.flush();report['server_log']=(f.base/'supervisor.log').read_text()[-16384:]
        report['plugin_log']=(f.state/'logs/plugins.jsonl').read_text()[-16384:] if (f.state/'logs/plugins.jsonl').exists() else ''
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');f.close()
    print(json.dumps({k:v for k,v in report.items() if not k.endswith('log')},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
