#!/usr/bin/env python3
"""Disposable TLS WebDAV acceptance, optionally with independent litmus 0.18."""
import argparse, base64, shutil, sqlite3, threading, hashlib, http.client, json, os, signal, socket, ssl, subprocess, tempfile, time, uuid
from pathlib import Path
from m1_integration import wait

class Fixture:
    password = 'M3-disposable-password-123!'
    def __init__(self, binary, memory=256, seed_identity=None):
        self.binary = Path(binary).resolve()
        self.suffix = '.exe' if os.name == 'nt' else ''
        self.tmp = tempfile.TemporaryDirectory(prefix='tc3-')
        self.base = Path(self.tmp.name)
        self.state = self.base / 'state'
        self.root = self.base / 'files'
        self.root.mkdir()
        ports = []
        for _ in range(2):
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0)); ports.append(s.getsockname()[1])
        self.port, self.davport = ports
        self.ctl('init', '--port', str(self.port))
        config = json.loads((self.state / 'config.json').read_text())
        config.update(dav_port=self.davport, memory_mb=memory)
        (self.state / 'config.json').write_text(json.dumps(config))
        self.context = ssl.create_default_context(cafile=str(self.state / 'tls-cert.pem'))
        self.log = (self.base / 'supervisor.log').open('w')
        self.start()
        if seed_identity is None:
            self.ctl('bootstrap', '--username', 'admin', '--password-stdin', stdin=self.password+'\n')
            self.admin = self.api('auth/login', data=dict(username='admin', password=self.password, scope='admin'))['token']
            self.api('users', self.admin, dict(username='alice', password=self.password))
            self.api('users', self.admin, dict(username='bob', password=self.password))
        else:
            # Test-only offline provisioning for an emulated native-client
            # fixture. Ordinary acceptance always exercises bootstrap/login.
            self.stop();self.admin=seed_identity(self.state);self.start()
        self.api('storage-roots', self.admin, dict(id='data', path=str(self.root)))
        self.api('spaces', self.admin, dict(id='alice', root='data', path='alice', owner='alice', quota=2*1024**3))
        self.api('shares', self.admin, dict(id='dav', space='alice', exposures={'webdav':'rw'}))
        self.auth = 'Basic ' + base64.b64encode(('alice:'+self.password).encode()).decode()
        self.url = f'https://127.0.0.1:{self.davport}/dav/dav/'
    def ctl(self, *args, stdin=None, ok=True):
        p = subprocess.run([str(self.binary/('taucloud_ctl'+self.suffix)), '--state', str(self.state), *args],input=stdin,text=True,capture_output=True,timeout=30)
        assert (p.returncode == 0) == ok, (args,p.stdout,p.stderr)
        return json.loads(p.stdout) if ok else p.stderr
    def start(self):
        self.process = subprocess.Popen([str(self.binary/('taucloud_supervisor'+self.suffix)), '--state', str(self.state)],stdout=self.log,stderr=self.log)
        wait(lambda: self.api('health/ready')['status']=='ready')
        wait(lambda: all(v['status']=='running' for v in self.ctl('status').values()))
    def stop(self):
        self.ctl('stop'); self.process.wait(timeout=25)
    def close(self):
        try:
            if self.process.poll() is None: self.stop()
        finally:
            self.log.close(); self.tmp.cleanup()
    def api(self,path,token=None,data=None,expected=200):
        headers={'Content-Type':'application/json','Idempotency-Key':uuid.uuid4().hex}
        if token: headers['Authorization']='Bearer '+token
        c=http.client.HTTPSConnection('127.0.0.1',self.port,context=self.context,timeout=15)
        try:
            c.request('POST' if data is not None else 'GET','/api/v1/'+path,None if data is None else json.dumps(data),headers)
            r=c.getresponse(); b=r.read(); assert r.status==expected,(path,r.status,b)
            return json.loads(b)
        finally: c.close()
    def dav(self,method,path='',body=None,headers=None,status=None):
        h={'Authorization':self.auth}; h.update(headers or {})
        c=http.client.HTTPSConnection('127.0.0.1',self.davport,context=self.context,timeout=15)
        try:
            c.request(method,'/dav/dav/'+path,body,h); r=c.getresponse(); b=r.read()
            assert status is None or r.status==status,(method,path,r.status,b[:2000])
            return r.status,dict((k.lower(),v) for k,v in r.getheaders()),b
        finally: c.close()

def run(args):
    checks=[]; reports={}; sampling=None;sampler=None;f=Fixture(args.bin,512 if args.sanitizers else 256)
    try:
        f.stop()
        for role in ('file','file_1','file_2','file_3'):
            db=sqlite3.connect(f.state/(role+'.db'))
            try: db.executescript('DROP TABLE dav_properties; DROP TABLE dav_locks; PRAGMA user_version=1;');db.commit()
            finally: db.close()
        keys=json.loads((f.state/'ipc-keys.json').read_text());keys.pop('webdav');(f.state/'ipc-keys.json').write_text(json.dumps(keys))
        f.start()
        assert all((f.state/(role+'.pre-v2.db')).exists() for role in ('file','file_1','file_2','file_3'))
        checks.append('M2 file schema migrates transactionally with backups; supervisor adds the new DAV role key')
        f.dav('OPTIONS',status=200)
        f.dav('PUT','first.txt',b'hello',status=201)
        initial_etag=f.dav('HEAD','first.txt',status=200)[1]['etag']
        assert f.dav('GET','first.txt',status=200)[2]==b'hello'
        assert f.dav('HEAD','first.txt',status=200)[1]['etag']==initial_etag
        f.dav('DELETE','first.txt',headers={'If-Match':initial_etag},status=204)
        f.dav('MKCOL','tree',status=201)
        f.dav('MKCOL','tree/sub',status=201)
        f.dav('PUT','tree/sub/%E4%B8%AD%E6%96%87',b'unicode',status=201)
        f.dav('DELETE','tree',headers={'Depth':'0'},status=400)
        f.dav('COPY','tree',headers={'Destination':f.url+'copied'},status=201)
        f.dav('MOVE','copied',headers={'Destination':f.url+'moved'},status=201)
        assert f.dav('GET','moved/sub/%E4%B8%AD%E6%96%87',status=200)[2]==b'unicode'
        f.dav('PUT','plain',b'old',status=201)
        f.dav('COPY','tree',headers={'Destination':f.url+'plain'},status=204)
        f.dav('DELETE','plain',status=204)
        f.dav('DELETE','moved',status=204)
        f.dav('DELETE','tree',status=204)
        checks.append('TLS Basic auth, UTF-8 names, recursive collection COPY/MOVE/DELETE and type-changing overwrite')
        curl=shutil.which('curl.exe' if os.name=='nt' else 'curl')
        if curl:
            version=subprocess.run([curl,'--version'],capture_output=True,text=True,check=True).stdout.splitlines()[0]
            command=[curl,'--silent','--show-error','--fail','--cacert',str(f.state/'tls-cert.pem'),'--user','alice:'+f.password]
            subprocess.run(command+['--upload-file','-',f.url+'curl-client'],input=b'curl-roundtrip',capture_output=True,check=True)
            assert subprocess.run(command+[f.url+'curl-client'],capture_output=True,check=True).stdout==b'curl-roundtrip'
            reports['curl']={'version':version,'status':'passed'}
            f.dav('DELETE','curl-client',status=204)
            checks.append('independent curl TLS upload/download with certificate verification')
        if args.litmus:
            env=os.environ.copy();env['TESTS']=args.litmus_tests
            result=subprocess.run([args.litmus,'--insecure',f.url,'alice',f.password],env=env,text=True,capture_output=True,timeout=600)
            reports['litmus']={'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
            print(result.stdout+result.stderr,flush=True)
            assert result.returncode==0,'litmus failed'
            checks.append('litmus '+args.litmus_tests)
        # Header-only rejection: no upload body is admitted before authentication/conditions.
        def raw_start(path,extra='',auth=True,length=1000000):
            s=f.context.wrap_socket(socket.create_connection(('127.0.0.1',f.davport)),server_hostname='localhost');s.settimeout(10)
            h=f'PUT /dav/dav/{path} HTTP/1.1\r\nHost: 127.0.0.1:{f.davport}\r\nContent-Length: {length}\r\nExpect: 100-continue\r\n'
            if auth:h+='Authorization: '+f.auth+'\r\n'
            s.sendall((h+extra+'\r\n').encode());return s
        s=raw_start('unauthorized',auth=False);assert b'401 Unauthorized' in s.recv(4096);s.close()
        f.dav('PUT','conditional',b'abcdef',status=201)
        tag=f.dav('HEAD','conditional',status=200)[1]['etag']
        f.dav('GET','conditional',headers={'If-None-Match':tag},status=304)
        f.dav('GET','conditional',headers={'If-Match':'W/'+tag},status=412)
        f.dav('GET','conditional',headers={'If-None-Match':'W/'+tag},status=304)
        f.dav('GET','conditional',headers={'If-Unmodified-Since':'Thu, 01 Jan 1970 00:00:00 GMT'},status=412)
        assert f.dav('GET','conditional',headers={'Range':'bytes=1-3'},status=206)[2]==b'bcd'
        assert f.dav('GET','conditional',headers={'Range':'bytes=-2'},status=206)[2]==b'ef'
        f.dav('GET','conditional',headers={'Range':'bytes=99-'},status=416)
        s=raw_start('conditional','If-None-Match: *\r\n');assert b'412 Precondition Failed' in s.recv(4096);s.close()
        s=raw_start('interrupted');assert b'100 Continue' in s.recv(4096);s.sendall(b'x'*4000);s.close()
        token=f.api('auth/login',data=dict(username='alice',password=f.password,scope='files'))['token']
        def core(op,path='',expected=200,**kw):return f.api('files/'+op,token,dict(space='alice',path=path,**kw),expected)
        wait(lambda:core('quota')['reserved']==0)
        f.dav('GET','interrupted',status=404)
        checks.append('auth/condition before 100-continue; ranges, HEAD, 304/412/416; interrupted PUT releases quota')
        # Chunked body split at deliberately irregular boundaries.
        c=http.client.HTTPSConnection('127.0.0.1',f.davport,context=f.context,timeout=15)
        c.request('PUT','/dav/dav/chunked',iter([b'one',b'two',b'\0'*70001]),{'Authorization':f.auth},encode_chunked=True)
        r=c.getresponse();assert r.status==201,r.read();r.read();c.close()
        assert f.dav('GET','chunked',status=200)[2]==b'onetwo'+b'\0'*70001
        f.dav('PROPFIND',headers={'Depth':'infinity'},status=403)
        for path in ('../escape','%2e%2e/escape','a%2fb','a%5cb','a%00b','e%CC%81'):
            assert f.dav('PUT',path,b'x')[0] in (400,403)
        for xml in (b'<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><D:propfind xmlns:D="DAV:">&x;</D:propfind>', b'<x:propfind/>'):
            f.dav('PROPFIND',body=xml,headers={'Depth':'0'},status=400)
        f.dav('COPY','conditional',headers={'Destination':'https://example.com/dav/dav/stolen'},status=400)
        checks.append('chunk framing, UTF-8/NFC and encoded traversal checks, bounded depth, DTD/entity rejection, destination origin confinement')
        patch=b'<D:propertyupdate xmlns:D="DAV:" xmlns:T="urn:test"><D:set><D:prop><T:color>blue</T:color></D:prop></D:set></D:propertyupdate>'
        f.dav('PROPPATCH','conditional',patch,status=207)
        lockbody=b'<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>test</D:owner></D:lockinfo>'
        lock=f.dav('LOCK','conditional',lockbody,{'Depth':'0','Timeout':'Second-300'},200)[1]['lock-token']
        f.dav('PUT','conditional',b'bad',status=423)
        core('begin','conditional',expected=423,size=0)
        core('remove','conditional',expected=423)
        core('begin','other',size=0) # Cancel an explicit durable core upload before backup.
        for j in core('jobs'):
            if j['status']=='staging':core('cancel_job',j['path'],job=j['id'])
        f.dav('PUT','conditional',b'locked',{'If':'('+lock+')'},204)
        # Same-owner token required even when a second user has write access.
        f.api('grants',f.admin,dict(space='alice',subject_type='user',subject='bob',rights='rw'))
        bob='Basic '+base64.b64encode(('bob:'+f.password).encode()).decode()
        f.dav('PUT','conditional',b'bad',{'If':'('+lock+')','Authorization':bob},423)
        services=f.ctl('status'); victim=services['file']['identity']['pid']
        os.kill(victim,signal.SIGTERM if os.name=='nt' else signal.SIGKILL)
        wait(lambda:(s:=f.ctl('status'))['file']['status']=='running' and s['file']['identity']['pid']!=victim)
        f.dav('PUT','conditional',b'bad',status=423)
        assert b'blue' in f.dav('PROPFIND','conditional',headers={'Depth':'0'},status=207)[2]
        f.dav('UNLOCK','conditional',headers={'Lock-Token':lock},status=204)
        exp=f.dav('LOCK','conditional',lockbody,{'Depth':'0','Timeout':'Second-1'},200)[1]['lock-token']
        time.sleep(1.1);f.dav('PUT','conditional',b'after-expiry',status=204)
        f.dav('MKCOL','recover-src',status=201)
        f.dav('PUT','recover-src/data',b'recover-copy',status=201)
        f.dav('COPY','recover-src',headers={'Destination':f.url+'recover-dest'},status=201)
        f.stop()
        db=sqlite3.connect(f.state/'file.db')
        try:
            row=next((id,json.loads(body)) for id,body in db.execute('SELECT id,body FROM jobs') if json.loads(body).get('to')=='recover-dest')
            jid,j=row
            os.rename(f.root/'alice/recover-dest',f.root/'alice'/j['stage'])
            j['status']='committing'
            db.execute('UPDATE jobs SET body=? WHERE id=?',(json.dumps(j),jid));db.commit()
        finally: db.close()
        f.start()
        assert f.dav('GET','recover-dest/data',status=200)[2]==b'recover-copy'
        f.dav('DELETE','recover-src',status=204);f.dav('DELETE','recover-dest',status=204)
        checks.append('durable recursive COPY journal resumes from pre-publication crash cut')
        checks.append('persistent properties and exclusive lock survive file-worker crash; owner/token enforcement across DAV and core; expiry')
        # Slow, revoked upload cleanup uses a cancellation-only proof, never a renewed write grant.
        s=raw_start('revoked');assert b'100 Continue' in s.recv(4096);s.sendall(b'x'*1000)
        f.api('shares',f.admin,dict(id='dav',space='alice',exposures={'webdav':'r'},update=True))
        s.sendall(b'x'*20000);s.close()
        wait(lambda:core('quota')['reserved']==0)
        f.api('shares',f.admin,dict(id='dav',space='alice',exposures={'webdav':'rw'},update=True))
        checks.append('share exposure updates revoke active DAV writes and cancellation releases reservations')
        # Real payload larger than configured allocation ceiling, bounded client and server chunks.
        size=args.large_mib*1024*1024; block=bytes(range(256))*256; expected_hash=hashlib.sha256()
        if size:
            hard='windows_job_private_commit' if os.name=='nt' else 'not_applied'
            if args.large_mib>256 and os.name!='nt':
                import resource
                for role in ('file','webdav'):
                    resource.prlimit(f.ctl('status')[role]['identity']['pid'],resource.RLIMIT_DATA,(256*1024**2,256*1024**2))
                hard='linux_RLIMIT_DATA'
            peak={'file':0,'webdav':0};sampling=threading.Event()
            def sample():
                while not sampling.wait(.5):
                    try:
                        services=f.ctl('status')
                        for role in peak:peak[role]=max(peak[role],services[role].get('rss',0))
                    except (AssertionError,OSError,subprocess.SubprocessError):pass
            sampler=threading.Thread(target=sample,daemon=True);sampler.start()
            c=http.client.HTTPSConnection('127.0.0.1',f.davport,context=f.context,timeout=30)
            c.putrequest('PUT','/dav/dav/large');c.putheader('Authorization',f.auth);c.putheader('Content-Length',str(size));c.endheaders()
            remaining=size
            while remaining:
                part=block[:min(len(block),remaining)];c.send(part);expected_hash.update(part);remaining-=len(part)
            r=c.getresponse();body=r.read();assert r.status==201,(r.status,body);c.close()
            c=http.client.HTTPSConnection('127.0.0.1',f.davport,context=f.context,timeout=30);c.request('GET','/dav/dav/large',headers={'Authorization':f.auth});r=c.getresponse();assert r.status==200
            actual=hashlib.sha256();count=0
            while chunk:=r.read(65536):actual.update(chunk);count+=len(chunk)
            c.close();assert count==size and actual.digest()==expected_hash.digest()
            sampling.set();sampler.join()
            reports['transfer']={'sampled_peak_rss':peak,'bytes':size,'sha256':actual.hexdigest(),'worker_budget_mib':512 if args.sanitizers else 256,'hard_limit':hard}
            c=http.client.HTTPSConnection('127.0.0.1',f.davport,context=f.context,timeout=30)
            c.request('GET','/dav/dav/large',headers={'Authorization':f.auth});r=c.getresponse();r.read(1024);c.close()
            wait(lambda:f.dav('DELETE','large')[0]==204)
            checks.append('streaming upload/download SHA-256 roundtrip')
        f.ctl('login','--username','admin','--scope','admin','--password-stdin',stdin=f.password+'\n')
        assert f.ctl('call','--path','/api/v1/protocols')[0]['enabled']
        assert f.api('monitoring',f.admin)['memory']['total']>0
        backup=f.base/'backup'
        f.ctl('backup','--output',str(backup),ok=False)
        f.stop();f.ctl('backup','--output',str(backup))
        manifest=json.loads((backup/'manifest.json').read_text());assert not manifest['file_data'] and not manifest['private_keys']
        assert not (backup/'tls-key.pem').exists()
        original=f.state;old_cert=(original/'tls-cert.pem').read_bytes();f.state=f.base/'restored'
        f.ctl('restore','--input',str(backup))
        assert (f.state/'tls-cert.pem').read_bytes()!=old_cert
        f.context=ssl.create_default_context(cafile=str(f.state/'tls-cert.pem'));f.start()
        f.api('auth/me',token,expected=401)
        assert f.dav('GET','conditional',status=200)[2]==b'after-expiry'
        assert b'blue' in f.dav('PROPFIND','conditional',headers={'Depth':'0'},status=207)[2]
        f.ctl('restore','--input',str(backup),ok=False)
        damaged=backup/'identity.db';damaged.write_bytes(damaged.read_bytes()+b'damaged')
        invalid=f.base/'invalid-restore'
        failed=subprocess.run([str(f.binary/('taucloud_ctl'+f.suffix)),'--state',str(invalid),'restore','--input',str(backup)],text=True,capture_output=True,timeout=30)
        assert failed.returncode and 'backup_checksum' in failed.stderr and not invalid.exists()
        checks.append('offline backup refuses running services; restore into new state rotates TLS/IPC, revokes sessions and preserves metadata/files')
        reports.update(status='passed',checks=checks)
    finally:
        if sampling is not None:sampling.set();sampler.join()
        reports.setdefault('status','failed'); reports['checks']=checks
        if reports['status']=='failed':
            f.log.flush(); reports['service_log_tail']=(f.base/'supervisor.log').read_text(errors='replace')[-12000:]
        args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(reports,indent=2)+'\n')
        f.close()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--bin',type=Path,required=True);p.add_argument('--output',type=Path,default=Path('build/m3/integration.json'));p.add_argument('--litmus');p.add_argument('--litmus-tests',default='basic copymove props locks http');p.add_argument('--large-mib',type=int,default=1);p.add_argument('--sanitizers',action='store_true');run(p.parse_args())
