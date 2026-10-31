#!/usr/bin/env python3
"""Disposable FTP/explicit FTPS acceptance; no system services or real datasets."""
import argparse, ftplib, hashlib, io, json, os, platform, shutil, signal, socket, ssl, struct, subprocess, threading, time
from pathlib import Path
from m3_integration import Fixture as DavFixture
from m1_integration import wait

class ReuseFTP(ftplib.FTP_TLS):
    """stdlib's FTP state machine with explicit TLS data-session resumption."""
    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(conn, server_hostname=self.host, session=self.sock.session)
            assert conn.session_reused, 'data TLS must resume control session'
        return conn, size

class Fixture(DavFixture):
    def __init__(self, binary, memory=256):
        super().__init__(binary, memory)
        self.stop()
        for _ in range(100):
            sockets=[]
            try:
                probe=socket.socket();probe.bind(('127.0.0.1',0));self.ftpport=probe.getsockname()[1];sockets.append(probe)
                first=self.ftpport+1
                if first+3>65535:continue
                for port in range(first,first+4):
                    probe=socket.socket();probe.bind(('127.0.0.1',port));sockets.append(probe)
                break
            except OSError:pass
            finally:
                for probe in sockets:probe.close()
        else:raise RuntimeError('cannot find passive ports')
        self.first=first
        config=json.loads((self.state/'config.json').read_text())
        config.update(ftp_port=self.ftpport,ftp_passive_first=first,ftp_passive_last=first+3)
        (self.state/'config.json').write_text(json.dumps(config))
        # Exercise upgrading an existing M3 state with no FTP IPC credential.
        keys=json.loads((self.state/'ipc-keys.json').read_text());keys.pop('ftp');(self.state/'ipc-keys.json').write_text(json.dumps(keys))
        self.start()
        self.api('spaces',self.admin,dict(id='transfer',root='data',path='transfer',owner='alice',quota=2*1024**3))
        self.expose('rw')
        self.token=self.api('auth/login',data=dict(username='alice',password=self.password,scope='files'))['token']
    def expose(self,mode,update=False):
        return self.api('shares',self.admin,dict(id='ftp',space='transfer',exposures={'ftp':mode},update=update))
    def core(self,op,path='',**kw):return self.api('files/'+op,self.token,dict(space='transfer',path=path,**kw))
    def connect(self,secure=True,user='alice',context=None):
        deadline=time.monotonic()+65
        while True:
            ftp=ReuseFTP(context=context or self.context,timeout=15) if secure else ftplib.FTP(timeout=15)
            try:
                ftp.connect('127.0.0.1',self.ftpport)
                ftp.login(user,self.password)
                if secure:ftp.prot_p()
                return ftp
            except ftplib.error_perm as e:
                ftp.close()
                if 'rate_limited' not in str(e) or time.monotonic()>deadline:raise
                # Keep the production 5/account/minute policy in the fixture.
                time.sleep(2)

def fails(call,*codes):
    try:call()
    except ftplib.Error as e:
        assert int(str(e)[:3]) in codes,str(e)
        return str(e)
    raise AssertionError('expected FTP rejection')

def download(ftp,path,rest=None):
    out=io.BytesIO();ftp.retrbinary('RETR '+path,out.write,rest=rest);return out.getvalue()

def upload(ftp,path,data,rest=None):return ftp.storbinary('STOR '+path,io.BytesIO(data),blocksize=65536,rest=rest)

def run(args):
    checks=[];clients={};f=Fixture(args.bin,512 if args.sanitizers else 256)
    def passed(message): checks.append(message);print('PASS '+message,flush=True)
    try:
        protocols=f.api('protocols',f.admin);assert next(p for p in protocols if p['id']=='ftp')['enabled']
        c=ftplib.FTP(timeout=10);c.connect('127.0.0.1',f.ftpport)
        fails(lambda:c.login('alice',f.password),534);fails(lambda:c.sendcmd('PORT 127,0,0,1,1,1'),502);c.close()
        c=ReuseFTP(context=f.context,timeout=10);c.connect('127.0.0.1',f.ftpport);c.auth()
        fails(lambda:c.sendcmd('USER anonymous'),530);fails(lambda:c.sendcmd('PROT P'),503)
        c.login('alice',f.password);c.prot_p();fails(lambda:c.sendcmd('PROT C'),536);fails(lambda:c.sendcmd('CCC'),534)
        passed('M3 state adds isolated FTP worker; plaintext default deny, anonymous/active/FXP/downgrade denied')
        # Count the configured listeners before data connections can leave
        # Windows exclusive-bind ports temporarily unavailable in TIME_WAIT.
        held=[]
        for _ in range(4):
            item=f.connect();item.sendcmd('EPSV');held.append(item)
        fails(lambda:c.sendcmd('EPSV'),425)
        for item in held:item.quit()
        c.sendcmd('EPSV');c.sendcmd('ABOR')
        feat=c.sendcmd('FEAT');assert 'REST STREAM' in feat and 'MLST' in feat
        assert c.pwd()=='/' and 'ftp' in c.nlst()
        c.cwd('/ftp');c.mkd('dir');c.cwd('dir');c.sendcmd('TYPE I')
        payload=b'\x00\xff\r\n'+b'a'*200000
        upload(c,'中文.txt',payload);assert download(c,'中文.txt')==payload
        c.sendcmd('TYPE I');assert c.size('中文.txt')==len(payload)
        assert c.sendcmd('MDTM 中文.txt').startswith('213 ')
        entries=dict(c.mlsd());assert entries['中文.txt']['size']==str(len(payload))
        c.sendcmd('OPTS MLST type;');assert 'size=' not in c.sendcmd('MLST 中文.txt')
        c.sendcmd('OPTS MLST type;size;modify;')
        c.rename('中文.txt','renamed');assert download(c,'renamed',rest=123)==payload[123:]
        upload(c,'renamed',b'replacement',rest=123);assert download(c,'renamed')==payload[:123]+b'replacement'
        fails(lambda:c.storbinary('STOR renamed',io.BytesIO(b'bad'),rest=999999),551)
        c.sendcmd('TYPE A');fails(lambda:c.size('renamed'),504)
        fails(lambda:c.sendcmd('RETR renamed'),504);fails(lambda:c.sendcmd('TYPE E'),504)
        c.cwd('/ftp');fails(lambda:c.rmd('dir'),550);c.delete('dir/renamed');c.rmd('dir')
        c.cwd('/');fails(lambda:c.cwd('..'),550);fails(lambda:c.mkd('/ftp/e\u0301'),550)
        fails(lambda:c.sendcmd('EPRT |1|127.0.0.1|1234|'),502)
        bob=f.connect(user='bob');assert bob.nlst()==[];fails(lambda:bob.cwd('/ftp'),550);bob.quit()
        fails(lambda:c.rmd('/ftp'),550)
        # TLS 1.2 and 1.3 use the same mandatory control/data association rule.
        legacy=ssl.create_default_context(cafile=str(f.state/'tls-cert.pem'));legacy.maximum_version=ssl.TLSVersion.TLSv1_2
        old=f.connect(context=legacy);upload(old,'/ftp/tls12',b'tls12');assert download(old,'/ftp/tls12')==b'tls12';old.quit()
        passed('stdlib FTP client: UTF-8, PASV, MLSD/MLST facts, directories/rename/delete, binary roundtrip and safe REST upload/download')
        # EPSV, EPSV ALL, protected data required, peer binding and session binding.
        c.sendcmd('EPSV ALL');fails(lambda:c.sendcmd('PASV'),501);c.quit()
        c=f.connect();c.sendcmd('TYPE I')
        passive=c.sendcmd('EPSV');port=int(passive.split('|')[-2])
        raw=socket.create_connection(('127.0.0.1',port));c.putcmd('STOR /ftp/unbound');assert c.getresp().startswith('150')
        unbound=f.context.wrap_socket(raw,server_hostname='localhost');unbound.close()
        fails(c.getresp,522);assert not (f.root/'transfer/unbound').exists()
        other=f.connect();other.sendcmd('TYPE I')
        port=int(c.sendcmd('EPSV').split('|')[-2]);raw=socket.create_connection(('127.0.0.1',port))
        c.putcmd('STOR /ftp/wrong-session');c.getresp()
        wrong=f.context.wrap_socket(raw,server_hostname='localhost',session=other.sock.session);assert not wrong.session_reused;wrong.close()
        fails(c.getresp,522);other.quit()
        # Independent TLS trust failure must not crash the worker.
        bad=ReuseFTP(timeout=10,context=ssl.create_default_context());bad.connect('127.0.0.1',f.ftpport)
        try:bad.auth();raise AssertionError('untrusted certificate accepted')
        except ssl.SSLCertVerificationError:pass
        finally:bad.close()
        assert c.voidcmd('NOOP').startswith('200')
        passed('EPSV ALL and TLS certificate verification; fresh or different-control TLS sessions rejected on data channel')
        # Wrong peer address, handshake timeout and oversized framing are bounded.
        port=int(c.sendcmd('EPSV').split('|')[-2])
        peer=socket.socket();peer.bind(('127.0.0.2',0));peer.connect(('127.0.0.1',port))
        c.putcmd('STOR /ftp/wrong-peer');assert c.getresp().startswith('150');fails(c.getresp,425);peer.close()
        port=int(c.sendcmd('EPSV').split('|')[-2]);peer=socket.create_connection(('127.0.0.1',port))
        c.putcmd('STOR /ftp/no-handshake');assert c.getresp().startswith('150');fails(c.getresp,426);peer.close()
        oversized=f.connect();oversized.sock.sendall(b'X'*3000+b'\r\n');fails(oversized.getresp,500);oversized.close()
        passed('configured passive port exhaustion returns 425 and releases listeners on ABOR/QUIT')
        c.sendcmd('TYPE I');upload(c,'/ftp/atomic',b'original')
        data=c.transfercmd('STOR /ftp/atomic');data.sendall(b'x'*65536)
        # In-band ABOR over TLS: FTP_TLS.abort uses urgent data, which TLS cannot carry.
        c.putcmd('ABOR');fails(c.getresp,426);assert c.getresp().startswith('226');data.close()
        assert download(c,'/ftp/atomic')==b'original';wait(lambda:f.core('quota')['reserved']==0)
        c.sendcmd('TYPE I');data=c.transfercmd('STOR /ftp/truncated');data.sendall(b'x'*65536)
        # close() without unwrap omits TLS close_notify and is a failed upload.
        data.close();fails(c.getresp,426);wait(lambda:f.core('quota')['reserved']==0)
        assert not (f.root/'transfer/truncated').exists()
        passed('in-band ABOR and missing TLS close_notify discard staging, preserve existing file, release quota')
        # Resume checks the original representation again before publication.
        upload(c,'/ftp/resume-race',b'original')
        data=c.transfercmd('STOR /ftp/resume-race',rest=3)
        wait(lambda:any(j['path']=='resume-race' and j['status']=='staging' and j['progress']==3 for j in f.core('jobs')))
        peer=f.connect();upload(peer,'/ftp/resume-race',b'new-version');peer.quit()
        data.sendall(b'old-suffix')
        try:data.unwrap()
        except OSError:pass
        data.close();fails(c.getresp,550);assert download(c,'/ftp/resume-race')==b'new-version'
        f.api('spaces',f.admin,dict(id='small',root='data',path='small',owner='alice',quota=8))
        f.api('shares',f.admin,dict(id='small',space='small',exposures={'ftp':'rw'}))
        c.quit();c=f.connect();c.sendcmd('TYPE I');data=c.transfercmd('STOR /small/too-large');data.sendall(b'0123456789')
        try:data.unwrap()
        except OSError:pass
        data.close();fails(c.getresp,552)
        assert not (f.root/'small/too-large').exists()
        passed('bounded malformed commands, mismatched data peer, stalled TLS, quota overflow and changed-source resume rejection')
        data=c.transfercmd('STOR /ftp/revoked');data.sendall(b'x'*65536)
        f.expose('r',True)
        try:data.sendall(b'y'*65536);data.unwrap()
        except (OSError,ssl.SSLError):pass
        data.close();fails(c.getresp,550,426);wait(lambda:f.core('quota')['reserved']==0)
        assert not (f.root/'transfer/revoked').exists();f.expose('rw',True)
        # Revoked session/credential cannot continue to inspect files.
        f.api('users',f.admin,dict(username='alice',enabled=False,update=True))
        fails(lambda:c.sendcmd('PWD'),530);c.close()
        f.api('users',f.admin,dict(username='alice',enabled=True,update=True));c=f.connect();c.sendcmd('TYPE I')
        f.token=f.api('auth/login',data=dict(username='alice',password=f.password,scope='files'))['token']
        passed('share revocation during STOR cleans unpublished data; disabled credentials invalidate existing control sessions')
        # The single writer gate is preserved; core and DAV remain read-only peers of FTP.
        f.api('shares',f.admin,dict(id='unsafe',space='transfer',exposures={'webdav':'rw'}),expected=503)
        before=f.ctl('status');data=c.transfercmd('STOR /ftp/killed');data.sendall(b'x'*131072)
        wait(lambda:f.core('quota')['reserved']>0)
        os.kill(before['ftp']['identity']['pid'],signal.SIGTERM if os.name=='nt' else signal.SIGKILL)
        c.close();data.close()
        wait(lambda:(entry:=f.ctl('status')['ftp'])['status']=='running' and entry['identity']['pid']!=before['ftp']['identity']['pid'])
        wait(lambda:f.core('quota')['reserved']==0)
        after=f.ctl('status')
        for role in ('api','webdav','file','identity'):assert before[role]['identity']['pid']==after[role]['identity']['pid']
        f.dav('PUT','ftp-sibling',b'survived',status=201);assert f.dav('GET','ftp-sibling',status=200)[2]==b'survived'
        assert not (f.root/'transfer/killed').exists()
        c=f.connect();assert download(c,'/ftp/atomic')==b'original'
        passed('FTP kill/restart reclaims stages; API, identity, file and DAV processes survive; mixed writer gate retained')
        # curl is a separate FTP implementation; plaintext and explicit FTPS both exercised.
        curl=shutil.which('curl.exe' if os.name=='nt' else 'curl')
        assert curl,'curl required for acceptance'
        version=subprocess.run([curl,'--version'],text=True,capture_output=True,check=True).stdout.splitlines()[0]
        command=[curl,'--silent','--show-error','--fail','--max-time','30','--ssl-reqd','--cacert',str(f.state/'tls-cert.pem'),'--user','alice:'+f.password]
        url=f'ftp://127.0.0.1:{f.ftpport}/ftp/curl-client'
        result=subprocess.run(command+['--upload-file','-',url],input=b'curl-ftps',capture_output=True)
        assert result.returncode==0,result.stderr
        assert subprocess.run(command+[url],capture_output=True,check=True).stdout==b'curl-ftps'
        clients['curl_ftps']={'version':version,'returncode':0,'status':'passed'}
        clients['python']={'version':platform.python_version(),'tls':ssl.OPENSSL_VERSION,'status':'passed','adapter':'stdlib FTP_TLS plus explicit SSL session reuse'}
        passed('independent curl explicit FTPS probe (strict session binding retained)')
        # Transfer exceeds per-worker allocation budget without client-sized server buffers.
        if os.name!='nt' and not args.sanitizers:
            import resource
            state=f.ctl('status')
            for role in ('ftp','file'):
                resource.prlimit(state[role]['identity']['pid'],resource.RLIMIT_DATA,(256*1024**2,256*1024**2))
        content=f.base/'large.bin';chunk=bytes(range(256))*256;digest=hashlib.sha256()
        with content.open('wb') as out:
            for _ in range(args.large_mib*16):out.write(chunk);digest.update(chunk)
        c.sendcmd('TYPE I')
        start=time.monotonic()
        with content.open('rb') as inp:c.storbinary('STOR /ftp/large',inp,blocksize=65536)
        received=hashlib.sha256();total=0
        def consume(block):
            nonlocal total
            received.update(block);total+=len(block)
        c.retrbinary('RETR /ftp/large',consume,blocksize=65536)
        assert total==content.stat().st_size and received.digest()==digest.digest()
        clients['large_transfer']={'bytes':total,'sha256':digest.hexdigest(),'seconds':time.monotonic()-start,'worker_memory_mb':512 if args.sanitizers else 256}
        passed('bounded streaming upload/download '+str(args.large_mib)+' MiB with digest verification')
        c.quit();f.stop()
        config=json.loads((f.state/'config.json').read_text());config['ftp_plaintext']=True;(f.state/'config.json').write_text(json.dumps(config));f.start()
        c=f.connect(False);upload(c,'/ftp/plain',b'plain-opt-in');assert download(c,'/ftp/plain')==b'plain-opt-in';c.quit()
        plain=[curl,'--silent','--show-error','--fail','--max-time','30','--user','alice:'+f.password]
        assert subprocess.run(plain+[f'ftp://127.0.0.1:{f.ftpport}/ftp/plain'],capture_output=True,check=True).stdout==b'plain-opt-in'
        clients['curl_plain']={'version':version,'status':'passed'}
        passed('explicit plaintext opt-in works after restart with stdlib and curl; default remains TLS only')
        return {'status':'passed','checks':checks,'clients':clients,'filezilla':{'status':'not_tested','reason':'No installed automatable FileZilla GUI on either acceptance host'}}
    except BaseException:
        try:
            c.sock.settimeout(2)
            print('Control response after failure:',c.getresp(),flush=True)
        except Exception as diagnostic:print('Control diagnostic:',repr(diagnostic),flush=True)
        try:print('Service diagnostic:',f.ctl('status'),flush=True)
        except Exception:pass
        try:print('Fixture log:',(f.base/'supervisor.log').read_text(errors='replace')[-8000:],flush=True)
        except Exception:pass
        raise
    finally:
        f.close()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--bin',required=True);p.add_argument('--large-mib',type=int,default=1);p.add_argument('--sanitizers',action='store_true');p.add_argument('--output',type=Path)
    args=p.parse_args();report=run(args)
    if args.output:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
