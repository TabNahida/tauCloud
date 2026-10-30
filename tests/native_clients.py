#!/usr/bin/env python3
"""Linux kernel CIFS/NFS and Samba client acceptance on disposable local data.

Run the harness as the normal runner user; sudo is used only for mount/umount.
Each profile runs independently and retains its command failure as evidence.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import traceback
from m3_integration import Fixture

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    report = dict(host=platform.platform(), recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  profiles=[], status='failed')
    f = Fixture(args.bin)
    def run(command, timeout=45):
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        current['commands'].append(dict(command=command, returncode=result.returncode,
                                        stdout=result.stdout, stderr=result.stderr))
        if result.returncode:
            raise RuntimeError(f'{command[0]} failed: {result.stderr or result.stdout}')
        return result.stdout
    try:
        f.stop()
        with socket.socket() as a, socket.socket() as b:
            a.bind(('127.0.0.1',0)); b.bind(('127.0.0.1',0))
            smbport, nfsport = a.getsockname()[1], b.getsockname()[1]
        cfg=json.loads((f.state/'config.json').read_text())
        cfg.update(smb_port=smbport,nfs_port=nfsport)
        (f.state/'config.json').write_text(json.dumps(cfg)); f.start()
        for protocol in ('smb','nfs'):
            f.api('spaces',f.admin,dict(id=protocol+'data',root='data',path=protocol+'data',owner='alice',quota=2**31))
            f.api('shares',f.admin,dict(id=protocol,space=protocol+'data',exposures={protocol:'rw'}))
        f.api('smb/credentials',f.admin,dict(username='alice',password=f.password))
        f.api('groups',f.admin,dict(name='unix'))
        f.api('memberships',f.admin,dict(username='alice',group='unix'))
        # Only this disposable fixture grants the squashed account write access:
        # mount probes originate as root while file operations run as runner UID.
        f.api('grants',f.admin,dict(space='nfsdata',subject_type='user',subject='bob',rights='rw'))
        groups={str(g):'unix' for g in set(os.getgroups()+[os.getgid()])}
        f.api('nfs-exports',f.admin,dict(id='nfs',trust='loopback-auth-sys',anonymous='bob',
                                       uids={str(os.getuid()):'alice'},gids=groups))
        credentials=f.base/'smb-credentials'
        credentials.write_text('username=alice\npassword='+f.password+'\ndomain=TAUCLOUD\n')
        credentials.chmod(0o600)
        payload=bytes(range(256))*4096
        source=f.base/'source'; source.write_bytes(payload)
        mount=f.base/'mount'; mount.mkdir()
        profiles=[('smbclient-2.1','samba','SMB2_10'),('smbclient-3.1.1','samba','SMB3_11')]
        profiles += [('kernel-cifs-'+v,'cifs',v) for v in ('2.1','3.0','3.02','3.1.1')]
        profiles += [('kernel-nfs-'+v,'nfs',v) for v in ('3','4.1')]
        for name,kind,version in profiles:
            current=dict(name=name,status='failed',commands=[])
            report['profiles'].append(current)
            mounted=False
            try:
                if kind=='samba':
                    target=f.base/'download'
                    command=['smbclient','//127.0.0.1/smb','-p',str(smbport),'-A',str(credentials),
                             '--option=client min protocol='+version,'--option=client max protocol='+version,
                             '--option=client signing=required','-c',
                             f'put {source} probe; get probe {target}; rename probe renamed; del renamed']
                    current['version']=run(['smbclient','--version']).strip()
                    run(command)
                    assert target.read_bytes()==payload
                else:
                    if kind=='cifs':
                        options=f'port={smbport},credentials={credentials},vers={version},sec=ntlmssp,sign,uid={os.getuid()},gid={os.getgid()},cache=none'
                        if version!='2.1': options+=',seal'
                        remote='//127.0.0.1/smb'
                    else:
                        options=f'vers={version},proto=tcp,port={nfsport},sec=sys,soft,timeo=10,retrans=1'
                        if version=='3': options+=f',mountproto=tcp,mountport={nfsport},mountvers=3,nolock'
                        remote='127.0.0.1:/nfs'
                    run(['sudo','-n','mount','-t',kind,'-o',options,remote,str(mount)])
                    mounted=True
                    # Bound filesystem operations too: a buggy server must not hang CI.
                    code = '''import os,sys,hashlib
from pathlib import Path
p=Path(sys.argv[1]); data=Path(sys.argv[2]).read_bytes()
d=p/'probe-dir'; d.mkdir()
f=d/'file'
with f.open('wb') as out: out.write(data); out.flush(); os.fsync(out.fileno())
assert f.read_bytes()==data
f.rename(d/'renamed'); f=d/'renamed'
with f.open('r+b') as out: out.seek(123);out.write(b'changed');out.truncate(65537);out.flush();os.fsync(out.fileno())
assert f.read_bytes()==(data[:123]+b'changed'+data[130:])[:65537]
assert [x.name for x in d.iterdir()]==['renamed']
f.unlink();d.rmdir()
'''
                    run(['python3','-c',code,str(mount),str(source)])
                current.update(status='passed',payload_sha256=hashlib.sha256(payload).hexdigest())
            except Exception:
                current['error']=traceback.format_exc()
            finally:
                if mounted:
                    try: run(['sudo','-n','umount',str(mount)])
                    except Exception:
                        current.update(status='failed',cleanup_error=traceback.format_exc())
                        subprocess.run(['sudo','-n','umount','-lf',str(mount)],timeout=20)
            print(name+': '+current['status'],flush=True)
        report['status']='passed' if all(x['status']=='passed' for x in report['profiles']) else 'failed'
    finally:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+'\n')
        f.close()
    return int(report['status']!='passed')

if __name__=='__main__':
    raise SystemExit(main())
