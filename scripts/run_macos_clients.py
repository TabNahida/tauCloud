#!/usr/bin/env python3
"""Run macOS native mounts against our Linux binary in an isolated QEMU guest.

Only loopback SSH is forwarded. Server listeners remain inside guest loopback;
no system SMB/NFS server is installed, and no host service is reconfigured.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import socket
import subprocess
import sys
import time
import traceback
import urllib.parse
import urllib.request

IMAGE='https://cloud-images.ubuntu.com/releases/noble/release-20260814/ubuntu-24.04-server-cloudimg-amd64.img'
IMAGE_SHA='6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733'
BOOT_FILES={
    'vmlinuz':'76a7f2ef15fcbd2f5c25cd7e7b413f903b2078396063557f1dffb4a0b089a964',
    'initrd':'194f73c17ca4795f987f2e1713c7184f8d1bb88f063f79a753dada5da6a9987c',
}
PASSWORD='M3-disposable-password-123!'
ROOT=Path(__file__).resolve().parents[1]

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();assert platform.system()=='Darwin'
    work=ROOT/'build/mac-vm';work.mkdir(parents=True,exist_ok=True)
    a.output=a.output.resolve();a.output.parent.mkdir(parents=True,exist_ok=True)
    report=dict(status='failed',client_host=platform.platform(),server_host='Ubuntu 24.04 QEMU guest',
                source_commit=os.environ.get('TC_SERVER_COMMIT',os.environ.get('GITHUB_SHA')),
                harness_commit=os.environ.get('GITHUB_SHA'),image=IMAGE,image_sha256=IMAGE_SHA,
                server_archive_sha256=hashlib.sha256(a.archive.read_bytes()).hexdigest(),profiles=[])
    processes=[];guest=None
    def run(cmd,timeout=60,**kw):
        return subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=timeout,**kw).stdout
    try:
        image=work/'ubuntu.img'
        if not image.exists():
            with urllib.request.urlopen(IMAGE,timeout=60) as src,image.open('wb') as out:
                while chunk:=src.read(1024*1024):out.write(chunk)
        h=hashlib.sha256()
        with image.open('rb') as inp:
            while chunk:=inp.read(1024*1024):h.update(chunk)
        assert h.hexdigest()==IMAGE_SHA,'Ubuntu image hash mismatch'
        for name,digest in BOOT_FILES.items():
            target=work/name
            url=IMAGE.rsplit('/',1)[0]+'/unpacked/ubuntu-24.04-server-cloudimg-amd64-'+name+'-generic'
            if not target.exists():
                with urllib.request.urlopen(url,timeout=60) as src,target.open('wb') as out:
                    while chunk:=src.read(1024*1024):out.write(chunk)
            assert hashlib.sha256(target.read_bytes()).hexdigest()==digest,'Ubuntu boot-file hash mismatch'
        report['boot_files_sha256']=BOOT_FILES
        key=work/'ssh-key'
        if not key.exists():run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)])
        seed=work/'seed';seed.mkdir(exist_ok=True)
        (seed/'user-data').write_text('#cloud-config\nusers:\n  - name: ubuntu\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n    lock_passwd: true\n    ssh_authorized_keys:\n      - '+key.with_suffix('.pub').read_text().strip()+'\nssh_pwauth: false\n')
        (seed/'meta-data').write_text('instance-id: taucloud-acceptance\nlocal-hostname: taucloud-acceptance\n')
        iso=work/'seed.iso';iso.unlink(missing_ok=True)
        run(['hdiutil','makehybrid','-o',str(iso),'-iso','-joliet','-default-volume-name','cidata',str(seed)])
        disk=work/'disk.qcow2';disk.unlink(missing_ok=True)
        run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(image),str(disk),'12G'])
        sshport=port()
        console=work/'console.log'
        # Probe actual Hypervisor.framework access, not merely the compiled-in
        # accelerator list. A hosted runner may deny nested virtualization.
        probe=subprocess.Popen(['qemu-system-x86_64','-machine','q35,accel=hvf','-cpu','host',
                                '-m','128','-S','-display','none','-nodefaults'],
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        time.sleep(2)
        accelerated=probe.poll() is None
        if accelerated:probe.terminate()
        _,probe_error=probe.communicate(timeout=10)
        report['accelerator']='hvf' if accelerated else 'tcg'
        report['accelerator_probe']=probe_error[-2048:]
        qemu=['qemu-system-x86_64','-machine','q35,accel='+report['accelerator'],
              '-cpu','host' if accelerated else 'max','-smp','4','-m','4096',
              '-kernel',str(work/'vmlinuz'),'-initrd',str(work/'initrd'),
              '-append','root=/dev/vda1 ro console=ttyS0 noapic',
              '-drive',f'file={disk},if=virtio,format=qcow2','-drive',f'file={iso},media=cdrom,readonly=on',
              '-netdev',f'user,id=net0,hostfwd=tcp:127.0.0.1:{sshport}-:22','-device','virtio-net-pci,netdev=net0',
              '-display','none','-serial',f'file:{console}']
        qlog=(work/'qemu.log').open('w');processes.append(subprocess.Popen(qemu,stdout=qlog,stderr=qlog))
        common=['-i',str(key),'-o','BatchMode=yes','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=no',
                '-o','UserKnownHostsFile='+str(work/'known_hosts')]
        ssh=['ssh']+common+['-p',str(sshport),'ubuntu@127.0.0.1']
        deadline=time.monotonic()+600
        while True:
            if processes[0].poll() is not None:raise RuntimeError('QEMU exited before SSH was ready')
            if console.exists() and 'Kernel panic' in console.read_text(errors='replace'):
                raise RuntimeError('Guest kernel panic; see mac-console.log')
            try:run(ssh+['true'],timeout=8);break
            except (subprocess.SubprocessError,OSError):
                if time.monotonic()>deadline:raise RuntimeError('Guest SSH boot deadline exceeded')
                time.sleep(5)
        report['guest_kernel']=run(ssh+['uname -a']).strip()
        run(ssh+['mkdir -p work/bin'])
        scp=['scp']+common+['-P',str(sshport)]
        run(scp+[str(a.archive.resolve()),'ubuntu@127.0.0.1:work/server.tgz'],timeout=180)
        run(scp+[str(ROOT/'tests'/n) for n in ('m1_integration.py','m3_integration.py','mac_guest_fixture.py')]+['ubuntu@127.0.0.1:work/'])
        run(ssh+['cd work && tar xzf server.tgz -C bin'])
        # Nested HVF and TCG can exceed the real server's IPC budget for Argon2.
        # Compute exactly the production parameters on the native host and
        # seed only a stopped disposable test DB. SMB still performs real
        # NTLMv2/MIC authentication against normally enrolled credentials.
        from argon2.low_level import hash_secret_raw,Type
        identity=dict(token=os.urandom(32).hex(),users=[])
        for name in ('admin','alice','bob'):
            salt=os.urandom(16).hex()
            verifier=hash_secret_raw(PASSWORD.encode(),salt.encode(),time_cost=3,
                                     memory_cost=65536,parallelism=1,hash_len=32,type=Type.ID,version=19).hex()
            identity['users'].append(dict(name=name,salt=salt,verifier=verifier))
        seed=work/'identity-seed.json'
        with seed.open('w') as out:
            os.chmod(seed,0o600);json.dump(identity,out)
        try:run(scp+[str(seed),'ubuntu@127.0.0.1:work/identity-seed.json'])
        finally:seed.unlink(missing_ok=True)
        identity_args=' --identity-seed identity-seed.json'
        report['identity_setup']='offline disposable identity seed, native Argon2id 64 MiB/3/1; management login excluded; SMB authentication unchanged'
        groups=json.dumps(sorted(set(os.getgroups()+[os.getgid()])))
        command='cd work && nohup python3 mac_guest_fixture.py --uid '+str(os.getuid())+' --groups '+shlex.quote(groups)+identity_args+' --output info.json > fixture.log 2>&1 < /dev/null &'
        run(ssh+[command])
        deadline=time.monotonic()+240
        while True:
            try:guest=json.loads(run(ssh+['cat work/info.json']));break
            except (subprocess.SubprocessError,json.JSONDecodeError):
                if time.monotonic()>deadline:raise RuntimeError('Server fixture startup deadline exceeded')
                time.sleep(3)
        smbport,nfsport=port(),port()
        tunnel=['ssh']+common+['-p',str(sshport),'-N','-o','ExitOnForwardFailure=yes',
                '-L',f'127.0.0.1:{smbport}:127.0.0.1:{guest["smb_port"]}',
                '-L',f'127.0.0.1:{nfsport}:127.0.0.1:{guest["nfs_port"]}','ubuntu@127.0.0.1']
        tlog=(work/'tunnel.log').open('w');processes.append(subprocess.Popen(tunnel,stdout=tlog,stderr=tlog));time.sleep(2)
        assert processes[-1].poll() is None,'SSH tunnel exited'
        mount=work/'mount';mount.mkdir(exist_ok=True)
        for kind in ('smb','nfs3'):
            item=dict(name='macos-native-'+kind,status='failed');report['profiles'].append(item)
            try:
                if kind=='smb':
                    remote='//TAUCLOUD;alice:'+urllib.parse.quote(PASSWORD,safe='')+f'@127.0.0.1:{smbport}/smb'
                    cmd=['mount','-t','smbfs','-o','nobrowse',remote,str(mount)]
                else:
                    options=f'vers=3,tcp,port={nfsport},mountport={nfsport},nolocks,soft,timeo=10,retrans=1'
                    cmd=['sudo','-n','mount','-t','nfs','-o',options,'127.0.0.1:/nfs',str(mount)]
                item['mount_output']=run(cmd,timeout=60)
                code='''import os,sys,hashlib
from pathlib import Path
p=Path(sys.argv[1])/'native-probe';p.mkdir();f=p/'payload';data=bytes(range(251))*4096
with f.open('wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
assert f.read_bytes()==data
f.rename(p/'renamed');f=p/'renamed'
with f.open('r+b') as out:out.truncate(65537);out.flush();os.fsync(out.fileno())
assert f.read_bytes()==data[:65537]
assert [x.name for x in p.iterdir()]==['renamed']
f.unlink();p.rmdir();print(hashlib.sha256(data).hexdigest())
'''
                item['payload_sha256']=run([sys.executable,'-c',code,str(mount)],timeout=90).strip()
                item['status']='passed'
            except Exception as e:
                item['error']=traceback.format_exc()
                if isinstance(e,subprocess.CalledProcessError):item.update(stdout=e.stdout,stderr=e.stderr)
            finally:
                if os.path.ismount(mount):
                    try:run(['sudo','-n','umount',str(mount)],timeout=30)
                    except Exception:
                        item.update(status='failed',cleanup_error=traceback.format_exc())
                        subprocess.run(['sudo','-n','umount','-f',str(mount)],timeout=30)
            print(kind+': '+item['status'],flush=True)
        report['status']='passed' if all(x['status']=='passed' for x in report['profiles']) else 'failed'
    except Exception:report['error']=traceback.format_exc()
    finally:
        if guest:
            try:run(ssh+['kill -TERM '+str(guest['pid'])]);time.sleep(3)
            except Exception:pass
        if 'ssh' in locals():
            for source in ('fixture.log','server.log'):
                try:(a.output.parent/('mac-'+source)).write_text(run(ssh+['tail -c 65536 work/'+source]))
                except Exception:pass
        for proc in reversed(processes):
            proc.terminate()
            try:proc.wait(timeout=15)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        for name in ('console.log','qemu.log','tunnel.log'):
            if (work/name).exists():(a.output.parent/('mac-'+name)).write_text((work/name).read_text(errors='replace')[-65536:])
        a.output.write_text(json.dumps(report,indent=2).replace(PASSWORD,'<fixture-password>').replace(urllib.parse.quote(PASSWORD,safe=''),'<fixture-password>')+'\n')
    return int(report['status']!='passed')

if __name__=='__main__':raise SystemExit(main())
