#!/usr/bin/env python3
"""Native Linux NFSv4.1/GSS check inside a disposable Actions runner.
Called by nfs_gss_integration.py only with --native; requires sudo and nfs-common.
"""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def exercise(fixture, kdc, port, output):
    def run(args, timeout=45, check=True):
        result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        if check:
            assert result.returncode == 0, (args, result.stdout, result.stderr)
        return result

    # The KDC, ticket files, mount points and foreground gssd are all unique to
    # this fixture. Preserve the runner's service state and remove every mount.
    base = kdc.base / 'native'
    base.mkdir()
    pipefs, mount, caches = [base / name for name in ('pipefs', 'mount', 'ccaches')]
    for path in (pipefs, mount, caches):
        path.mkdir()
    kdc.credentials()
    run(['sudo', '-n', 'install', '-m', '600', str(kdc.last_cache), str(caches / 'krb5cc_0')])
    was_active = run(['systemctl', 'is-active', '--quiet', 'rpc-gssd.service'], check=False).returncode == 0
    daemon, pipe_mounted, mounted = None, False, False
    report = {'status': 'failed', 'profiles': []}
    logpath = output.resolve().with_suffix('.gssd.log')
    with logpath.open('w') as log:
        try:
            run(['sudo', '-n', 'systemctl', 'stop', 'rpc-gssd.service'])
            run(['sudo', '-n', 'modprobe', 'rpcsec_gss_krb5'])
            run(['sudo', '-n', 'mount', '-t', 'rpc_pipefs', 'sunrpc', str(pipefs)])
            pipe_mounted = True
            daemon = subprocess.Popen([
                'sudo', '-n', 'env', 'KRB5_CONFIG=' + os.environ['KRB5_CONFIG'],
                'KRB5RCACHEDIR=' + str(kdc.base), 'rpc.gssd', '-f', '-n', '-M', '-v', '-v',
                '-k', str(kdc.keytab), '-d', str(caches), '-p', str(pipefs), '-T', '5', '-U', '10', '-C'],
                stdout=log, stderr=log, start_new_session=True)
            time.sleep(.3)
            assert daemon.poll() is None, 'rpc.gssd did not start'
            code = '''import os,sys
from pathlib import Path
root=Path(sys.argv[1]);name=sys.argv[2];data=bytes(range(256))*1024
p=root/('kernel-'+name);p.mkdir()
f=p/'first'
with f.open('wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
assert f.read_bytes()==data
assert f.stat().st_uid==1000
f.rename(p/'second');f=p/'second'
with f.open('r+b') as stream:stream.seek(19);stream.write(b'kerberos');stream.truncate(65537);stream.flush();os.fsync(stream.fileno())
assert f.read_bytes()==(data[:19]+b'kerberos'+data[27:])[:65537]
assert sorted(x.name for x in p.iterdir())==['second']
f.unlink();p.rmdir()
'''
            for service in ('krb5', 'krb5i', 'krb5p'):
                options = f'vers=4.1,proto=tcp,port={port},sec={service},soft,timeo=10,retrans=1,nosharecache'
                run(['sudo', '-n', 'mount', '-t', 'nfs', '-o', options, 'localhost:/nfs', str(mount)])
                mounted = True
                run(['sudo', '-n', sys.executable, '-c', code, str(mount), service], timeout=60)
                run(['sudo', '-n', 'umount', str(mount)])
                mounted = False
                report['profiles'].append({'service': service, 'status': 'passed',
                    'checks': ['native kernel mount', '256 KiB write/fsync/read', 'mapped owner',
                               'rename/overwrite/truncate', 'directory enumeration/unlink/rmdir']})
            report['status'] = 'passed'
        finally:
            if mounted:
                run(['sudo', '-n', 'umount', '-fl', str(mount)], timeout=15, check=False)
            if daemon:
                # Only the new process group created above; never kill by name.
                run(['sudo', '-n', 'kill', '-TERM', '--', '-' + str(daemon.pid)], check=False)
                try:
                    daemon.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    run(['sudo', '-n', 'kill', '-KILL', '--', '-' + str(daemon.pid)], check=False)
                    daemon.wait(timeout=10)
            if pipe_mounted:
                run(['sudo', '-n', 'umount', str(pipefs)], timeout=15, check=False)
            if was_active:
                run(['sudo', '-n', 'systemctl', 'start', 'rpc-gssd.service'], check=False)
    return report
