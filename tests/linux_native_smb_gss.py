#!/usr/bin/env python3
"""Real kernel CIFS/Kerberos acceptance on a disposable sudo Actions runner."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
from smb_trace_proxy import HeaderProxy


def exercise(fixture, kdc, host, output, report):
    # Standalone Actions starts without an acceptance directory. Prepare it
    # before mounting, so diagnostic writes cannot mask a protocol failure.
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    def run(command, timeout=45, check=True):
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
        if check:
            assert result.returncode == 0, (command, result.stdout, result.stderr)
        return result

    report.update(status='failed', profiles=[])
    started = int(time.time())
    base = kdc.base / 'native-smb'
    base.mkdir()
    mount = base / 'mount'
    mount.mkdir()
    cache = base / 'client.ccache'
    shutil.copyfile(kdc.last_cache, cache)
    cache.chmod(0o600)
    # cifs.upcall drops DAC override capabilities. Use the actual credential
    # owner so the private config/cache remain readable after the uid change.
    config = base / 'krb5.conf'
    config.write_text((kdc.base / 'krb5.conf').read_text().replace(
        '[libdefaults]', '[libdefaults]\n default_ccache_name = FILE:' + str(cache), 1))
    helper = shutil.which('cifs.upcall', path='/usr/sbin:/sbin:/usr/bin')
    assert helper, 'cifs-utils is required'
    rule = base / 'request-key.conf'
    # keyutils 1.6.x supports ONE wildcard per field, not shell glob syntax.
    # The kernel's v2 upcall description starts with this exact version/host.
    rule.write_text(f'create cifs.spnego ver=0x2;host={host};* * {helper} -k {config} %k\n')
    installed = '/etc/request-key.d/00-taucloud-' + uuid.uuid4().hex + '.conf'
    installed_rule = False
    proxy = HeaderProxy(fixture.smbport)
    try:
        run(['sudo', '-n', 'modprobe', 'cifs'])
        run(['sudo', '-n', 'install', '-m', '644', str(rule), installed])
        installed_rule = True
        code = '''import os,sys
from pathlib import Path
root=Path(sys.argv[1]);data=bytes(range(256))*4096
d=root/'kernel-kerberos';d.mkdir();p=d/'first'
with p.open('wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
assert p.read_bytes()==data
p.rename(d/'renamed');p=d/'renamed'
with p.open('r+b') as f:f.seek(17);f.write(b'kerberos');f.truncate(65537);f.flush();os.fsync(f.fileno())
assert p.read_bytes()==(data[:17]+b'kerberos'+data[25:])[:65537]
names=sorted(x.name for x in d.iterdir())
assert names==['renamed'], ('directory contents after rename', names)
p.unlink();d.rmdir()
'''
        for dialect in ('2.1', '3.0', '3.02', '3.1.1'):
            profile = dict(dialect=dialect, security='krb5', status='failed')
            report['profiles'].append(profile)
            options = f'ip=127.0.0.1,port={proxy.port},vers={dialect},sec=krb5,sign,cruid={os.getuid()},cache=none,nosharesock,soft'
            if dialect != '2.1':
                options += ',seal'
            try:
                run(['sudo', '-n', 'mount', '-t', 'cifs', '//' + host + '/smb', str(mount), '-o', options])
                run(['sudo', '-n', sys.executable, '-c', code, str(mount)], timeout=60)
                run(['sudo', '-n', 'umount', str(mount)])
                profile.update(status='passed', checks=['kernel CIFS Kerberos mount',
                    'mandatory signing' if dialect == '2.1' else 'required SMB3 encryption',
                    '1 MiB write/fsync/read', 'rename/overwrite/truncate/enumerate/delete'])
            finally:
                run(['sudo', '-n', 'umount', '-fl', str(mount)], timeout=15, check=False)
        report['status'] = 'passed'
    finally:
        proxy.close()
        output.resolve().with_suffix('.native-metadata.json').write_text(json.dumps(proxy.trace, indent=2)+'\n')
        if installed_rule:
            run(['sudo', '-n', 'rm', '--', installed], check=False)
        log = run(['sudo', '-n', 'dmesg', '--ctime'], check=False)
        output.resolve().with_suffix('.kernel.log').write_text('\n'.join(
            line for line in log.stdout.splitlines() if 'cifs' in line.lower() or 'smb' in line.lower())[-16000:] + '\n')
        log = run(['sudo', '-n', 'journalctl', '--no-pager', '--since', '@' + str(started),
                   '-t', 'cifs.upcall', '-t', 'request-key'], check=False)
        output.resolve().with_suffix('.upcall.log').write_text(log.stdout[-16000:])
