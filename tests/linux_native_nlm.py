#!/usr/bin/env python3
"""Native Linux NFSv3 blocking locks/reclaim on a disposable Actions runner."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid
import xdrlib3 as xdr

from m1_integration import wait
from m7_integration import Client, t3
from pynfs_acceptance import fixture


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    assert sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true', 'disposable Linux Actions runner required'
    f, port = fixture(args.bin)
    rules, clients, checks = [], [], []
    mounted, process, log = False, None, None
    report = dict(status='failed', checks=checks)
    mount = f.base / 'native-nlm'; mount.mkdir()
    def run(command, timeout=30):
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
        if result.returncode: raise RuntimeError((command, result.stdout, result.stderr))
        return result.stdout
    try:
        f.api('grants', f.admin, dict(space='nfsdata', subject_type='user', subject='bob', rights='rw'))
        f.api('nfs-exports', f.admin, dict(id='nfs', trust='loopback-auth-sys', anonymous='bob',
            uids={str(os.getuid()):'alice'}, gids={str(g):'unix' for g in set(os.getgroups()+[os.getgid()])}, update=True))
        f.stop()
        config = json.loads((f.state / 'config.json').read_text())
        config['nfs_address'] = '127.0.0.2'
        (f.state / 'config.json').write_text(json.dumps(config)); f.start()
        run(['sudo', '-n', 'systemctl', 'start', 'rpcbind', 'rpc-statd'])
        # Keep the real client's rpcbind/statd on .1. Only this fixture's .2
        # discovery is redirected to the isolated server, for both TCP and NSM UDP.
        marker = 'taucloud-nlm-' + uuid.uuid4().hex
        for protocol in ('tcp', 'udp'):
            rule = ['-d', '127.0.0.2', '-p', protocol, '--dport', '111', '-m', 'comment',
                    '--comment', marker, '-j', 'DNAT', '--to-destination', f'127.0.0.2:{port}']
            run(['sudo', '-n', 'iptables', '-t', 'nat', '-I', 'OUTPUT'] + rule)
            rules.append(rule)
        def connect():
            c = Client(port, uid=os.getuid(), gid=os.getgid(), groups=os.getgroups(), address='127.0.0.2')
            clients.append(c); return c
        c = connect(); status, root = c.mount(); assert status == 0
        attrs = t3.sattr3(t3.set_mode3(True, 0o666), t3.set_uid3(False), t3.set_gid3(False),
                          t3.set_size3(False), t3.set_atime(0), t3.set_mtime(0))
        result = c.v3('CREATE', t3.CREATE3args(t3.diropargs3(t3.nfs_fh3(root), b'locked'), t3.createhow3(1, attrs)), 8)
        assert result.status == 0, result
        handle = result.resok.obj.handle.data
        data = b'native-nlm-payload'
        assert c.v3('WRITE', t3.WRITE3args(t3.nfs_fh3(handle), 0, len(data), 2, data), 7).status == 0
        def lock(proc):
            body = xdr.Packer(); body.pack_bytes(b'independent')
            if proc == 2: body.pack_bool(False)
            if proc != 4: body.pack_bool(True)
            body.pack_string(b'wire-peer'); body.pack_bytes(handle); body.pack_bytes(b'independent-owner')
            body.pack_uint(123); body.pack_uhyper(0); body.pack_uhyper(10)
            if proc == 2: body.pack_bool(False); body.pack_uint(1)
            u = xdr.Unpacker(c.exchange(c.packet(100021, 4, proc, body.get_buffer())))
            assert u.unpack_bytes() == b'independent'
            return u.unpack_uint()
        assert lock(2) == 0
        options = f'vers=3,proto=tcp,port={port},mountproto=tcp,mountport={port},mountvers=3,sec=sys,lock,soft,timeo=10,retrans=1'
        run(['sudo', '-n', 'mount', '-t', 'nfs', '-o', options, '127.0.0.2:/nfs', str(mount)])
        mounted = True
        helper = r'''import fcntl,sys,time
from pathlib import Path
mount,events=map(Path,sys.argv[1:])
with (mount/'locked').open('r+b', buffering=0) as file:
    (events/'attempting').touch()
    fcntl.lockf(file, fcntl.LOCK_EX, 10, 0)
    assert file.read()==b'native-nlm-payload'
    (events/'acquired').touch()
    end=time.monotonic()+150
    while not (events/'release').exists():
        assert time.monotonic()<end, 'parent did not release native lock'
        time.sleep(.1)
    fcntl.lockf(file, fcntl.LOCK_UN, 10, 0)
'''
        events = f.base / 'lock-events'; events.mkdir()
        log = (f.base / 'native-lock.log').open('w')
        process = subprocess.Popen([sys.executable, '-c', helper, str(mount), str(events)], stdout=log, stderr=log)
        wait(lambda: (events / 'attempting').exists(), timeout=15)
        time.sleep(1)
        assert not (events / 'acquired').exists() and process.poll() is None
        assert lock(4) == 0
        wait(lambda: (events / 'acquired').exists(), timeout=15)
        assert lock(1) == 1, 'independent NLM TEST must observe the native client lock'
        checks.append('native F_SETLKW blocks on an independent wire owner, receives GRANTED and retains a server-visible byte lock')
        before = f.ctl('status')
        pid = before['nfs']['identity']['pid']
        os.kill(pid, signal.SIGKILL)
        wait(lambda: (entry := f.ctl('status')['nfs'])['status'] == 'running' and entry['identity']['pid'] != pid)
        c = connect()
        # An independent wire TEST, after grace, cannot be satisfied by the
        # kernel's local lock cache. It proves that native reclaim reached us.
        deadline = time.monotonic() + 75
        while True:
            state = lock(1)
            if state != 4: break
            assert time.monotonic() < deadline, 'recovery grace did not end'
            time.sleep(1)
        assert state == 1, 'native lock was not reclaimed on the server'
        assert process.poll() is None
        (events / 'release').touch()
        process.wait(timeout=20); log.close()
        assert process.returncode == 0, (f.base / 'native-lock.log').read_text()
        wait(lambda: lock(1) == 0, timeout=10)
        assert f.ctl('status')['file']['identity']['pid'] == before['file']['identity']['pid']
        checks.append('NSM server-reboot notification makes the Linux kernel reclaim its lock; independent post-grace TEST observes it and native unlock releases it')
        report['status'] = 'passed'
    except Exception:
        import traceback
        report['error'] = traceback.format_exc()
    finally:
        def cleanup(command):
            try: return run(command)
            except Exception as error:
                report['status'] = 'failed'
                report.setdefault('cleanup_errors', []).append(str(error))
                return ''
        if process is not None and process.poll() is None:
            process.kill(); process.wait(timeout=10)
        if log is not None: log.close()
        if mounted:
            try: run(['sudo', '-n', 'umount', str(mount)])
            except Exception:
                report['status'] = 'failed'
                cleanup(['sudo', '-n', 'umount', '-lf', str(mount)])
        for rule in reversed(rules):
            cleanup(['sudo', '-n', 'iptables', '-t', 'nat', '-D', 'OUTPUT'] + rule)
        for c in clients: c.close()
        report['worker_logs'] = {role:path.read_text()[-32768:] for role in ('nfs', 'file')
            if (path := f.state / 'logs' / (role + '.jsonl')).exists()}
        report['kernel_log'] = cleanup(['sudo', '-n', 'dmesg', '--ctime'])[-16384:]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        f.close()
    print(json.dumps({k:v for k,v in report.items() if k not in ('worker_logs','kernel_log')}, indent=2))
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
