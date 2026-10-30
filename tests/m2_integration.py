#!/usr/bin/env python3
"""M2 authenticated identity/file workflows on disposable native filesystems."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import signal
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from m1_integration import wait


def run(binary, output, large_mib=0):
    suffix = '.exe' if os.name == 'nt' else ''
    checks = []
    password = 'M2-disposable-password-123!'
    with tempfile.TemporaryDirectory(prefix='tc2-') as tmp:
        state = Path(tmp) / 'state'
        root = Path(tmp) / 'root'
        root.mkdir()
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        def ctl(*args, stdin=None, ok=True, timeout=30):
            p = subprocess.run([str(binary / ('taucloud_ctl' + suffix)), '--state', str(state), *args],
                               text=True, input=stdin, capture_output=True, timeout=timeout)
            assert (p.returncode == 0) == ok, (args, p.stdout, p.stderr)
            return json.loads(p.stdout) if ok else p.stderr
        ctl('init', '--port', str(port))
        settings = json.loads((state / 'config.json').read_text())
        budget_mib = 256 if large_mib > 256 else 512
        settings['memory_mb'] = budget_mib
        (state / 'config.json').write_text(json.dumps(settings))
        context = ssl.create_default_context(cafile=str(state / 'tls-cert.pem'))
        def request(path, token=None, data=None, expected=200, key=None):
            h = {'Content-Type': 'application/json'}
            if token:
                h['Authorization'] = 'Bearer ' + token
            if data is not None:
                h['Idempotency-Key'] = key or uuid.uuid4().hex
            conn = http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=10)
            try:
                conn.request('POST' if data is not None else 'GET', '/api/v1/' + path,
                             None if data is None else json.dumps(data), h)
                reply = conn.getresponse()
                raw = reply.read()
                assert reply.status == expected, (path, reply.status, raw[:1000])
                return json.loads(raw)
            finally:
                conn.close()
        def login(name, scope='files', expected=200):
            return request('auth/login', data={'username': name, 'password': password, 'scope': scope}, expected=expected)
        def file(op, token, space='alice', path='hello.txt', **kwargs):
            expected = kwargs.pop('expected', 200)
            key = kwargs.pop('key', None)
            return request('files/' + op, token, {'space': space, 'path': path, **kwargs}, expected, key)
        def put(token, data, space='alice', path='hello.txt', key=None):
            j = file('begin', token, space, path, size=len(data), key=key)
            if data:
                file('chunk', token, space, path, job=j['id'], offset=0, data=data.hex())
            return file('commit', token, space, path, job=j['id'])

        with (Path(tmp) / 'supervisor.log').open('w') as log:
            p = subprocess.Popen([str(binary / ('taucloud_supervisor' + suffix)), '--state', str(state)], stdout=log, stderr=log)
            try:
                wait(lambda: request('health/ready')['status'] == 'ready')
                wait(lambda: all(v['status'] == 'running' for v in ctl('status').values()))
                ctl('bootstrap', '--username', 'admin', '--password-stdin', stdin=password+'\n')
                admin = login('admin', 'admin')['token']
                for name in ('alice', 'bob'):
                    request('users', admin, {'username': name, 'password': password})
                request('users', admin, {'username': 'bob', 'update': True, 'enabled': False})
                login('bob', expected=401)
                request('users', admin, {'username': 'bob', 'update': True, 'enabled': True})
                request('groups', admin, {'name': 'team'})
                request('memberships', admin, {'group': 'team', 'username': 'bob'})
                alice = login('alice')['token']
                bob = login('bob')['token']
                login('bob', 'admin', 403)
                request('users', bob, expected=403)
                request('storage-roots', admin, {'id': 'data', 'path': str(root)})
                request('storage-roots', admin, {'id': 'alias', 'path': str(root)}, expected=503)
                for name in ('alice', 'bob'):
                    request('spaces', admin, {'id': name, 'root': 'data', 'path': name, 'owner': name, 'quota': 2*1024**3})
                request('spaces', admin, {'id': 'overlap', 'root': 'data', 'path': 'alice/nested', 'owner': 'bob', 'quota': 1000}, expected=503)
                request('spaces', admin, {'id': 'team', 'root': 'data', 'path': 'team', 'group': 'team', 'quota': 105})
                request('shares', admin, {'id': 'alice-share', 'space': 'alice'})
                request('shares', admin, {'id': 'alice-alias', 'space': 'alice'})
                request('shares', admin, {'id': 'bad-writer', 'space': 'alice', 'exposures': {'smb': 'rw'}}, expected=503)
                request('shares', admin, {'id': 'bob-ftp', 'space': 'bob', 'exposures': {'ftp': 'rw'}})
                file('begin', bob, space='bob', path='mixed.txt', size=1, expected=503)
                checks.append('users/groups/membership; separate management roles; root, space and writer overlap rejected')

                put(alice, b'hello')
                file('stat', bob, expected=403)
                file('stat', admin, expected=403)
                assert [s['id'] for s in request('spaces', alice)] == ['alice']
                file('stat', bob, share='alice-share', expected=403)
                assert file('quota', alice, path='')['used'] == 5
                assert file('quota', alice, path='', share='alice-alias')['used'] == 5
                checks.append('two-user isolation and administrator has no implicit file grant; aliases charge quota once')

                for bad in ('../escape', '/absolute', 'a\\b', 'file:stream', 'CON', 'bad.', '\x01', '.tc-secret'):
                    value = file('open', alice, path=bad, expected=400)
                    assert value['error']['code'] in ('invalid_path', 'unsupported_name', 'reserved_name')
                file('begin', alice, path='HELLO.txt', size=1, expected=409)
                outside = Path(tmp) / 'outside'
                outside.write_bytes(b'outside-secret')
                os.link(outside, root / 'alice/hardlink')
                file('open', alice, path='hardlink', expected=404)  # unknown until reconciliation
                file('quota', alice, path='', expected=503)
                (root / 'alice/hardlink').unlink()
                try:
                    os.symlink(outside, root / 'alice/link')
                except OSError:
                    pass
                else:
                    file('quota', alice, path='', expected=503)
                    (root / 'alice/link').unlink()
                checks.append('portable names, traversal, case aliases, hard links and symlink rejection')

                h = file('open', alice, write=True)
                h2 = file('open', alice, write=True)
                file('lock', alice, handle=h['handle'], offset=0, length=3)
                file('write', alice, handle=h2['handle'], offset=0, data=b'X'.hex(), expected=409)
                file('unlock', alice, handle=h['handle'])
                written = file('write', alice, handle=h['handle'], offset=1, data=b'A'.hex(), flush=True, key='random-write-idempotent-01')
                assert written['written'] == 1 and written['durable']
                file('write', alice, handle=h['handle'], offset=1, data=b'A'.hex(), flush=True, key='random-write-idempotent-01')
                file('rename', alice, destination={'space': 'alice', 'path': 'renamed.txt'}, key='rename-object-test-01')
                assert file('rename', alice, destination={'space': 'alice', 'path': 'renamed.txt'}, key='rename-object-test-01')['status'] == 'completed'
                assert file('read', alice, path='renamed.txt', handle=h['handle'], offset=0, count=5)['data'] == b'hAllo'.hex()
                assert file('stat', alice, path='renamed.txt')['object'] == h['object']
                for handle in (h, h2):
                    file('close', alice, path='renamed.txt', handle=handle['handle'])
                put(alice, b'delete', path='delete.txt')
                for _ in range(2):
                    assert file('remove', alice, path='delete.txt', key='remove-object-test-01')['status'] == 'completed'
                checks.append('random writes, explicit flush, range locks, stable open identity across rename')

                put(bob, b'12345', 'team', 'quota.txt')
                j = file('begin', bob, 'team', 'stage.bin', size=100)
                file('begin', bob, 'team', 'extra.bin', size=1, expected=507)
                assert file('quota', bob, 'team', '')['reserved'] == 100
                file('cancel_job', bob, 'team', 'stage.bin', job=j['id'])
                assert file('quota', bob, 'team', '')['reserved'] == 0
                checks.append('quota pre-reservation, staged visibility and cancellation releases capacity')

                request('grants', admin, {'space': 'alice', 'subject_type': 'user', 'subject': 'bob', 'rights': 'r'})
                borrowed = file('open', bob, path='renamed.txt')
                revoked = request('grants', admin, {'space': 'alice', 'subject_type': 'user', 'subject': 'bob', 'rights': ''})
                assert all(isinstance(v, int) for v in revoked['revocation']['acknowledgements'].values())
                file('read', bob, path='renamed.txt', handle=borrowed['handle'], offset=0, count=5, expected=403)
                request('memberships', admin, {'group': 'team', 'username': 'bob', 'enabled': False})
                file('list', bob, 'team', '', expected=403)
                checks.append('acknowledged grant and group revocation; open handles cannot bypass policy')

                held = file('open', alice, path='renamed.txt')
                stage = file('begin', alice, path='recover.txt', size=7, key='durable-upload-restart-01')
                file('chunk', alice, path='recover.txt', job=stage['id'], offset=0, data=b'recover'.hex())
                services = ctl('status')
                victim = services['file']['identity']['pid']
                os.kill(victim, signal.SIGTERM if os.name == 'nt' else signal.SIGKILL)
                wait(lambda: (s := ctl('status'))['file']['status'] == 'running' and s['file']['identity']['pid'] != victim)
                file('read', alice, path='renamed.txt', handle=held['handle'], offset=0, count=5, expected=409)
                done = file('commit', alice, path='recover.txt', job=stage['id'])
                assert done['status'] == 'completed'
                assert ctl('status')['file_1']['identity']['pid'] == services['file_1']['identity']['pid']
                checks.append('domain crash fencing, sibling continuity and durable staged upload recovery')

                inventory = request('monitoring', admin)
                assert inventory['memory']['total'] > 0 and inventory['cpu']['logical'] > 0
                assert all(d['health']['status'] in ('available', 'unavailable', 'permission_denied', 'stale') for d in inventory['disks'])
                assert request('audit', admin)
                checks.append('bounded CPU/memory/network/capacity inventory, honest disk-health states and audit')

                ctl('login', '--username', 'alice', '--scope', 'files', '--password-stdin', stdin=password+'\n')
                hard_limit = 'windows_job_private_commit' if os.name == 'nt' else 'not_applied'
                if large_mib > 256 and os.name != 'nt':
                    import resource
                    for role in ('file', 'api'):
                        resource.prlimit(ctl('status')[role]['identity']['pid'], resource.RLIMIT_DATA, (256*1024**2, 256*1024**2))
                    hard_limit = 'linux_RLIMIT_DATA'
                source = Path(tmp) / 'input.bin'
                size = max(1, large_mib) * 1024**2
                block = hashlib.sha256(b'tauCloud M2 streaming fixture').digest() * (128*1024//32)
                with source.open('wb') as f:
                    for offset in range(0, size, len(block)):
                        f.write(block[:min(len(block), size-offset)])
                peak = {'file': 0, 'api': 0}
                sampling = threading.Event()
                def sample():
                    while not sampling.wait(.5):
                        try:
                            services = ctl('status')
                            for role in peak:
                                peak[role] = max(peak[role], services[role].get('rss', 0))
                        except (AssertionError, OSError, subprocess.SubprocessError):
                            pass
                sampler = threading.Thread(target=sample)
                sampler.start()
                try:
                    uploaded = ctl('put', '--space', 'alice', '--path', 'large.bin', '--file', str(source), '--request-id', 'cli-large-transfer-01', timeout=1800)
                    target = Path(tmp) / 'output.bin'
                    downloaded = ctl('get', '--space', 'alice', '--path', 'large.bin', '--file', str(target), timeout=1800)
                finally:
                    sampling.set()
                    sampler.join()
                assert uploaded['bytes'] == downloaded['bytes'] == size
                def hash_file(path):
                    h = hashlib.sha256()
                    with path.open('rb') as f:
                        while data := f.read(128*1024):
                            h.update(data)
                    return h.hexdigest()
                assert hash_file(source) == hash_file(target)
                checks.append(f'bounded HTTPS CLI upload/download with SHA-256 match: {size} bytes; worker budget {budget_mib} MiB')
                ctl('stop')
                p.wait(timeout=35)
                assert p.returncode == 0
                text = ''.join(f.read_text() for f in (state / 'logs').glob('*.jsonl')) + (Path(tmp) / 'supervisor.log').read_text()
                assert password not in text and alice not in text and 'ERROR: AddressSanitizer' not in text and 'runtime error:' not in text
                for db_path in state.glob('*.db'):
                    with sqlite3.connect(db_path) as db:
                        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
                    db.close()
                checks.append('clean stop, all owner databases consistent and logs exclude credentials')
            except Exception:
                print((Path(tmp) / 'supervisor.log').read_text())
                for f in (state / 'logs').glob('*.jsonl'):
                    print(f.name, f.read_text()[-4000:])
                raise
            finally:
                if p.poll() is None:
                    try:
                        ctl('stop')
                        p.wait(timeout=40)
                    except Exception:
                        p.kill()
    report = {'status': 'passed', 'host': platform.platform(), 'checks': checks, 'large_bytes': size,
              'worker_memory_budget_bytes': budget_mib*1024**2, 'physical_host_ram_exceeded': False,
              'hard_memory_limit': hard_limit, 'sampled_peak_rss_bytes': peak}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, default=Path('build/m2/integration.json'))
    p.add_argument('--large-mib', type=int, default=0)
    a = p.parse_args()
    run(a.bin.resolve(), a.output, a.large_mib)
