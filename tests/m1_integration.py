#!/usr/bin/env python3
"""Independent HTTPS client and real-process M1 acceptance; disposable local state."""
import argparse
import datetime
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
import time


def wait(check, timeout=25):
    until = time.monotonic() + timeout
    last = None
    while time.monotonic() < until:
        try:
            value = check()
            if value:
                return value
        except (OSError, ValueError, AssertionError, subprocess.SubprocessError) as exc:
            last = exc
        time.sleep(.1)
    raise AssertionError(f"condition timed out: {last}")


def run(bin_dir, output):
    suffix = '.exe' if os.name == 'nt' else ''
    checks = []
    succeeded = False
    children = []
    password = 'M1-test-only-strong-passphrase!'
    with tempfile.TemporaryDirectory(prefix='tc1-') as tmp:
        state = Path(tmp) / 'state'
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        def ctl(*args, ok=True, stdin=None):
            result = subprocess.run([str(bin_dir / ('taucloud_ctl' + suffix)), '--state', str(state), *args],
                                    input=stdin, text=True, capture_output=True, timeout=20)
            assert (result.returncode == 0) == ok, (args, result.stdout, result.stderr)
            return json.loads(result.stdout) if ok else result.stderr

        ctl('init', '--port', str(port))
        context = ssl.create_default_context(cafile=str(state / 'tls-cert.pem'))
        def request(path, method='GET', body=None, headers=None, token=None, expected=200, trust=context):
            conn = http.client.HTTPSConnection('127.0.0.1', port, context=trust, timeout=8)
            h = {'Content-Type': 'application/json', **(headers or {})}
            if token:
                h['Authorization'] = 'Bearer ' + token
            try:
                conn.request(method, '/api/v1/' + path, json.dumps(body) if body is not None else None, h)
                response = conn.getresponse()
                raw = response.read()
                assert response.status == expected, (path, response.status, raw)
                return (json.loads(raw) if response.status != 413 else {'rejected': True}), dict(response.getheaders())
            finally:
                conn.close()

        log_path = Path(tmp) / 'services.log'
        with log_path.open('w') as log:
            def start(allow_degraded=False):
                p = subprocess.Popen([str(bin_dir / ('taucloud_supervisor' + suffix)), '--state', str(state)],
                                     stdout=log, stderr=log)
                children.append(p)
                wait(lambda: request('health/ready')[0]['status'] == 'ready')
                wait(lambda: all(s['status'] == 'running' or (allow_degraded and r == 'helper' and s['status'] == 'crash_loop')
                                 for r, s in ctl('status').items()))
                return p
            try:
                supervisor = start()
                checks.append('all service targets start and readiness resolves dependencies')
                duplicate = subprocess.run([str(bin_dir / ('taucloud_supervisor' + suffix)), '--state', str(state)],
                                           capture_output=True, timeout=10)
                assert duplicate.returncode != 0
                checks.append('single supervisor owner fence')
                ctl('bootstrap', '--username', 'admin', '--password-stdin', stdin=password+'\n')
                assert not (state / 'bootstrap.json').exists()
                ctl('bootstrap', '--username', 'other', '--password-stdin', stdin=password+'\n', ok=False)
                checks.append('one-use local administrator bootstrap')
                request('capabilities', expected=401)
                request('auth/login', 'POST', {'username': 'admin', 'password': 'incorrect'}, expected=401)
                try:
                    request('health/live', trust=ssl.create_default_context())
                    raise AssertionError('untrusted certificate accepted')
                except ssl.SSLCertVerificationError:
                    pass
                checks.append('unauthenticated, incorrect password and untrusted TLS rejected')
                request('auth/login', 'POST', {'padding': 'x' * 9000}, expected=413)
                idle = [socket.create_connection(('127.0.0.1', port), timeout=3) for _ in range(32)]
                try:
                    time.sleep(.2)
                    try:
                        request('health/live')
                        raise AssertionError('connection admission was unbounded')
                    except (OSError, http.client.HTTPException):
                        pass
                    wait(lambda: request('health/live')[0]['status'] == 'ok', timeout=8)
                finally:
                    for connection in idle:
                        connection.close()
                checks.append('HTTP body limit, connection admission and idle TLS timeout')
                ctl('login', '--username', 'admin', '--password-stdin', stdin=password+'\n')
                token = json.loads((state / 'cli-session.json').read_text())['token']
                assert ctl('whoami')['username'] == 'admin'
                caps = ctl('capabilities')
                assert caps['management'] and caps['file_service'] and caps['protocols'] == []
                request('services/restart', 'POST', {'role': 'file'}, token=token,
                        headers={'Idempotency-Key': 'readonly-restart-001'}, expected=403)
                checks.append('authenticated CLI and truthful capabilities; read scope cannot restart')
                # Revocation must also work for read-scoped sessions.
                ctl('logout')
                request('auth/me', token=token, expected=401)
                checks.append('read-scoped session logout and immediate revocation')
                ctl('login', '--username', 'admin', '--password-stdin', '--scope', 'admin', stdin=password+'\n')
                token = json.loads((state / 'cli-session.json').read_text())['token']
                browser, headers = request('auth/login', 'POST', {'username': 'admin', 'password': password,
                         'kind': 'browser', 'scope': 'admin'}, headers={'Origin': f'https://127.0.0.1:{port}'})
                cookie = headers['Set-Cookie']
                assert all(flag in cookie for flag in ('Secure', 'HttpOnly', 'SameSite=Strict', 'Path=/'))
                assert 'token' not in browser
                cookie = cookie.split(';')[0]
                request('auth/me', headers={'Cookie': cookie})
                request('auth/me', token=cookie.split('=', 1)[1], expected=401)
                request('auth/logout', 'POST', headers={'Cookie': cookie, 'Origin': f'https://127.0.0.1:{port}'}, expected=403)
                request('auth/logout', 'POST', headers={'Cookie': cookie, 'Origin': 'https://evil.example',
                        'X-CSRF-Token': browser['csrf']}, expected=403)
                request('auth/logout', 'POST', headers={'Cookie': cookie, 'Origin': f'https://127.0.0.1:{port}',
                        'X-CSRF-Token': browser['csrf']})
                request('auth/me', headers={'Cookie': cookie}, expected=401)
                checks.append('browser secure cookies, exact-origin CORS, CSRF and revocation')
                before = ctl('services')
                request_id = 'integration-restart-0001'
                first, _ = request('services/restart', 'POST', {'role': 'file'}, token=token,
                                   headers={'Idempotency-Key': request_id}, expected=202)
                after = wait(lambda: (s if (s := ctl('services'))['file']['status'] == 'running'
                            and s['file']['identity']['pid'] != before['file']['identity']['pid'] else None))
                repeated, _ = request('services/restart', 'POST', {'role': 'file'}, token=token,
                                      headers={'Idempotency-Key': request_id}, expected=202)
                assert repeated['generation'] == first['generation']
                assert after['identity']['identity']['pid'] == before['identity']['identity']['pid']
                checks.append('idempotent restart and sibling continuity')
                supervisor.kill()
                supervisor.wait(timeout=10)
                adopted = start()
                services = ctl('services')
                assert all(services[r]['identity']['pid'] == after[r]['identity']['pid'] for r in services)
                assert ctl('whoami')['username'] == 'admin'
                checks.append('supervisor crash verified adoption preserves workers and session')
                # Independent abnormal worker termination, followed by automatic replacement.
                victim = services['monitor']['identity']['pid']
                os.kill(victim, signal.SIGTERM if os.name == 'nt' else signal.SIGKILL)
                wait(lambda: (s := ctl('services'))['monitor']['status'] == 'running' and
                     s['monitor']['identity']['pid'] != victim)
                assert ctl('services')['monitor']['generation'] != services['monitor']['generation']
                checks.append('abrupt worker death recovers with backoff')
                for _ in range(5):
                    services = ctl('services')
                    victim = services['helper']['identity']['pid']
                    os.kill(victim, signal.SIGTERM if os.name == 'nt' else signal.SIGKILL)
                    wait(lambda: (s := ctl('services'))['helper']['status'] == 'crash_loop' or
                         (s['helper']['status'] == 'running' and s['helper']['identity']['pid'] != victim))
                assert ctl('services')['helper']['status'] == 'crash_loop'
                checks.append('persistent crash-loop limit')
                ctl('stop')
                adopted.wait(timeout=30)
                assert adopted.returncode == 0
                checks.append('graceful dependency-ordered shutdown')
                # Reconstruct a prior schema, then crash with a migration transaction open.
                database = sqlite3.connect(state / 'identity.db')
                database.executescript('DROP TABLE records; DROP TABLE memberships; DROP TABLE grants; DROP TABLE policy_state; DROP TABLE policy_audit; DROP TABLE policy_requests; ALTER TABLE users DROP COLUMN role; ALTER TABLE users DROP COLUMN enabled; DROP TABLE sessions; DROP TABLE attempts; PRAGMA user_version=1;')
                database.close()
                crash = 'import sqlite3,os,sys; c=sqlite3.connect(sys.argv[1]); c.execute("BEGIN IMMEDIATE"); c.execute("CREATE TABLE interrupted(value TEXT)"); os._exit(71)'
                result = subprocess.run([__import__('sys').executable, '-c', crash, str(state / 'identity.db')])
                assert result.returncode == 71
                recovered = start(allow_degraded=True)
                assert ctl('status')['helper']['status'] == 'crash_loop'
                assert (state / 'identity.pre-v2.db').exists()
                ctl('login', '--username', 'admin', '--password-stdin', stdin=password+'\n')
                assert ctl('whoami')['username'] == 'admin'
                ctl('stop')
                recovered.wait(timeout=30)
                checks.append('abrupt migration transaction recovery and pre-upgrade backup')
                # No secret is present in database values or structured logs.
                database = sqlite3.connect(state / 'identity.db')
                assert database.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
                assert database.execute('PRAGMA user_version').fetchone()[0] == 4
                assert database.execute("SELECT count(*) FROM sqlite_master WHERE name='interrupted'").fetchone()[0] == 0
                verifier = database.execute('SELECT verifier FROM users').fetchone()[0]
                assert password not in verifier and len(verifier) == 64
                assert database.execute('SELECT count(*) FROM sessions WHERE hash=?', (token,)).fetchone()[0] == 0
                database.close()
                text = log_path.read_text() + ''.join(p.read_text() for p in (state / 'logs').glob('*.jsonl'))
                assert password not in text and token not in text
                assert 'ERROR: AddressSanitizer' not in text and 'runtime error:' not in text
                checks.append('SQLite integrity, hashed tokens/passwords, redacted logs')
                succeeded = True
            finally:
                for p in children:
                    if p.poll() is None:
                        try:
                            ctl('stop')
                            p.wait(timeout=30)
                        except Exception:
                            p.kill()
                # Test fixture cleanup only: child PIDs recorded under this temporary state.
                for instance in state.glob('*.instance.json'):
                    try:
                        pid = json.loads(instance.read_text())['pid']
                        if os.name != 'nt' and Path(f'/proc/{pid}/cmdline').exists():
                            assert str(state).encode() in Path(f'/proc/{pid}/cmdline').read_bytes()
                            os.kill(pid, signal.SIGKILL)
                    except (OSError, KeyError, AssertionError):
                        pass
                if not succeeded:
                    print(log_path.read_text())
    report = {'schema': 1, 'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'host': platform.platform(), 'python': platform.python_version(), 'checks': checks, 'status': 'passed'}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('build/m1/integration.json'))
    args = parser.parse_args()
    run(args.bin.resolve(), args.output)
