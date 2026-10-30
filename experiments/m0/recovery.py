#!/usr/bin/env python3
"""Disposable multi-process IPC/fencing experiment; no production service."""
import argparse
import hashlib
import hmac
import json
import multiprocessing.connection as ipc
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

MAX_FRAME = 65536
MAX_LEASE = 2.0


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def mac(key, value):
    return hmac.new(bytes.fromhex(key), encoded(value), hashlib.sha256).hexdigest()


def send(connection, value):
    data = encoded(value)
    if len(data) > MAX_FRAME:
        raise ValueError('oversized frame')
    connection.send_bytes(data)


def receive(connection):
    if not connection.poll(2):
        raise TimeoutError('IPC deadline')
    return json.loads(connection.recv_bytes(MAX_FRAME))


def lock_domain(path):
    file = open(path, 'a+b')
    file.seek(0)
    if os.name == 'nt':
        import msvcrt
        # The fixture pre-creates this byte before starting workers.
        msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    return file


def authorize(config, grant, action):
    if not isinstance(grant, dict) or set(grant) != {'body', 'signature'}:
        return False
    body = grant['body']
    if not isinstance(body, dict):
        return False
    if not hmac.compare_digest(mac(config['issuer_key'], body), grant['signature']):
        return False
    now = time.monotonic()
    return (body.get('subject') == 'alice' and body.get('resource') == config['domain'] and
            body.get('generation') == config['generation'] and body.get('action') == action and
            isinstance(body.get('issued'), (int, float)) and isinstance(body.get('expires'), (int, float)) and
            body['issued'] <= now < body['expires'] and
            0 < body['expires'] - body['issued'] <= MAX_LEASE)


def worker(config):
    with lock_domain(config['lock']), ipc.Listener(config['address'], family=config['family']) as listener:
        while True:
            with listener.accept() as connection:
                try:
                    challenge = {'nonce': secrets.token_hex(32), 'instance': config['instance']}
                    send(connection, {'challenge': challenge, 'signature': mac(config['ipc_key'], challenge)})
                    request = receive(connection)
                    body = request['body']
                    if request['nonce'] != challenge['nonce'] or not hmac.compare_digest(
                            mac(config['ipc_key'], {'nonce': request['nonce'], 'body': body}), request['signature']):
                        raise ValueError('unauthenticated caller')
                    if not 1 <= body['version'] <= 2:
                        response = {'error': 'version'}
                    elif body['deadline'] < time.monotonic():
                        response = {'error': 'deadline'}
                    elif body['generation'] != config['generation']:
                        response = {'error': 'stale_generation'}
                    elif body['op'] == 'health':
                        response = {'pid': os.getpid(), 'instance': config['instance'],
                                    'generation': config['generation'], 'version': body['version']}
                    elif body['op'] == 'read':
                        response = {'data': 'fixture'} if authorize(config, body.get('grant'), 'read') else {'error': 'grant'}
                    else:
                        response = {'error': 'unsupported'}
                    # Bind reply to this request and challenge, including the request ID.
                    reply = {'request_id': body['request_id'], 'nonce': request['nonce'], 'result': response}
                    send(connection, {'body': reply, 'signature': mac(config['ipc_key'], reply)})
                except (OSError, EOFError, ValueError, KeyError, TypeError, TimeoutError):
                    pass


def call(config, **fields):
    with ipc.Client(config['address'], family=config['family']) as connection:
        greeting = receive(connection)
        challenge = greeting['challenge']
        if challenge['instance'] != config['instance'] or not hmac.compare_digest(
                mac(config['ipc_key'], challenge), greeting['signature']):
            raise ValueError('server authentication failed')
        body = {'version': 1, 'deadline': time.monotonic() + 2, 'generation': config['generation'],
                'op': 'health', 'request_id': secrets.token_hex(16), **fields}
        envelope = {'nonce': challenge['nonce'], 'body': body}
        send(connection, {**envelope, 'signature': mac(config['ipc_key'], envelope)})
        response = receive(connection)
        if not hmac.compare_digest(mac(config['ipc_key'], response['body']), response['signature']):
            raise ValueError('reply authentication failed')
        reply = response['body']
        if reply['nonce'] != challenge['nonce'] or reply['request_id'] != body['request_id']:
            raise ValueError('replayed reply')
        return reply['result']


def grant(config, ttl=1):
    now = time.monotonic()
    body = {'subject': 'alice', 'resource': config['domain'], 'generation': config['generation'],
            'action': 'read', 'issued': now, 'expires': now + ttl}
    return {'body': body, 'signature': mac(config['issuer_key'], body)}


def start(path, config):
    path.write_text(json.dumps(config))
    os.chmod(path, 0o600)
    process = subprocess.Popen([sys.executable, __file__, '--worker', str(path)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode())
            try:
                if call(config)['pid'] == process.pid:
                    return process
            except (OSError, EOFError):
                time.sleep(0.02)
        raise TimeoutError('worker readiness')
    except BaseException:
        process.kill(); process.communicate(timeout=5)
        raise


def probe():
    processes = []
    with tempfile.TemporaryDirectory(prefix='taucloud-m0-ipc-') as temporary:
        root = Path(temporary)
        def configuration(domain):
            path = root / (domain + '.lock')
            path.write_bytes(b'0')
            return {'domain': domain, 'generation': 1, 'instance': secrets.token_hex(16),
                    'ipc_key': secrets.token_hex(32), 'issuer_key': secrets.token_hex(32),
                    'address': (r'\\.\pipe\taucloud-m0-' + secrets.token_hex(12)) if os.name == 'nt' else str(root / (domain + '.sock')),
                    'family': 'AF_PIPE' if os.name == 'nt' else 'AF_UNIX', 'lock': str(path)}
        a, b = configuration('volume-a'), configuration('volume-b')
        try:
            first = start(root / 'a.json', a); processes.append(first)
            sibling = start(root / 'b.json', b); processes.append(sibling)
            healthy = call(b)
            assert call(a, op='read', grant=grant(a)) == {'data': 'fixture'}
            assert call(a, op='read', grant=grant(b)) == {'error': 'grant'}
            tampered = grant(a); tampered['body']['subject'] = 'mallory'
            assert call(a, op='read', grant=tampered) == {'error': 'grant'}
            assert call(a, op='read', grant=grant(a, 10)) == {'error': 'grant'}
            expired = grant(a, 0.01); time.sleep(0.02)
            assert call(a, op='read', grant=expired) == {'error': 'grant'}
            assert call(a, version=2)['version'] == 2
            assert call(a, version=3) == {'error': 'version'}
            assert call(a, deadline=0) == {'error': 'deadline'}
            wrong = {**a, 'ipc_key': secrets.token_hex(32)}
            try:
                call(wrong)
                raise AssertionError('wrong peer key accepted')
            except ValueError:
                pass
            # A fresh supervisor process adopts the live child only after challenge proof.
            adopted = subprocess.check_output([sys.executable, __file__, '--adopt', str(root / 'a.json')], timeout=5)
            assert json.loads(adopted)['pid'] == first.pid
            duplicate = subprocess.run([sys.executable, __file__, '--worker', str(root / 'a.json')],
                                       capture_output=True, timeout=5)
            assert duplicate.returncode != 0, 'two storage owners acquired same domain'
            old = grant(a)
            first.kill(); first.communicate(timeout=5)
            assert call(b) == healthy, 'sibling traffic interrupted'
            if a['family'] == 'AF_UNIX':
                Path(a['address']).unlink(missing_ok=True)
            a = {**a, 'generation': 2, 'instance': secrets.token_hex(16)}
            replacement = start(root / 'a.json', a); processes.append(replacement)
            assert call(a, generation=1) == {'error': 'stale_generation'}
            assert call(a, op='read', grant=old) == {'error': 'grant'}
            assert call(a, op='read', grant=grant(a)) == {'data': 'fixture'}
            assert call(b) == healthy
            return {'probe': 'recovery', 'status': 'passed', 'transport': a['family'], 'checks': 17,
                    'limits': 'serial prototype; production ACL/admission and durable generation authority pending'}
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', type=Path)
    parser.add_argument('--adopt', type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(json.loads(args.worker.read_text()))
    elif args.adopt:
        print(json.dumps(call(json.loads(args.adopt.read_text()))))
    else:
        print(json.dumps(probe()))
