#!/usr/bin/env python3
"""Ed25519-verified, side-by-side update and crash-journal experiment."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile


def openssl():
    binary = shutil.which('openssl')
    if not binary and os.name == 'nt':
        candidate = Path(os.environ['ProgramFiles']) / 'Git/usr/bin/openssl.exe'
        if candidate.is_file():
            binary = str(candidate)
    if not binary:
        raise RuntimeError('OpenSSL 3 CLI required for Ed25519 fixture verification')
    return binary


def crypto(*args):
    return subprocess.run([openssl(), *map(str, args)], check=True, capture_output=True)


def flush_dir(path):
    if os.name != 'nt':
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write_durable(path, data):
    with path.open('xb') as file:
        file.write(data); file.flush(); os.fsync(file.fileno())
    flush_dir(path.parent)


@contextmanager
def database(root):
    db = sqlite3.connect(root / 'updates.sqlite')
    db.execute('PRAGMA synchronous=FULL')
    db.execute('CREATE TABLE IF NOT EXISTS journal (id INTEGER PRIMARY KEY CHECK(id=1), active TEXT, previous TEXT, target TEXT, phase TEXT, write_epoch INTEGER, switch_epoch INTEGER)')
    db.execute("INSERT OR IGNORE INTO journal VALUES (1, 'v1', NULL, NULL, 'healthy', 0, 0)")
    db.commit()
    try:
        with db:
            yield db
    finally:
        db.close()


def verify(root, package):
    # Fixture public key is provisioned outside the package. A package cannot
    # replace the trust anchor. Production trust-key rotation belongs to M8c.
    crypto('pkeyutl', '-verify', '-pubin', '-inkey', root / 'trusted.pem', '-rawin',
           '-in', package / 'manifest.json', '-sigfile', package / 'manifest.sig')
    manifest = json.loads((package / 'manifest.json').read_bytes())
    if (manifest['component'] != 'fixture-worker' or manifest['version'] != 'v2' or
            manifest['file'] != 'worker.bin' or manifest['sequence'] <= 1 or
            not manifest['ipc_min'] <= 1 <= manifest['ipc_max']):
        raise ValueError('package identity, freshness, path or IPC incompatibility')
    payload = package / manifest['file']
    if payload.is_symlink() or not payload.is_file():
        raise ValueError('nonregular payload')
    data = payload.read_bytes()
    if len(data) > 65536 or hashlib.sha256(data).hexdigest() != manifest['sha256']:
        raise ValueError('payload size/hash mismatch')
    return data


def crash(point, wanted):
    if point == wanted:
        os._exit(91)  # Deliberately skip Python/SQLite cleanup, like worker loss.


def install(root, point):
    source = root / 'package'
    data = verify(root, source)
    stage = root / 'versions/v2'
    stage.mkdir()
    write_durable(stage / 'worker.bin', data)
    for name in ('manifest.json', 'manifest.sig'):
        write_durable(stage / name, (source / name).read_bytes())
    flush_dir(stage.parent)
    crash('staged_files', point)
    with database(root) as db:
        db.execute("UPDATE journal SET previous=active, target='v2', phase='staged', switch_epoch=write_epoch")
    crash('staged', point)
    with database(root) as db:
        db.execute("UPDATE journal SET phase='intent'")
    crash('intent', point)
    with database(root) as db:
        db.execute("UPDATE journal SET active=target, phase='switched'")
    crash('switched', point)
    reconcile(root)
    crash('healthy', point)


def reconcile(root):
    with database(root) as db:
        active, previous, phase, epoch, switched = db.execute(
            'SELECT active,previous,phase,write_epoch,switch_epoch FROM journal').fetchone()
        if phase in ('staged', 'intent'):
            db.execute("UPDATE journal SET target=NULL,phase='aborted'")
        elif phase == 'switched':
            try:
                payload = verify(root, root / 'versions' / active)
                if payload != b'healthy-v2':
                    raise ValueError('health failed')
                db.execute("UPDATE journal SET phase='healthy'")
            except (ValueError, OSError, subprocess.CalledProcessError):
                if epoch != switched:
                    db.execute("UPDATE journal SET phase='recovery_required'")
                else:
                    db.execute("UPDATE journal SET active=previous,phase='rolled_back'")
        return db.execute('SELECT active,phase FROM journal').fetchone()


def package(root, payload=b'healthy-v2', **changes):
    target = root / 'package'
    target.mkdir(exist_ok=True)
    (target / 'worker.bin').write_bytes(payload)
    manifest = {'component': 'fixture-worker', 'version': 'v2', 'sequence': 2,
                'file': 'worker.bin', 'sha256': hashlib.sha256(payload).hexdigest(),
                'ipc_min': 1, 'ipc_max': 2, **changes}
    (target / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True))
    crypto('pkeyutl', '-sign', '-inkey', root / 'private.pem', '-rawin',
           '-in', target / 'manifest.json', '-out', target / 'manifest.sig')


def fixture(root, keys):
    root.mkdir()
    (root / 'versions/v1').mkdir(parents=True)
    (root / 'versions/v1/worker.bin').write_bytes(b'healthy-v1')
    for name in ('private.pem', 'trusted.pem'):
        shutil.copyfile(keys / name, root / name)
    with database(root):
        pass
    package(root)


def probe():
    with tempfile.TemporaryDirectory(prefix='taucloud-m0-update-') as temporary:
        temporary = Path(temporary)
        crypto('genpkey', '-algorithm', 'ED25519', '-out', temporary / 'private.pem')
        crypto('pkey', '-in', temporary / 'private.pem', '-pubout', '-out', temporary / 'trusted.pem')
        for point in ('staged_files', 'staged', 'intent', 'switched', 'healthy'):
            root = temporary / point; fixture(root, temporary)
            child = subprocess.run([sys.executable, __file__, '--install', str(root), '--crash', point],
                                   capture_output=True, timeout=15)
            assert child.returncode == 91, child.stderr.decode()
            active, _ = reconcile(root)
            assert active == ('v2' if point in ('switched', 'healthy') else 'v1')
            assert (root / 'versions/v1/worker.bin').read_bytes() == b'healthy-v1'
        for kind in ('signature', 'payload', 'path', 'version', 'rollback', 'unsafe_rollback'):
            root = temporary / kind; fixture(root, temporary)
            if kind == 'signature':
                (root / 'package/manifest.sig').write_bytes(bytes(64))
            elif kind == 'payload':
                (root / 'package/worker.bin').write_bytes(b'tampered')
            elif kind == 'path':
                package(root, file='../escape')
            elif kind == 'version':
                package(root, ipc_min=3, ipc_max=3)
            else:
                package(root, payload=b'unhealthy')
            if kind in ('rollback', 'unsafe_rollback'):
                child = subprocess.run([sys.executable, __file__, '--install', str(root), '--crash', 'switched'],
                                       capture_output=True, timeout=15)
                assert child.returncode == 91, child.stderr.decode()
                if kind == 'unsafe_rollback':
                    with database(root) as db:
                        db.execute('UPDATE journal SET write_epoch=1')
                result = reconcile(root)
                assert result == (('v1', 'rolled_back') if kind == 'rollback' else ('v2', 'recovery_required'))
            else:
                try:
                    install(root, None)
                    raise AssertionError('invalid package installed')
                except (ValueError, subprocess.CalledProcessError):
                    pass
                assert reconcile(root) == ('v1', 'healthy')
        return {'probe': 'updates', 'status': 'passed', 'checks': 11,
                'crypto': crypto('version').stdout.decode().strip(), 'sqlite': sqlite3.sqlite_version,
                'power_loss_durability': 'not_tested'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--install', type=Path)
    parser.add_argument('--crash')
    args = parser.parse_args()
    if args.install:
        install(args.install, args.crash)
    else:
        print(json.dumps(probe()))
