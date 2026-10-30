#!/usr/bin/env python3
"""Export and verify the locked Git object, never a neighbour's working tree."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def digest(root):
    result = hashlib.sha256()
    for item in sorted(root.rglob('*'), key=lambda item: item.relative_to(root).as_posix()):
        if item.is_symlink():
            raise ValueError('symlinks are not permitted in the dependency export')
        if item.is_file():
            result.update(item.relative_to(root).as_posix().encode() + b'\0')
            result.update(hashlib.sha256(item.read_bytes()).digest())
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--git-source', help='Optional offline Git object database (ignores working tree)')
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--dependency', choices=['pace', 'recipes', 'pynfs'], default='pace')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'dependencies.lock.json').read_text())[args.dependency]
    destination = ROOT / '.deps' / args.dependency
    if destination.exists() or args.verify:
        if not destination.is_dir() or digest(destination) != lock['source_sha256']:
            raise SystemExit(args.dependency + ' export is missing or modified; remove its .deps export and fetch again')
        print(args.dependency + ' verified: ' + lock['revision'])
        return
    destination.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        temporary = Path(temporary)
        source = args.git_source
        if source is None:
            source = str(temporary / 'repository')
            subprocess.run(['git', 'init', '--bare', source], check=True, capture_output=True)
            subprocess.run(['git', '-C', source, 'fetch', '--depth=1', lock['url'], lock['revision']], check=True)
        # git archive applies checkout conversion too. Hosted Windows runners set
        # core.autocrlf=true globally; the locked export always uses Git's LF bytes.
        archive = subprocess.check_output(['git', '-c', 'core.autocrlf=false', '-c', 'core.eol=lf',
                                           '-C', source, 'archive', '--format=tar', lock['revision']])
        export = temporary / 'export'
        export.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            for member in tar:
                # The pinned pynfs export omits its unused NFSv4.0 convenience
                # symlinks. No archive links are created or followed.
                if args.dependency == 'pynfs' and member.issym() and member.name.startswith('nfs4.0/'):
                    continue
                path = Path(member.name)
                if path.is_absolute() or '..' in path.parts or not (member.isdir() or member.isfile()):
                    raise ValueError('unsafe dependency archive')
                target = export / path
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as data:
                        target.write_bytes(data.read())
        if digest(export) != lock['source_sha256']:
            raise SystemExit(args.dependency + ' source digest mismatch')
        shutil.move(str(export), destination)
    print(args.dependency + ' acquired: ' + lock['revision'])


if __name__ == '__main__':
    main()
