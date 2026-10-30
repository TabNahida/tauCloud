#!/usr/bin/env python3
"""Build and verify backend-only M1 on Linux/GCC, Linux/Clang or Windows/MSVC."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', choices=['gcc', 'clang', 'msvc'], required=True)
    parser.add_argument('--sanitizers', action='store_true')
    parser.add_argument('--skip-build', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    os.chdir(ROOT)
    host = 'windows' if os.name == 'nt' else 'linux'
    arch = 'x64' if os.name == 'nt' else 'x86_64'
    suffix = '.exe' if os.name == 'nt' else ''
    binary = ROOT / 'build' / host / arch / 'debug'
    output = args.output or ROOT / 'build/m1' / f'{host}-{args.compiler}.json'
    commands = [[sys.executable, 'scripts/fetch_pace.py', '--verify'],
                [sys.executable, 'scripts/fetch_pace.py', '--dependency', 'recipes', '--verify']]
    if not args.skip_build:
        commands += [['xmake', 'f', '-y', '-c', '-p', host, '-a', arch, '-m', 'debug',
                      '--m0=n', '--m1=y', '--toolchain=' + args.compiler,
                      '--sanitizers=' + ('y' if args.sanitizers else 'n')], ['xmake', '-y', '-j', '8']]
    commands += [[str(binary / ('taucloud_m1_tests' + suffix))],
                 [sys.executable, 'tests/m1_integration.py', '--bin', str(binary),
                  '--output', str(output.with_suffix('.integration.json'))]]
    digest = hashlib.sha256()
    sources = [ROOT / 'xmake.lua', ROOT / 'dependencies.lock.json']
    for directory in ('src', 'include', 'apps', 'tests', 'scripts', 'packaging'):
        sources += [p for p in (ROOT / directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    for path in sorted(sources):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    report = {'schema': 1, 'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'host': platform.platform(), 'compiler': args.compiler, 'sanitizers': args.sanitizers,
              'sources_sha256': digest.hexdigest(), 'dependencies': json.loads((ROOT / 'dependencies.lock.json').read_text()),
              'steps': [], 'status': 'failed'}
    try:
        for command in commands:
            result = subprocess.run(command, text=True, capture_output=True, timeout=1800)
            report['steps'].append({'command': command, 'returncode': result.returncode,
                                    'stdout': result.stdout, 'stderr': result.stderr})
            print(('PASS ' if result.returncode == 0 else 'FAIL ') + ' '.join(command), flush=True)
            if result.returncode:
                print(result.stdout + result.stderr)
                return 1
        report['status'] = 'passed'
        return 0
    finally:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
