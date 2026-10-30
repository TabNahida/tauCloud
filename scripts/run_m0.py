#!/usr/bin/env python3
"""Build and run bounded M0 probes; preserve evidence without claiming release support."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
ANSI = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')


def execute(command, timeout=60):
    start = time.monotonic()
    try:
        process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                 encoding='utf-8', errors='replace', timeout=timeout)
        return {'command': command, 'returncode': process.returncode,
                'seconds': round(time.monotonic() - start, 3),
                'stdout': ANSI.sub('', process.stdout).strip(),
                'stderr': ANSI.sub('', process.stderr).strip()}
    except (subprocess.TimeoutExpired, OSError) as error:
        return {'command': command, 'returncode': -1, 'error': str(error)}


def main():
    # Preserve evidence even when a Windows console cannot represent diagnostics.
    sys.stdout.reconfigure(errors='replace')
    sys.stderr.reconfigure(errors='replace')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', choices=['gcc', 'clang', 'msvc'], default='msvc' if os.name == 'nt' else 'gcc')
    parser.add_argument('--git-source')
    parser.add_argument('--sanitizers', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--smb-python', help='Isolated Python with the pinned independent SMB test client')
    parser.add_argument('--smb-client', choices=['impacket', 'smbprotocol'], default='impacket')
    args = parser.parse_args()
    source_digest = hashlib.sha256()
    sources = [ROOT / 'xmake.lua', ROOT / 'dependencies.lock.json']
    for directory in ('scripts', 'include', 'experiments'):
        sources += [path for path in (ROOT / directory).rglob('*')
                    if path.is_file() and '__pycache__' not in path.parts]
    for source in sorted(sources):
        source_digest.update(source.relative_to(ROOT).as_posix().encode() + b'\0')
        source_digest.update(hashlib.sha256(source.read_bytes()).digest())
    host = 'windows' if os.name == 'nt' else 'linux'
    output = args.output or ROOT / f'build/m0/{host}-{args.compiler}.json'
    report = {'schema': 1, 'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'host': platform.platform(), 'python': platform.python_version(),
              'machine': platform.machine(), 'logical_cpus': os.cpu_count(),
              'compiler': args.compiler, 'sanitizers': args.sanitizers,
              'sources_sha256': source_digest.hexdigest(),
              'pace': json.loads((ROOT / 'dependencies.lock.json').read_text())['pace']['revision'],
              'milestone_status': 'accepted_by_functional_evidence_2026_10_29', 'steps': []}
    report['tool_versions'] = [execute(['xmake', '--version'])]
    report['tool_versions'].append(execute([{'gcc': 'g++', 'clang': 'clang++', 'msvc': 'cl'}[args.compiler],
                                          *([] if args.compiler == 'msvc' else ['--version'])]))
    commands = [[sys.executable, 'scripts/fetch_pace.py', *(['--git-source', args.git_source] if args.git_source else ['--verify'])],
                ['xmake', 'f', '-c', '-p', host, '-a', 'x64' if host == 'windows' else 'x86_64',
                 '-m', 'debug', '-o', f'build/{host}-{args.compiler}', '--m0=y', '--m1=n',
                 '--sanitizers=' + ('y' if args.sanitizers else 'n'), '--toolchain=' + args.compiler, '-y'],
                ['xmake', '-j', '4'],
                ['xmake', 'run', 'taucloud_m0_runtime'],
                ['xmake', 'run', 'taucloud_m0_filesystem'],
                [sys.executable, 'experiments/m0/recovery.py'],
                [sys.executable, 'experiments/m0/updates.py'],
                [sys.executable, 'experiments/m0/smb.py']]
    if host == 'windows':
        commands[1] += ['--vs=2026', '--vs_toolset=14.51.36231', '--vs_sdkver=10.0.26100.0']
        commands.append(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                         '-File', 'experiments/m0/windows_host.ps1'])
    if args.smb_python:
        commands.append([args.smb_python, 'experiments/m0/smb_interop.py', '--client', args.smb_client])
    else:
        report['smb_interop'] = 'not_run; pass --smb-python with the pinned test environment'
    failed = False
    for command in commands:
        result = execute(command, 180 if command[0] == 'xmake' else 45)
        report['steps'].append(result)
        print(('PASS ' if result['returncode'] == 0 else 'FAIL ') + ' '.join(command), flush=True)
        if result['returncode']:
            print(result.get('stderr', result.get('error', '')))
            print(result.get('stdout', ''))
            failed = True
            break
    report['probe_status'] = 'failed' if failed else 'passed'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print('Evidence: ' + str(output))
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
