#!/usr/bin/env python3
"""Build the pinned, unmodified upstream NFSv4.1 client and test suite."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
subprocess.run([sys.executable, str(ROOT / 'scripts/fetch_pace.py'),
                '--dependency', 'pynfs'], cwd=ROOT, check=True)
target = ROOT / 'build/pynfs'
for directory in ('xdr', 'rpc', 'nfs4.1'):
    shutil.copytree(ROOT / '.deps/pynfs' / directory, target / directory,
                    dirs_exist_ok=True)
sys.path.insert(0, str(target / 'xdr'))
import xdrgen
for directory in (target / 'rpc', target / 'nfs4.1/xdrdef'):
    os.chdir(directory)
    for definition in sorted(directory.glob('*.x')):
        xdrgen.run(str(definition))
print('Prepared upstream suite at', target)
