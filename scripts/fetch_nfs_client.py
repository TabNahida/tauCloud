#!/usr/bin/env python3
"""Verify pinned upstream pynfs and generate independent codecs outside its clean export."""
import os, shutil, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
os.chdir(ROOT)
subprocess.run([sys.executable,'scripts/fetch_pace.py','--dependency','pynfs'],check=True)
source=ROOT/'.deps/pynfs/nfs4.1'
target=ROOT/'build/nfs-client';(target/'xdrdef').mkdir(parents=True,exist_ok=True)
shutil.copyfile(ROOT/'.deps/pynfs/xdr/xdrgen.py',target/'xdrgen.py')
sys.path.insert(0,str(target))
import xdrgen
shutil.copyfile(source/'nfs_ops.py',target/'nfs_ops.py')
shutil.copyfile(source/'xdrdef/__init__.py',target/'xdrdef/__init__.py')
for name in ('nfs3.x','nfs4.x','mnt3.x'):shutil.copyfile(source/'xdrdef'/name,target/'xdrdef'/name)
os.chdir(target/'xdrdef')
for name in ('nfs3.x','nfs4.x','mnt3.x'):xdrgen.run(name)
