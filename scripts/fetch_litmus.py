#!/usr/bin/env python3
"""Build the pinned independent DAV conformance tool (Linux, not a runtime dependency)."""
import argparse, hashlib, os, subprocess, tarfile, urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
URL='https://notroj.github.io/litmus/litmus-0.18.tar.gz'
SHA256='efb3a1b91472760f66f2fcb4ca2b58af19c024fb0263ca725f1f1b44182fd8ca'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path)
    args=parser.parse_args()
    assert os.name!='nt','Use Linux for the independent litmus suite; Windows uses native TLS acceptance.'
    workspace=ROOT/'build/litmus';workspace.mkdir(parents=True,exist_ok=True)
    archive=args.archive or workspace/'litmus-0.18.tar.gz'
    if not archive.exists():
        with urllib.request.urlopen(URL,timeout=60) as response: archive.write_bytes(response.read(8*1024*1024))
    assert hashlib.sha256(archive.read_bytes()).hexdigest()==SHA256,'litmus source hash mismatch'
    source=workspace/'litmus-0.18';prefix=workspace/'installed'
    if not source.exists():
        with tarfile.open(archive) as tar:tar.extractall(workspace,filter='data')
    log=workspace/'build.log'
    with log.open('w') as out:
        for command in (['./configure','--with-ssl=openssl','--prefix='+str(prefix)],['make','-j4'],['make','install']):
            subprocess.run(command,cwd=source,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=600)
    print(prefix/'bin/litmus')

if __name__=='__main__':main()
