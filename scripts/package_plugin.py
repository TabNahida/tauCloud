#!/usr/bin/env python3
"""Package one trusted native worker for explicit administration approval."""
import argparse,hashlib,json,re,shutil
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--id',required=True);p.add_argument('--version',required=True)
    p.add_argument('--kind',choices=['generic','docker'],default='generic')
    p.add_argument('--capability',action='append',default=[])
    a=p.parse_args()
    if not re.fullmatch('[a-z][a-z0-9-]{0,47}',a.id):p.error('invalid id')
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',a.version):p.error('version must be MAJOR.MINOR.PATCH')
    a.output.mkdir(parents=True,exist_ok=False);source=a.binary.resolve(strict=True)
    shutil.copy2(source,a.output/source.name)
    caps=['plugin.invoke']+(['docker.read'] if a.kind=='docker' else [])+a.capability
    caps=list(dict.fromkeys(caps))
    allowed={'plugin.invoke'}|({'docker.read','docker.logs','docker.control'} if a.kind=='docker' else set())
    if not set(caps)<=allowed:p.error('capability not allowed for this kind')
    manifest=dict(schema=1,id=a.id,version=a.version,ipc_version=1,kind=a.kind,entry=source.name,
        files={source.name:hashlib.sha256(source.read_bytes()).hexdigest()},capabilities=caps)
    (a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(a.output.resolve())
if __name__=='__main__':main()
