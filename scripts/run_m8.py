#!/usr/bin/env python3
"""Build and test process plugins and Docker adapters without requiring a host engine."""
import argparse,datetime,json,os,platform,subprocess,sys
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--compiler',choices=['gcc','clang','msvc'],required=True)
    p.add_argument('--skip-build',action='store_true');p.add_argument('--sanitizers',action='store_true');a=p.parse_args()
    root=Path(__file__).resolve().parents[1];os.chdir(root)
    host='windows' if os.name=='nt' else 'linux';arch='x64' if os.name=='nt' else 'x86_64';mode='debug' if a.sanitizers else 'release'
    binary=root/'build'/host/arch/mode;output=root/'build/m8'/f'{host}-{a.compiler}.json'
    commands=[[sys.executable,'scripts/fetch_pace.py','--verify'],[sys.executable,'scripts/fetch_pace.py','--dependency','recipes','--verify']]
    if not a.skip_build:commands += [['xmake','f','-y','-c','-p',host,'-a',arch,'-m',mode,'--m0=n','--m1=y','--toolchain='+a.compiler,'--sanitizers='+('y' if a.sanitizers else 'n')],['xmake','-y','-j','8']]
    if a.sanitizers:commands += [['strip','--strip-debug',str(binary/'taucloud_docker'),str(binary/'taucloud_m8_plugin_fixture')]]
    commands += [[sys.executable,'tests/m8_integration.py','--bin',str(binary),'--output',str(output.with_suffix('.integration.json'))]]
    report=dict(status='failed',host=platform.platform(),recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),steps=[])
    try:
        for command in commands:
            r=subprocess.run(command,capture_output=True,text=True,timeout=1800)
            report['steps'].append(dict(command=command,returncode=r.returncode,stdout=r.stdout,stderr=r.stderr))
            print(('PASS ' if r.returncode==0 else 'FAIL ')+' '.join(command),flush=True)
            if r.returncode:print(r.stdout+r.stderr);return 1
        report['status']='passed';return 0
    finally:output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':raise SystemExit(main())
