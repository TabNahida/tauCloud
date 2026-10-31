#!/usr/bin/env python3
"""Real Docker Engine acceptance; creates/removes only uniquely named test objects."""
import argparse,io,json,os,subprocess,tarfile,traceback,uuid
from pathlib import Path
from m8_integration import Fixture,package,wait

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bin',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert os.environ.get('GITHUB_ACTIONS')=='true' and os.name!='nt','disposable Linux Actions runner required'
    f=Fixture(a.bin);name='tc-m8-'+uuid.uuid4().hex[:16];container=image=None;report=dict(status='failed',checks=[])
    def cli(*args,input=None):return subprocess.run(['docker',*args],input=input,capture_output=True,check=True,timeout=120).stdout.decode().strip()
    def api(op,b=None):return f.api('plugins/'+op,f.admin,b)
    def invoke(op,**kwargs):return api('invoke',dict(id='docker',request=dict(engine='native',operation=op,**kwargs)))
    try:
        report['engine']=json.loads(cli('version','--format','{{json .Server}}'))
        cli('pull','alpine:3.21.3');report['runtime_image']=cli('image','inspect','alpine:3.21.3','--format','{{.Id}}')
        cli('volume','create','--label','taucloud.test='+name,name)
        cli('network','create','--label','taucloud.test='+name,name)
        container=cli('create','--name',name,'--label','taucloud.test='+name,'alpine:3.21.3','sh','-c','echo tc-m8-ready; while true; do sleep 1; done')
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w'):pass
        image=cli('import','-',name+':fixture',input=stream.getvalue())
        path=package(f,'docker',kind='docker',caps=['plugin.invoke','docker.read','docker.logs','docker.control'])
        plan=api('plan',dict(source=str(path)));api('install',dict(source=str(path),approved_digest=plan['digest'],approved_permissions=plan['manifest']['capabilities'],trusted_code=True));api('enable',dict(id='docker'))
        wait(lambda:any(x['id']=='docker' and x['status']=='running' for x in api('list')['plugins']))
        endpoint=dict(id='native',transport='unix',path='/var/run/docker.sock',platform='linux-native',permissions=['docker.read','docker.logs','docker.control'])
        plan=api('engine-plan',dict(endpoint=endpoint));api('engine-approve',dict(endpoint=endpoint,approved_digest=plan['digest']))
        report['capabilities']=invoke('info')['capabilities']
        for resource in ('containers','images','volumes','networks'):
            items=invoke('inventory',resource=resource)['items'];expected=container if resource=='containers' else image if resource=='images' else name
            key='Id' if resource in ('containers','images') else 'Name';assert any(x.get(key)==expected for x in items),(resource,expected)
        invoke('lifecycle',id=container,action='start')
        wait(lambda:b'tc-m8-ready' in bytes.fromhex(invoke('logs',id=container)['data']))
        assert 'cpu_stats' in invoke('stats',id=container)
        invoke('lifecycle',id=container,action='restart',timeout=1)
        invoke('lifecycle',id=container,action='stop',timeout=1)
        invoke('lifecycle',id=container,action='remove');container=None
        invoke('lifecycle',resource='volumes',id=name,action='remove')
        invoke('lifecycle',resource='networks',id=name,action='remove')
        invoke('lifecycle',resource='images',id=image,action='remove');image=None
        report.update(status='passed',checks=['real engine version/platform negotiation','four inventories contain independently created objects','native logs and one-shot stats','start/restart/stop/remove container; remove dedicated image/volume/network'])
    except Exception:report['error']=traceback.format_exc();raise
    finally:
        if container:subprocess.run(['docker','rm','-f',container],capture_output=True,timeout=30)
        if image:subprocess.run(['docker','image','rm',image],capture_output=True,timeout=30)
        subprocess.run(['docker','volume','rm',name],capture_output=True,timeout=30)
        subprocess.run(['docker','network','rm',name],capture_output=True,timeout=30)
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');f.close()
    print(json.dumps(report,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
