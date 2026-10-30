#!/usr/bin/env python3
"""Windows 2025 native SMB redirector, alternative TCP port, disposable mapping."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import traceback
from m5_integration import Fixture
from smb_trace_proxy import HeaderProxy

SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$remote = '\\127.0.0.1\smb'
if (Get-SmbMapping | Where-Object RemotePath -eq $remote) { throw 'Fixture remote is already mapped' }
$drive = $null
foreach ($candidate in @('Z:','Y:','X:','W:','V:')) {
    if (-not (Get-PSDrive -Name $candidate.TrimEnd(':') -ErrorAction SilentlyContinue) -and -not (Get-SmbMapping | Where-Object { $_.LocalPath -eq $candidate }) -and -not (Test-Path ('HKCU:\Network\'+$candidate.TrimEnd(':')))) { $drive=$candidate; break }
}
if (-not $drive) { throw 'No unused test drive' }
$drive | Set-Content -LiteralPath $env:TC_NATIVE_MAPPING
try {
    New-SmbMapping -LocalPath $drive -RemotePath $remote -TcpPort ([uint16]$env:TC_NATIVE_PORT) -UserName 'TAUCLOUD\alice' -Password $env:TC_NATIVE_PASSWORD -RequireIntegrity $true -RequirePrivacy $true -Persistent $false | Out-Null
    $dir = $drive+'\native-roundtrip'
    [IO.Directory]::CreateDirectory($dir) | Out-Null
    $path = $dir+'\payload'
    $data = [byte[]]::new(1048576)
    for ($i=0; $i -lt $data.Length; $i++) { $data[$i] = $i % 251 }
    $file = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    try { $file.Write($data,0,$data.Length); $file.Flush($true) } finally { $file.Dispose() }
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($data))
    if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($path))) -ne $hash) { throw 'Readback mismatch' }
    [IO.File]::Move($path,$dir+'\renamed'); $path=$dir+'\renamed'
    $file=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { $file.SetLength(65537); $file.Flush($true) } finally { $file.Dispose() }
    if ([IO.File]::ReadAllBytes($path).Length -ne 65537) { throw 'Truncate mismatch' }
    if ([IO.Directory]::GetFiles($dir).Count -ne 1) { throw 'Enumeration mismatch' }
    [IO.File]::Delete($path); [IO.Directory]::Delete($dir)
    $connection=Get-SmbConnection | Where-Object { $_.ServerName -eq '127.0.0.1' -and $_.ShareName -eq 'smb' } | Select-Object ServerName,ShareName,Dialect,Encrypted,Signed
    @{status='passed';client='Windows native SMB redirector';payload_sha256=$hash;connection=$connection} | ConvertTo-Json -Depth 4
} finally {
    Get-SmbMapping | Where-Object { $_.RemotePath -eq $remote -and $_.LocalPath -eq $drive } | Remove-SmbMapping -Force -Confirm:$false
}
'''

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();assert os.name=='nt'
    f=Fixture(args.bin);report=dict(status='failed',host=platform.platform())
    script=f.base/'native-smb.ps1';script.write_text(SCRIPT)
    mapping=f.base/'mapping.txt'
    proxy=HeaderProxy(f.smbport)
    env=os.environ.copy();env.update(TC_NATIVE_PORT=str(proxy.port),TC_NATIVE_PASSWORD=f.password,TC_NATIVE_MAPPING=str(mapping))
    try:
        result=subprocess.run(['pwsh','-NoProfile','-NonInteractive','-File',str(script)],env=env,capture_output=True,text=True,timeout=120)
        report.update(returncode=result.returncode,stdout=result.stdout,stderr=result.stderr)
        if result.returncode==0:report.update(json.loads(result.stdout))
    except Exception:report['error']=traceback.format_exc()
    finally:
        if mapping.exists():
            # The script records a previously unused drive before mapping it.
            cleanup=r"$d=(Get-Content -LiteralPath $env:TC_NATIVE_MAPPING).Trim(); Get-SmbMapping | Where-Object { $_.LocalPath -eq $d -and $_.RemotePath -eq '\\127.0.0.1\smb' } | Remove-SmbMapping -Force -Confirm:$false"
            result=subprocess.run(['pwsh','-NoProfile','-NonInteractive','-Command',cleanup],env=env,capture_output=True,text=True,timeout=30)
            if result.returncode:report.update(status='failed',cleanup_error=result.stderr)
        proxy.close();report['smb_headers']=proxy.trace
        f.log.flush();report['server_log']=(f.base/'supervisor.log').read_text()[-65536:]
        args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
        f.close()
    print(json.dumps({k:v for k,v in report.items() if k!='server_log'},indent=2))
    return int(report['status']!='passed')

if __name__=='__main__':raise SystemExit(main())
