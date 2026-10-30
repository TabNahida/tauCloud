# Run from a Windows checkout, or pass a WSL UNC source. Only a new disposable
# directory is modified on NTFS; evidence is copied back into the source tree.
param([string]$Source = (Split-Path $PSScriptRoot -Parent), [switch]$WithSmb)
$ErrorActionPreference = 'Stop'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('taucloud-m0-' + [Guid]::NewGuid().ToString('N'))
$exitCode = 1
try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    foreach ($item in @('xmake.lua', 'dependencies.lock.json', 'scripts', 'include', 'experiments')) {
        Copy-Item -LiteralPath (Join-Path $Source $item) -Destination $scratch -Recurse
    }
    New-Item -ItemType Directory -Path (Join-Path $scratch '.deps') | Out-Null
    Copy-Item -LiteralPath (Join-Path $Source '.deps/pace') -Destination (Join-Path $scratch '.deps') -Recurse
    Push-Location $scratch
    try {
        $env:PATH = "C:\Program Files\xmake;$env:PATH"
        $env:PYTHONUTF8 = '1'
        $extra = @()
        if ($WithSmb) {
            & python -m venv .deps/smb-venv
            if ($LASTEXITCODE -ne 0) { throw 'SMB test venv creation failed' }
            & .deps/smb-venv/Scripts/python.exe -m pip install --disable-pip-version-check -r experiments/m0/smbprotocol-requirements.txt
            if ($LASTEXITCODE -ne 0) { throw 'SMB test dependency installation failed' }
            $extra = @('--smb-python', (Join-Path $scratch '.deps/smb-venv/Scripts/python.exe'), '--smb-client', 'smbprotocol')
        }
        & python scripts/run_m0.py --compiler msvc --output build/windows-msvc.json @extra
        $exitCode = $LASTEXITCODE
        $destination = Join-Path $Source 'build/m0'
        New-Item -ItemType Directory -Force -Path $destination | Out-Null
        if (Test-Path build/windows-msvc.json) {
            Copy-Item build/windows-msvc.json (Join-Path $destination 'windows-msvc.json') -Force
        }
    } finally { Pop-Location }
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
exit $exitCode
