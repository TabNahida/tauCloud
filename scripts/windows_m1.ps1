# Build and exercise native MSVC executables from a disposable NTFS checkout.
param([string]$Source = (Split-Path $PSScriptRoot -Parent), [string]$Scratch = '')
$ErrorActionPreference = 'Stop'
if (!$Scratch) { $Scratch = Join-Path ([IO.Path]::GetTempPath()) ('taucloud-m1-' + [Guid]::NewGuid().ToString('N')) }
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
$destination = Join-Path $Source 'build/m1'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
Write-Output "Native checkout: $Scratch"
foreach ($item in @('xmake.lua', 'dependencies.lock.json', 'scripts', 'include', 'src', 'apps', 'tests', 'packaging')) {
    Copy-Item -LiteralPath (Join-Path $Source $item) -Destination $Scratch -Recurse -Force
}
if (!(Test-Path (Join-Path $Scratch '.deps/pace'))) {
    New-Item -ItemType Directory -Force -Path (Join-Path $Scratch '.deps') | Out-Null
    Copy-Item -LiteralPath (Join-Path $Source '.deps/pace') -Destination (Join-Path $Scratch '.deps') -Recurse
}
if (!(Test-Path (Join-Path $Scratch '.deps/recipes'))) {
    Copy-Item -LiteralPath (Join-Path $Source '.deps/recipes') -Destination (Join-Path $Scratch '.deps') -Recurse
}
Push-Location $Scratch
try {
    $env:PATH = "C:\Program Files\xmake;$env:PATH"
    $env:PYTHONUTF8 = '1'
    & xmake f -y -p windows -a x64 -m debug --m0=n --m1=y --vs=2026 --vs_toolset=14.51.36231 --vs_sdkver=10.0.26100.0
    if ($LASTEXITCODE -ne 0) { throw 'M1 configure failed' }
    & xmake -y -j 12
    if ($LASTEXITCODE -ne 0) { throw 'M1 build failed' }
    & python scripts/run_m1.py --compiler msvc --skip-build
    $testExit = $LASTEXITCODE
    Copy-Item build/m1/windows-msvc*.json $destination -Force
    if ($testExit -ne 0) { throw 'M1 verification failed' }
} finally { Pop-Location }
# Retain the isolated checkout for inspection and incremental validation.
