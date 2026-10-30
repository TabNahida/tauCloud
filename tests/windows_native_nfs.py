#!/usr/bin/env python3
"""Windows Client for NFS v3 on a disposable Actions runner (TCP, nolock).

Install NFS-Client before invocation. This harness never treats an absent feature
as a pass and never changes machine-wide client settings on a developer host.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import threading
import traceback

from pynfs_acceptance import fixture
from m7_integration import Client, t3, p3


class Relay:
    """Bounded loopback forwarding; preserve the server's advertised RPC port."""
    def __init__(self, port, target):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.2', port))
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        self.target, self.stopped, self.sockets, self.calls = target, False, [], []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopped:
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if len(self.sockets) >= 128:
                client.close()
                continue
            try:
                server = socket.create_connection(('127.0.0.1', self.target), timeout=5)
                client.settimeout(1); server.settimeout(1)
                self.sockets.extend((client, server))
                threading.Thread(target=self.copy, args=(client, server, True), daemon=True).start()
                threading.Thread(target=self.copy, args=(server, client, False), daemon=True).start()
            except OSError:
                client.close()

    def copy(self, source, target, trace):
        pending = bytearray()
        try:
            while not self.stopped:
                try:
                    data = source.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    break
                if trace:
                    pending.extend(data)
                    while len(pending) >= 4:
                        marker = struct.unpack('>I', pending[:4])[0]
                        length = marker & 0x7fffffff
                        if length > 262144:
                            pending.clear(); break
                        if len(pending) < length + 4:
                            break
                        packet = bytes(pending[4:length + 4])
                        del pending[:length + 4]
                        if marker >> 31 and len(packet) >= 32 and len(self.calls) < 512:
                            header = struct.unpack('>8I', packet[:32])
                            entry = dict(program=header[3], version=header[4], procedure=header[5])
                            if header[6] == 1 and len(packet) >= 40:
                                name_length = struct.unpack('>I', packet[36:40])[0]
                                offset = 40 + ((name_length + 3) & ~3)
                                if offset + 12 <= 32 + header[7] <= len(packet):
                                    entry['uid'], entry['gid'], entry['group_count'] = struct.unpack('>3I', packet[offset:offset + 12])
                            if header[3:6] == (100003, 3, 9):
                                offset = 32 + ((header[7] + 3) & ~3)
                                if offset + 8 <= len(packet):
                                    verifier_size = struct.unpack_from('>I', packet, offset + 4)[0]
                                    start = offset + 8 + ((verifier_size + 3) & ~3)
                                    try:
                                        u = p3.NFS3Unpacker(packet[start:])
                                        attrs = u.unpack_MKDIR3args().attributes
                                        entry['mkdir_attributes'] = str(attrs)
                                    except Exception:
                                        entry['decode_error'] = True
                            self.calls.append(entry)
                target.sendall(data)
        except OSError:
            pass
        finally:
            for sock in (source, target):
                try: sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass

    def close(self):
        self.stopped = True
        self.listener.close()
        self.thread.join(timeout=2)
        for sock in self.sockets:
            sock.close()


SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
Import-Module NFS
if (-not (Get-WindowsFeature NFS-Client).Installed) { throw 'Client for NFS is not installed' }
$old = Get-NfsClientConfiguration
$old | Export-Clixml -LiteralPath $env:TC_NATIVE_CONFIG
$drive = $null
foreach ($candidate in @('Z:','Y:','X:','W:','V:')) {
    if (-not (Get-PSDrive -Name $candidate.TrimEnd(':') -ErrorAction SilentlyContinue) -and -not (Test-Path ('HKCU:\Network\'+$candidate.TrimEnd(':')))) { $drive=$candidate; break }
}
if (-not $drive) { throw 'No unused drive' }
$drive | Set-Content -LiteralPath $env:TC_NATIVE_MAPPING
try {
    Set-NfsClientConfiguration -TransportProtocol TCP -MountType Soft -MountRetryAttempts 1 -RpcTimeoutSec 8 -Authentication sys
    $mount = & "$env:WINDIR\System32\mount.exe" -o anon -o nolock -o mtype=soft '\\127.0.0.2\nfs' $drive 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Native mount failed: $mount" }
    $dir = $drive+'\native-roundtrip'
    [IO.Directory]::CreateDirectory($dir) | Out-Null
    $path = $dir+'\payload'
    $data = [byte[]]::new(1048576)
    for ($i=0; $i -lt $data.Length; $i++) { $data[$i] = $i % 251 }
    $file = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    try { $file.Write($data,0,$data.Length); $file.Flush($true) } finally { $file.Dispose() }
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($data))
    if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($path))) -ne $hash) { throw 'Readback mismatch' }
    [IO.File]::Move($path,$dir+'\renamed'); $path=$dir+'\renamed'
    $file=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
    try { $file.SetLength(65537); $file.Flush($true) } finally { $file.Dispose() }
    if ([IO.File]::ReadAllBytes($path).Length -ne 65537) { throw 'Truncate mismatch' }
    if ([IO.Directory]::GetFiles($dir).Count -ne 1) { throw 'Enumeration mismatch' }
    [IO.File]::Delete($path); [IO.Directory]::Delete($dir)
    @{status='passed';client='Windows native Client for NFS';version=3;transport='tcp';locking='nolock';payload_sha256=$hash;mount_output="$mount"} | ConvertTo-Json -Depth 4
} finally {
    & "$env:WINDIR\System32\umount.exe" $drive 2>&1 | Out-Null
    Set-NfsClientConfiguration -TransportProtocol $old.TransportProtocol -MountType $old.MountType -MountRetryAttempts $old.MountRetryAttempts -RpcTimeoutSec $old.RpcTimeoutSec -Authentication $old.Authentication
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert os.name == 'nt' and os.environ.get('GITHUB_ACTIONS') == 'true', 'disposable Windows Actions runner required'
    f, port = fixture(args.bin)
    relays = []
    report = dict(status='failed', host=platform.platform(), checks=[])
    env = os.environ.copy()
    env['TC_NATIVE_MAPPING'] = str(f.base / 'mapping.txt')
    env['TC_NATIVE_CONFIG'] = str(f.base / 'client.xml')
    try:
        # Anonymous UID/GID values vary by Windows configuration; neither is
        # privileged here. Root is separately squashed to the fixture's bob.
        f.api('nfs-exports', f.admin, dict(id='nfs', trust='loopback-auth-sys', anonymous='bob',
              uids={'65534':'alice', '4294967294':'alice', '4294967295':'alice'},
              gids={'65534':'unix', '4294967294':'unix', '4294967295':'unix'}, update=True))
        f.api('grants', f.admin, dict(space='nfsdata', subject_type='user', subject='bob', rights='rw'))
        # Windows anonymous mappings vary by host. The fixture grants access to
        # those mapped principals and exposes matching POSIX traverse/write bits;
        # production application ACLs remain authoritative on every RPC.
        c = Client(port, uid=4294967294, gid=65534)
        try:
            status, root = c.mount()
            assert status == 0
            attrs = t3.sattr3(t3.set_mode3(True, 0o777), t3.set_uid3(False),
                t3.set_gid3(False), t3.set_size3(False), t3.set_atime(0), t3.set_mtime(0))
            result = c.v3('SETATTR', t3.SETATTR3args(t3.nfs_fh3(root), attrs, t3.sattrguard3(False)), 2)
            assert result.status == 0, result
        finally:
            c.close()
        # Native Windows has no alternate rpcbind-port option. Use an unused
        # loopback address; fail on a listener collision instead of replacing it.
        for listen in sorted({111, 2049, port}):
            relays.append(Relay(listen, port))
        script = f.base / 'native-nfs.ps1'
        script.write_text(SCRIPT)
        result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-File', str(script)],
                                env=env, capture_output=True, text=True, timeout=180)
        report.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if result.returncode == 0:
            report.update(json.loads(result.stdout))
            report['checks'] = ['native MOUNT and NFSv3 over TCP', '1 MiB flush and SHA256 readback',
                                'rename, truncate, enumeration and delete']
    except Exception:
        report['error'] = traceback.format_exc()
    finally:
        cleanup = r'''
$ErrorActionPreference='Stop'
if (Test-Path -LiteralPath $env:TC_NATIVE_MAPPING) {
    $drive=(Get-Content -LiteralPath $env:TC_NATIVE_MAPPING).Trim()
    if ($drive -notmatch '^[V-Z]:$') { throw 'Invalid fixture drive' }
    & "$env:WINDIR\System32\umount.exe" $drive 2>&1 | Out-Null
}
if (Test-Path -LiteralPath $env:TC_NATIVE_CONFIG) {
    $old=Import-Clixml -LiteralPath $env:TC_NATIVE_CONFIG
    Set-NfsClientConfiguration -TransportProtocol $old.TransportProtocol -MountType $old.MountType -MountRetryAttempts $old.MountRetryAttempts -RpcTimeoutSec $old.RpcTimeoutSec -Authentication $old.Authentication
}
'''
        try:
            result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-Command', cleanup],
                                    env=env, capture_output=True, text=True, timeout=30)
            if result.returncode:
                report.update(status='failed', cleanup_error=result.stderr)
        except Exception:
            report.update(status='failed', cleanup_error=traceback.format_exc())
        report['rpc_connections'] = [entry for relay in relays for entry in relay.calls]
        for relay in relays:
            relay.close()
        f.log.flush()
        report['server_log'] = (f.base / 'supervisor.log').read_text()[-65536:]
        report['worker_logs'] = {role: path.read_text()[-16384:] for role in ('nfs', 'file', 'identity')
            if (path := f.state / 'logs' / (role + '.jsonl')).exists()}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        f.close()
    print(json.dumps({k:v for k,v in report.items() if k not in ('server_log', 'worker_logs')}, indent=2))
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
