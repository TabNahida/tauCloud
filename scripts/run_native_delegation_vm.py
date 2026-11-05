#!/usr/bin/env python3
"""Boot a supplied Linux kernel and the real native_file test in an isolated VM.

The guest has no networking or host filesystem shares. Its ext4 disk is newly
created in the required empty output directory. A guest PASS marker is required;
a QEMU exit, timeout, skipped capability or kernel panic cannot pass acceptance.
"""
import argparse
import gzip
from pathlib import Path
import re
import stat
import subprocess


def archive(files):
    result = bytearray()
    def entry(name, mode, data=b'', major=0, minor=0):
        name = name.encode() + b'\0'
        fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(name), 0]
        result.extend(b'070701' + ''.join(f'{v:08x}' for v in fields).encode())
        result.extend(name)
        result.extend(b'\0' * (-len(result) % 4))
        result.extend(data)
        result.extend(b'\0' * (-len(result) % 4))
    dirs = {'proc', 'dev', 'tmp', 'disk', 'bin'}
    for name in files:
        dirs.update(str(p) for p in Path(name).parents if str(p) != '.')
    for name in sorted(dirs, key=lambda n: (n.count('/'), n)):
        entry(name, stat.S_IFDIR | 0o755)
    entry('dev/console', stat.S_IFCHR | 0o600, major=5, minor=1)
    entry('dev/null', stat.S_IFCHR | 0o666, major=1, minor=3)
    for name, source in files.items():
        entry(name, stat.S_IFREG | 0o755, source.read_bytes())
    entry('TRAILER!!!', 0)
    return bytes(result)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        p.error('--output must be empty (a new disposable disk will be created)')
    binary = args.binary.resolve(strict=True)
    # Sanitizer initialization runs before main() and needs /proc to discover
    # the initial stack. Starting an instrumented test directly as PID 1 before
    # /proc exists makes exception unwinding leave false stack poison behind.
    init_source = output / 'init.c'
    init_source.write_text('''#include <sys/mount.h>
#include <unistd.h>
int main(void) {
    if (mount("proc", "/proc", "proc", 0, 0)) return 111;
    char *args[] = {"/bin/probe", 0};
    char *environment[] = {0};
    execve(args[0], args, environment);
    return 112;
}
''')
    init = output / 'init'
    subprocess.run(['cc', '-O2', '-Wall', '-Wextra', str(init_source), '-o', str(init)], check=True)
    files = {'init': init, 'bin/probe': binary}
    dependencies = '\n'.join(subprocess.check_output(['ldd', str(executable)], text=True)
                             for executable in (init, binary))
    if 'not found' in dependencies:
        raise RuntimeError(dependencies)
    for path in re.findall(r'(/[^\s()]+)', dependencies):
        file = Path(path)
        if file.is_file():
            files[str(file).lstrip('/')] = file.resolve()
    # ldd may resolve a dependency through the host's LD_LIBRARY_PATH (for
    # example a local Kerberos SDK). The PID 1 probe and its exec'd owner have
    # no such environment. Also install each SONAME in the guest loader's
    # standard x86-64 directory so those dependencies remain discoverable.
    for name, resolved in re.findall(r'^\s*(\S+)\s+=>\s+(/[^\s()]+)', dependencies, re.MULTILINE):
        if Path(name).name != name:
            raise RuntimeError('Unexpected dependency name: ' + name)
        files['lib/x86_64-linux-gnu/' + name] = Path(resolved).resolve(strict=True)
    (output / 'dependencies.txt').write_text(dependencies)
    initrd = output / 'initrd.cpio.gz'
    initrd.write_bytes(gzip.compress(archive(files), mtime=0))
    disk = output / 'ext4.img'
    with disk.open('wb') as f:
        f.truncate(128 * 1024 * 1024)
    subprocess.run(['mkfs.ext4', '-F', '-q', str(disk)], check=True)
    # TCG is intentionally sufficient: hosted Actions need not expose /dev/kvm.
    cmd = ['qemu-system-x86_64', '-accel', 'tcg', '-m', '1024', '-smp', '2',
           '-nographic', '-no-reboot', '-nic', 'none', '-monitor', 'none',
           '-kernel', str(args.kernel.resolve(strict=True)), '-initrd', str(initrd),
           '-append', 'console=ttyS0 rdinit=/init panic=-1',
           '-drive', f'file={disk},format=raw,if=virtio']
    (output / 'command.txt').write_text(repr(cmd) + '\n')
    with (output / 'serial.log').open('w') as log:
        try:
            run = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        except subprocess.TimeoutExpired:
            raise SystemExit('VM timed out; inspect serial.log')
    serial = (output / 'serial.log').read_text(errors='replace')
    print(serial)
    if run.returncode or 'TAUCLOUD_DELEGATION_VM_PASS' not in serial or 'FAIL ' in serial:
        raise SystemExit('Native delegation VM acceptance failed')
    print('PASS isolated kernel acceptance (tmpfs + ext4)')


if __name__ == '__main__':
    main()
