#!/usr/bin/env python3
"""Build the pinned Linux delegation acceptance kernel (never install it)."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tarfile
import urllib.request

VERSION = '6.19'
# https://www.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc
SHA256 = '303079a8250b8f381f82b03f90463d12ac98d4f6b149b761ea75af1323521357'
OPTIONS = '''64BIT PRINTK BINFMT_ELF BINFMT_SCRIPT BLK_DEV_INITRD RD_GZIP
DEVTMPFS PROC_FS SYSFS SYSCTL TMPFS SHMEM MULTIUSER FILE_LOCKING FUTEX EPOLL SIGNALFD
TIMERFD EVENTFD NET UNIX TTY SERIAL_8250 SERIAL_8250_CONSOLE PCI VIRTIO_MENU
BLOCK BLK_DEV VIRTIO_PCI VIRTIO_BLK EXT4_FS EXT4_FS_POSIX_ACL POSIX_TIMERS
HIGH_RES_TIMERS X86_LOCAL_APIC X86_IO_APIC ACPI ACPI_SLEEP RANDOMIZE_BASE
STACKPROTECTOR TMPFS_XATTR TMPFS_POSIX_ACL'''.split()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--jobs', type=int, default=4)
    args = p.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    archive = work / f'linux-{VERSION}.tar.xz'
    if not archive.exists():
        temporary = archive.with_suffix('.download')
        urllib.request.urlretrieve(f'https://www.kernel.org/pub/linux/kernel/v6.x/{archive.name}', temporary)
        temporary.replace(archive)
    if hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest() != SHA256:
        raise SystemExit('Kernel archive SHA256 mismatch')
    source = work / f'linux-{VERSION}'
    if not source.exists():
        with tarfile.open(archive) as tar:
            tar.extractall(work, filter='data')
    out = work / 'out'
    make = ['make', '-C', str(source), f'O={out}']
    subprocess.run(make + ['tinyconfig'], check=True)
    configure = [str(source / 'scripts/config'), '--file', str(out / '.config')]
    for option in OPTIONS:
        configure += ['--enable', option]
    subprocess.run(configure, check=True)
    subprocess.run(make + ['olddefconfig'], check=True)
    config = (out / '.config').read_text()
    for option in ['64BIT', 'BINFMT_ELF', 'BLK_DEV_INITRD', 'FILE_LOCKING',
                   'TMPFS', 'EXT4_FS', 'VIRTIO_BLK', 'SERIAL_8250_CONSOLE']:
        if f'CONFIG_{option}=y\n' not in config:
            raise SystemExit(f'Missing required kernel option: {option}')
    subprocess.run(make + [f'-j{args.jobs}', 'bzImage'], check=True)
    print(out / 'arch/x86/boot/bzImage')


if __name__ == '__main__':
    main()
