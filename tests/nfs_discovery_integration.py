#!/usr/bin/env python3
"""MOUNT v3 discovery, principal isolation and read-only rpcbind registration."""
import argparse
import json
from pathlib import Path
import xdrlib3 as xdr

from m7_integration import Client, t3, t4, op
from pynfs_acceptance import fixture


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    args = p.parse_args()
    f, port = fixture(args.bin, 512 if args.sanitizers else 256)
    clients, checks = [], []

    def client(**kwargs):
        c = Client(port, **kwargs)
        clients.append(c)
        return c

    def mount_call(c, proc, path=None):
        payload = xdr.Packer()
        if path is not None:
            payload.pack_string(path)
        return xdr.Unpacker(c.exchange(c.packet(100005, 3, proc, payload.get_buffer())))

    def exports(c):
        u = mount_call(c, 5)
        entries = {}
        while u.unpack_bool():
            name, groups = u.unpack_string(), []
            while u.unpack_bool():
                groups.append(u.unpack_string())
            entries[name] = groups
        u.done()
        return entries

    def mounts(c):
        u = mount_call(c, 2)
        entries = []
        while u.unpack_bool():
            entries.append((u.unpack_string(), u.unpack_string()))
        u.done()
        return entries

    try:
        alice, root, unknown = client(), client(uid=0), client(uid=1001)
        assert exports(alice) == {b'/nfs': [b'127.0.0.1']}
        assert exports(root) == exports(unknown) == {}
        for proc in (2, 5):
            packet = xdr.Packer()
            for value in (100 + proc, 0, 2, 100005, 3, proc, 0, 0, 0, 0):
                packet.pack_uint(value)
            u = xdr.Unpacker(alice.exchange(packet.get_buffer()))
            assert not u.unpack_bool()
            u.done()
        assert mounts(alice) == []
        status, handle = alice.mount()
        assert status == 0
        for _ in range(3):
            assert alice.mount() == (0, handle)
        assert mounts(alice) == [(b'127.0.0.1', b'/nfs')]
        assert mounts(root) == mounts(unknown) == []
        checks.append('EXPORT and DUMP filter root-squashed/unmapped principals; duplicate MNT is idempotent')

        again = client()
        assert mounts(again) == mounts(alice)
        mount_call(unknown, 3, b'/nfs').done()
        assert len(mounts(alice)) == 1
        mount_call(again, 3, b'/nfs').done()
        assert mounts(alice) == []
        assert alice.v3('GETATTR', t3.GETATTR3args(t3.nfs_fh3(handle)), 1).status == 0
        assert alice.mount()[0] == 0
        mount_call(again, 4).done()
        assert mounts(alice) == []
        checks.append('mount records survive reconnect; UMNT/UMNTALL affect only caller and preserve NFS filehandles')

        expected = {(100003, 3), (100003, 4), (100005, 3),
                    (100000, 2), (100000, 3), (100000, 4)}
        address = ('127.0.0.1.%d.%d' % (port >> 8, port & 255)).encode()
        for version in (2, 3, 4):
            u = xdr.Unpacker(alice.exchange(alice.packet(100000, version, 4, b'')))
            registrations = set()
            while u.unpack_bool():
                registrations.add((u.unpack_uint(), u.unpack_uint()))
                if version == 2:
                    assert (u.unpack_uint(), u.unpack_uint()) == (6, port)
                else:
                    assert (u.unpack_string(), u.unpack_string(), u.unpack_string()) == (
                        b'tcp', address, b'tauCloud')
            u.done()
            assert registrations == expected
        for program, version, netid, wanted in ((100003, 4, b'tcp', address),
                (100003, 2, b'tcp', b''), (100003, 3, b'udp', b''),
                (100021, 4, b'tcp', b'')):
            body = xdr.Packer()
            body.pack_uint(program); body.pack_uint(version)
            for value in (netid, b'', b''):
                body.pack_string(value)
            u = xdr.Unpacker(alice.exchange(alice.packet(100000, 4, 9, body.get_buffer())))
            assert u.unpack_string() == wanted
            u.done()
        checks.append('rpcbind v2/v3/v4 DUMP and v4 GETVERSADDR advertise only implemented TCP services')

        alice.session()
        root_handle = alice.root()
        for operation in (op.link(b'alias'), op.readlink()):
            result = alice.compound([op.putfh(root_handle), operation])
            assert result.status == 10004 and len(result.resarray) == 3, result
        for kind in (t4.createtype4(5, linkdata=b'elsewhere'),
                     t4.createtype4(7),
                     t4.createtype4(3, devdata=t4.specdata4(1, 2))):
            result = alice.compound([op.putfh(root_handle),
                op.create(kind, b'unsupported', t4.fattr4([], b''))])
            assert result.status == 10007 and len(result.resarray) == 3, result
        checks.append('recognized unsupported file types return per-operation errors after successful SEQUENCE/PUTFH')

        assert alice.mount()[0] == 0
        f.api('nfs-exports', f.admin, dict(id='nfs', trust='loopback-auth-sys',
              anonymous='bob', uids={'1000': 'alice'}, gids={'1000': 'unix'},
              enabled=False, update=True))
        assert exports(alice) == {} and mounts(alice) == []
        assert alice.mount()[0] == 13
        checks.append('export revocation immediately hides discovery and denies subsequent MNT')
        report = dict(status='passed', checks=checks)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    finally:
        for c in clients:
            c.close()
        f.close()


if __name__ == '__main__':
    main()
