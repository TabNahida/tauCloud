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

        expected = {(p, v, b'tcp') for p, v in ((100003, 3), (100003, 4), (100005, 3),
                    (100000, 2), (100000, 3), (100000, 4), (100021, 4), (100024, 1))}
        expected.add((100024, 1, b'udp'))
        address = ('127.0.0.1.%d.%d' % (port >> 8, port & 255)).encode()
        for version in (2, 3, 4):
            u = xdr.Unpacker(alice.exchange(alice.packet(100000, version, 4, b'')))
            registrations = set()
            while u.unpack_bool():
                program, version_number = u.unpack_uint(), u.unpack_uint()
                if version == 2:
                    protocol = u.unpack_uint(); assert protocol in (6, 17)
                    transport = b'tcp' if protocol == 6 else b'udp'
                    assert u.unpack_uint() == port
                else:
                    transport = u.unpack_string()
                    assert (u.unpack_string(), u.unpack_string()) == (address, b'tauCloud')
                registrations.add((program, version_number, transport))
            u.done()
            assert registrations == expected
        for program, version, netid, wanted in ((100003, 4, b'tcp', address),
                (100003, 2, b'tcp', b''), (100003, 3, b'udp', b''),
                (100021, 4, b'tcp', address), (100021, 3, b'tcp', b''),
                (100024, 1, b'udp', address)):
            body = xdr.Packer()
            body.pack_uint(program); body.pack_uint(version)
            for value in (netid, b'', b''):
                body.pack_string(value)
            u = xdr.Unpacker(alice.exchange(alice.packet(100000, 4, 9, body.get_buffer())))
            assert u.unpack_string() == wanted
            u.done()
        checks.append('rpcbind DUMP/GETVERSADDR advertise implemented TCP services plus UDP NSM; older NLM versions remain absent')

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

        sys_auth = t4.callback_sec_parms4(1, t4.authsys_parms(0, b'client', 1000, 1000, []))
        for auth in ([], [t4.callback_sec_parms4(0)], [sys_auth]):
            result = alice.compound([op.backchannel_ctl(0x40000000, auth), op.putrootfh(), op.getfh()])
            assert result.status == 0 and len(result.resarray) == 4, result
        gss = t4.callback_sec_parms4(6, cbsp_gss_handles=t4.gss_cb_handles4(1, b'unknown', b'client'))
        result = alice.compound([op.backchannel_ctl(0x40000000, [gss])])
        assert result.status == 2 and len(result.resarray) == 2, result
        result = alice.compound([op.set_ssv(b'ssv', b'digest')])
        assert result.status == 22 and len(result.resarray) == 2, result
        obsolete = [op.renew(alice.cid), op.open_confirm(t4.stateid4(0, b'\0' * 12), 0),
                    op.release_lockowner(t4.lock_owner4(alice.cid, b'obsolete')),
                    op.setclientid(t4.nfs_client_id4(b'12345678', b'obsolete'),
                        t4.cb_client4(0, t4.clientaddr4(b'tcp', b'127.0.0.1.1.1')), 0),
                    op.setclientid_confirm(alice.cid, b'12345678')]
        for operation in obsolete:
            result = alice.compound([operation])
            assert result.status == 10004 and len(result.resarray) == 2, result
        checks.append('BACKCHANNEL_CTL updates bounded callback configuration; unknown GSS, SP4_NONE SET_SSV and obsolete v4.0 operations return defined per-operation errors')

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
