#!/usr/bin/env python3
"""NFSv4.1 pseudo-root traversal, multiple exports and authorization-safe replay."""
import argparse
import json
from pathlib import Path

from pynfs_acceptance import fixture
from m7_integration import Client, op, t4, p4


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sanitizers', action='store_true')
    args = parser.parse_args()
    f, port = fixture(args.bin, 512 if args.sanitizers else 256)
    clients, checks = [], []

    def connect(**kwargs):
        c = Client(port, **kwargs)
        clients.append(c)
        c.session()
        return c

    def expect(c, operations, status=0):
        r = c.compound(operations)
        assert r.status == status, r
        return r

    def export(name, space='nfsdata', uid=1000, enabled=True, anonymous='bob'):
        f.api('shares', f.admin, dict(id=name, space=space, exposures={'nfs': 'rw'}))
        mapping = dict(id=name, trust='loopback-auth-sys', anonymous=anonymous,
                       uids={str(uid): 'alice'}, gids={'1000': 'unix'}, enabled=enabled)
        f.api('nfs-exports', f.admin, mapping)
        return mapping

    def page(c, cookie=0, verifier=b'\0' * 8, count=512, bits=None):
        # Request type, fsid, handle and fileid so each returned mount point can
        # be compared with LOOKUP; include all XDR fields in the maxcount check.
        bits = bits if bits is not None else [(1 << 1) | (1 << 8) | (1 << 19) | (1 << 20)]
        r = expect(c, [op.putrootfh(), op.readdir(cookie, verifier, count, count, bits)])
        result = r.resarray[-1].opreaddir
        packer = p4.NFS4Packer()
        packer.pack_READDIR4res(result)
        assert len(packer.get_buffer()) <= count
        entries = []
        link = result.resok4.reply.entries
        while link:
            entries.append(link[0])
            link = link[0].nextentry
        return entries, result.resok4.cookieverf, result.resok4.reply.eof

    try:
        c = connect()
        # This first request fails with NOTSUPP on the previous implementation.
        entries, _, eof = page(c)
        assert [e.name for e in entries] == [b'nfs'] and eof
        expected = {b'nfs'}
        for i in range(12):
            name = 'alias-%02d' % i
            export(name)
            expected.add(name.encode())
        export('disabled', enabled=False)
        export('unmapped', uid=2000)
        f.api('spaces', f.admin, dict(id='private', root='data', path='private', owner='bob', quota=2**20))
        export('private', space='private', anonymous='alice')
        names, handles, cookie, verifier, pages = [], {}, 0, b'\0' * 8, 0
        while True:
            entries, verifier, eof = page(c, cookie, verifier)
            pages += 1
            for entry in entries:
                assert entry.cookie >= 3 and entry.cookie > cookie
                cookie = entry.cookie
                names.append(entry.name)
                u = p4.NFS4Unpacker(entry.attrs.attr_vals)
                assert u.unpack_uint() == 2
                u.unpack_fsid4()
                handles[entry.name] = u.unpack_nfs_fh4()
                u.unpack_uint64_t()
                u.done()
            if eof:
                break
            assert entries and pages < 32
        assert pages > 1 and len(names) == len(set(names)) and set(names) == expected
        for name, handle in handles.items():
            r = expect(c, [op.putrootfh(), op.lookup(name), op.getfh(), op.lookupp(), op.getfh()])
            assert r.resarray[3].opgetfh.resok4.object == handle
            assert r.resarray[-1].opgetfh.resok4.object == b'tauCloud:nfs:root'
        checks.append('paged pseudo-root READDIR exposes only enabled, mapped and authorized exports; returned handles match LOOKUP and LOOKUPP')

        for kwargs in (dict(uid=0, gid=0, groups=[0xffffffff]), dict(uid=4000), dict(gid=4000)):
            hidden = connect(**kwargs)
            entries, _, eof = page(hidden, count=20)
            assert not entries and eof
            expect(hidden, [op.putrootfh(), op.readdir(0, b'\0'*8, 128, 128, [0, 1 << 22])], 22)
            hidden.close()
        checks.append('root-squashed, unmapped and invalid-group identities cannot enumerate protected names; invalid attributes reject even in empty directories')

        entries, verifier, eof = page(c)
        assert entries and not eof
        for bad_cookie in (1, 2, 9999):
            expect(c, [op.putrootfh(), op.readdir(bad_cookie, verifier, 512, 512, [])], 10003)
        expect(c, [op.putrootfh(), op.readdir(entries[-1].cookie, b'bad-verf', 512, 512, [])], 10027)
        expect(c, [op.putrootfh(), op.readdir(0, b'\0'*8, 20, 20, [2])], 10005)
        before = expect(c, [op.putrootfh(), op.getattr([1 << 3])]).resarray[-1].opgetattr.resok4.obj_attributes.attr_vals
        export('added')
        after = expect(c, [op.putrootfh(), op.getattr([1 << 3])]).resarray[-1].opgetattr.resok4.obj_attributes.attr_vals
        assert int.from_bytes(after, 'big') > int.from_bytes(before, 'big')
        expect(c, [op.putrootfh(), op.readdir(entries[-1].cookie, verifier, 512, 512, [])], 10027)
        # Also apply the response-size and no-progress rule inside a real export.
        root = c.root()
        expect(c, [op.putfh(root), op.readdir(0, b'\0'*8, 20, 20, [2])], 10005)
        r = expect(c, [op.putrootfh(), op.secinfo(b'nfs')])
        assert r.resarray[-1].opsecinfo.resok4[0].flavor == 1
        expect(c, [op.putrootfh(), op.secinfo(b'nfs'), op.getfh()], 10020)
        checks.append('READDIR validates reserved cookies, changed verifiers, exact maxcount and forward progress; pseudo-root change and SECINFO work')

        f.api('spaces', f.admin, dict(id='second', root='data', path='second', owner='alice', quota=2**20))
        second_export = export('second', space='second')
        second_root = expect(c, [op.putrootfh(), op.lookup(b'second'), op.getfh()]).resarray[-1].opgetfh.resok4.object
        state1, h1 = c.open(root, b'one', True)
        state2, h2 = c.open(second_root, b'two', True)
        expect(c, [op.putfh(h1), op.write(state1, 0, 2, b'first'), op.putfh(h2), op.write(state2, 0, 2, b'second')])
        expect(c, [op.putfh(h2), op.read(state1, 0, 16)], 10025)
        reply = expect(c, [op.putfh(h1), op.read(state1, 0, 16), op.putfh(h2), op.read(state2, 0, 16)])
        assert reply.resarray[2].opread.resok4.data == b'first'
        assert reply.resarray[-1].opread.resok4.data == b'second'
        checks.append('one session holds simultaneous OPENs in distinct exports and executes cross-export compounds without accepting mismatched stateids')

        cached = c.compound([op.putfh(h1), op.read(state1, 0, 16), op.putfh(h2), op.read(state2, 0, 16)], packet_only=True)
        original = c.exchange(cached)
        assert c.decode4(original).status == 0 and c.exchange(cached) == original
        f.api('nfs-exports', f.admin, dict(second_export, update=True, enabled=False))
        assert c.decode4(c.exchange(cached)).status == 10008
        # A revoked export must not stall unrelated requests or another mapped
        # identity multiplexing the same host session.
        r = expect(c, [op.putfh(h1), op.read(state1, 0, 16)])
        assert r.resarray[-1].opread.resok4.data == b'first'
        expect(c, [op.putfh(h2), op.read(state2, 0, 16)], 13)
        f.api('nfs-exports', f.admin, dict(second_export, update=True))
        expect(c, [op.putfh(h2), op.close(0, state2)])
        expect(c, [op.putfh(h1), op.close(0, state1)])
        # No live OPEN remains: the old first-open renewal shortcut missed this.
        cached = c.compound([op.putfh(h2), op.read(t4.stateid4(0, b'\0'*12), 0, 16)], packet_only=True)
        original = c.exchange(cached)
        assert c.decode4(original).status == 0 and c.exchange(cached) == original
        f.api('nfs-exports', f.admin, dict(second_export, update=True, enabled=False))
        assert c.decode4(c.exchange(cached)).status == 10008
        expect(c, [op.putfh(h1), op.getattr([1 << 4])])
        checks.append('cached compound replies reauthorize every touched export, including READ without OPEN; revocation prevents data replay while other exports remain usable')

        cached = c.compound([op.putrootfh(), op.readdir(0, b'\0'*8, 512, 512, [2])], packet_only=True)
        original = c.exchange(cached)
        assert c.decode4(original).status == 0 and c.exchange(cached) == original
        f.api('nfs-exports', f.admin, dict(second_export, update=True))
        assert c.decode4(c.exchange(cached)).status == 10008
        expect(c, [op.putrootfh(), op.getattr([1 << 3])])
        checks.append('cached pseudo-root listings are fenced when export visibility changes and the next slot sequence still progresses')
        cached = c.compound([op.putfh(h2), op.read(t4.stateid4(0, b'\0'*12), 0, 16)], packet_only=True)
        assert c.decode4(c.exchange(cached)).status == 0
        f.api('shares', f.admin, dict(id='second', space='nfsdata', exposures={'nfs': 'rw'}, update=True))
        assert c.decode4(c.exchange(cached)).status == 10008
        expect(c, [op.putfh(h1), op.getattr([1 << 4])])
        checks.append('retargeting a share with the same export UUID cannot authorize a cached response from the old space')
        report = dict(status='passed', checks=checks)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    finally:
        for c in clients:
            c.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.with_suffix('.log').write_bytes((f.base / 'supervisor.log').read_bytes())
        f.close()


if __name__ == '__main__':
    main()
