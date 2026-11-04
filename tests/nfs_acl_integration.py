#!/usr/bin/env python3
"""Independent NFSv3/v4 mode/ACL checks against the shared SMB authority."""
import argparse
import json
import socket
import traceback
import uuid
from pathlib import Path
from pynfs_acceptance import fixture
from m7_integration import Client, op, t3, t4, p4
from m5_integration import create, denied
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

FULL = 0x1f01ff
ZERO = t4.stateid4(0, b'\0'*12)

def attrs(acl=None, mode=None, size=None, gid=None):
    bits = [0, 0]
    p = p4.NFS4Packer()
    if size is not None:
        bits[0] |= 1 << 4
        p.pack_uhyper(size)
    if acl is not None:
        bits[0] |= 1 << 12
        p.pack_uint(len(acl))
        for kind, flags, mask, who in acl:
            p.pack_nfsace4(t4.nfsace4(kind, flags, mask, who.encode()))
    if mode is not None:
        bits[1] |= 1 << 1
        p.pack_uint(mode)
    if gid is not None:
        bits[1] |= 1 << 5
        p.pack_string(str(gid).encode())
    return t4.fattr4(bits, p.get_buffer())

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    a = p.parse_args()
    f, port = fixture(a.bin, 512 if a.sanitizers else 256)
    clients = []
    report = dict(status='failed', checks=[])
    def passed(text):
        report['checks'].append(text)
        print('PASS '+text, flush=True)
    def client(uid=1000, gid=1000, groups=()):
        c = Client(port, uid=uid, gid=gid, groups=groups)
        clients.append(c)
        c.session()
        return c
    def get(c, h):
        r = c.compound([op.putfh(h), op.getattr([1 << 12, 1 << 1])])
        assert r.status == 0, r
        u = p4.NFS4Unpacker(r.resarray[-1].opgetattr.resok4.obj_attributes.attr_vals)
        acl = [u.unpack_nfsace4() for _ in range(u.unpack_uint())]
        mode = u.unpack_uint()
        u.done()
        return acl, mode
    def set_acl(c, h, value, expected=0):
        r = c.compound([op.putfh(h), op.setattr(ZERO, value)])
        assert r.status == expected, r
    def read(c, h, expected=0):
        r = c.v3('READ', t3.READ3args(t3.nfs_fh3(h), 0, 16), 6)
        assert r.status == expected, r
        return r
    try:
        f.stop()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); smbport = sock.getsockname()[1]
        cfg = json.loads((f.state/"config.json").read_text()); cfg["smb_port"] = smbport
        (f.state/"config.json").write_text(json.dumps(cfg)); f.start()
        f.api('memberships', f.admin, dict(username='bob', group='unix'))
        f.api('grants', f.admin, dict(space='nfsdata', subject_type='user', subject='bob', rights='rw'))
        export = dict(id='nfs', trust='loopback-auth-sys', anonymous='bob',
                      uids={'1000':'alice', '1001':'bob'}, gids={'1000':'unix'})
        f.api('nfs-exports', f.admin, dict(export, update=True))
        alice, bob = client(), client(1001)
        status, root = alice.mount()
        assert status == 0
        initial = t3.sattr3(t3.set_mode3(True, 0o600), t3.set_uid3(False), t3.set_gid3(False),
                           t3.set_size3(True, 0), t3.set_atime(0), t3.set_mtime(0))
        r = alice.v3('CREATE', t3.CREATE3args(t3.diropargs3(t3.nfs_fh3(root), b'private'), t3.createhow3(1, initial)), 8)
        assert r.status == 0, r
        h = r.resok.obj.handle.data
        r = alice.v3('WRITE', t3.WRITE3args(t3.nfs_fh3(h), 0, 6, 2, b'secret'), 7)
        assert r.status == 0, r
        assert get(alice, h)[1] == 0o600
        read(bob, h, 13)
        set_acl(bob, h, attrs(mode=0o777), 13)
        r = alice.compound([op.putfh(h), op.getattr([(1 << 0) | (1 << 13)])])
        assert r.status == 0, r
        u = p4.NFS4Unpacker(r.resarray[-1].opgetattr.resok4.obj_attributes.attr_vals)
        supported = u.unpack_bitmap4()
        assert supported[0] & (1 << 12) and u.unpack_uint() == 3
        u.done()
        passed('NFSv3 mode is enforced, owner/group are mapped, nonowner chmod denied; NFSv4 advertises real ACL support')

        set_acl(alice, h, attrs(mode=0o660))
        read(bob, h)
        assert get(alice, h)[1] == 0o660
        f.api('groups', f.admin, dict(name='limited'))
        f.api('memberships', f.admin, dict(username='bob', group='limited'))
        export['gids']['1001'] = 'limited'
        f.api('nfs-exports', f.admin, dict(export, update=True))
        omitted = client(1001, 1001)
        read(omitted, h, 13)
        included = client(1001, 1001, (1000,))
        read(included, h)
        squashed = client(0, 1000, (1000,))
        read(squashed, h, 13)
        passed('group mode checks use only verified AUTH_SYS groups; omitted groups and root-squashed groups cannot grant access')

        acl = [(0, 0, FULL, 'OWNER@'), (0, 0, 1, 'bob@taucloud')]
        set_acl(alice, h, attrs(acl=acl, mode=0o000))
        returned, mode = get(alice, h)
        assert mode == 0o700, mode
        assert [(x.type, x.flag, x.access_mask, x.who.decode()) for x in returned] == acl
        read(bob, h)
        r = bob.compound([op.putfh(h), op.getattr([1 << 12])])
        assert r.status == 13, r
        r = bob.compound([op.putfh(root), op.readdir(0, b'\0'*8, 65536, 65536, [(1 << 11) | (1 << 12)])])
        assert r.status == 0, r
        entries = r.resarray[-1].opreaddir.resok4.reply.entries
        found = False
        while entries:
            e = entries[0]
            if e.name == b'private':
                assert e.attrs.attrmask == [1 << 11] and e.attrs.attr_vals == b'\0\0\0\r', e
                found = True
            entries = e.nextentry
        assert found
        set_acl(alice, h, attrs(mode=0o600))
        read(bob, h, 13)
        assert get(alice, h)[1] == 0o600
        passed('ACL+mode applies mode then ACL; named-user ACE roundtrips, READ_ACL is enforced and chmod masks named grants')

        set_acl(alice, h, attrs(acl=[(0, 0, FULL, 'OWNER@'), (0, 0, 1, 'missing@elsewhere')], size=0), 10039)
        assert read(alice, h).resok.data == b'secret'
        set_acl(alice, h, attrs(acl=[(0, 8, FULL, 'OWNER@')]), 10032)
        set_acl(alice, h, attrs(acl=[]))
        read(alice, h, 13)
        set_acl(alice, h, attrs(mode=0o600))
        passed('invalid ACL principal and flags fail before truncation; empty ACL denies data and owner can recover WRITE_ACL')

        for who, flags in [('GROUP@', 0xc0), ('unix@taucloud', 0x40)]:
            set_acl(alice, h, attrs(acl=[(0, 0, FULL, 'OWNER@'), (0, flags, 1, who)]))
            read(included, h)
            read(omitted, h, 13)
            returned, mode = get(alice, h)
            assert returned[-1].who.decode() == who and returned[-1].flag == (0 if who == 'GROUP@' else flags)
            assert mode == (0o740 if who == 'GROUP@' else 0o700), mode
        f.api('memberships', f.admin, dict(username='alice', group='limited'))
        owner_with_groups = client(1000, 1000, (1001,))
        set_acl(alice, h, attrs(acl=[(0, 0, FULL, 'OWNER@'), (0, 0, 1, 'GROUP@')]))
        set_acl(owner_with_groups, h, attrs(gid=1001))
        read(omitted, h)
        read(bob, h, 13)
        assert get(alice, h)[0][-1].who == b'GROUP@'
        set_acl(owner_with_groups, h, attrs(gid=1000))
        read(bob, h)
        opaque = 'sid-01020000000000052000000021020000@taucloud'
        set_acl(alice, h, attrs(acl=[(0, 0, FULL, 'OWNER@'), (0, 0x40, 1, opaque)]))
        assert get(alice, h)[0][-1].who.decode() == opaque
        set_acl(alice, h, attrs(acl=[(0, 0, 1, 'sid-00@taucloud')]), 10039)
        set_acl(alice, h, attrs(acl=[(0, 0, FULL, 'OWNER@'), (1, 0, 1, 'bob@taucloud'),
                                   (0, 0, 0x20, 'bob@taucloud')]))
        read(bob, h)
        r = bob.compound([op.putfh(h), op.access(0x21), op.read(ZERO, 0, 6)])
        assert r.status == 0 and r.resarray[-2].opaccess.resok4.access == 0x21, r
        assert r.resarray[-1].opread.resok4.data == b'secret', r
        r = bob.compound([op.putfh(root), op.open(0, 1, 0, t4.open_owner4(bob.cid, b'executor'),
                          t4.openflag4(0), t4.open_claim4(0, file=b'private')), op.getfh()])
        assert r.status == 0 and r.resarray[-1].opgetfh.resok4.object == h, r
        state = r.resarray[-2].opopen.resok4.stateid
        r = bob.compound([op.putfh(h), op.close(0, state)])
        assert r.status == 0, r
        r = alice.compound([op.putfh(root), op.create(t4.createtype4(2), b'invalid-acl',
                            attrs(acl=[(0, 0, FULL, 'absent@taucloud')]))])
        assert r.status == 10039 and not (f.root/'nfsdata/invalid-acl').exists(), r
        passed('special/named groups and primary-group changes enforce the mapped trustee; opaque SMB SIDs roundtrip; execute-only NFS READ/OPEN/ACCESS works; invalid CREATE ACL leaves no object')

        inherited = [(0, 3, FULL, 'OWNER@'), (1, 3, 0x21, 'bob@taucloud'),
                     (0, 3, 0x1200a9, 'EVERYONE@')]
        r = alice.compound([op.putfh(root), op.create(t4.createtype4(2), b'acl-parent', attrs(acl=inherited)), op.getfh()])
        assert r.status == 0, r
        parent = r.resarray[-1].opgetfh.resok4.object
        state, child = alice.open(parent, b'child', create=True)
        r = alice.compound([op.putfh(child), op.close(0, state)])
        assert r.status == 0, r
        child_acl, child_mode = get(alice, child)
        # RFC 8881: acl clears INHERITED_ACE; only dacl/sacl expose that flag.
        assert all(not e.flag & 0x80 for e in child_acl), child_acl
        assert child_mode == 0o755, child_mode
        read(bob, child, 13)
        long_acl = [(0, 0, FULL, 'OWNER@')] + [(0, 0, 1, 'bob@taucloud')] * 150
        set_acl(alice, h, attrs(acl=long_acl))
        assert len(get(alice, h)[0]) == 151
        set_acl(alice, h, attrs(mode=0o600))
        passed('directory ACL inheritance preserves OWNER@ and clears the acl-only inherited flag; ACL attributes larger than 4 KiB roundtrip')

        f.api('shares', f.admin, dict(id='acl-smb', space='nfsdata', exposures={'smb':'r'}))
        f.api('smb/credentials', f.admin, dict(username='bob', password=f.password))
        cfg = json.loads((f.state/'config.json').read_text())
        # Use the independently negotiated encrypted SMB client.
        smb = Connection(uuid.uuid4(), '127.0.0.1', cfg['smb_port'], require_signing=True)
        clients.append(smb)
        smb.connect(dialect=0x311)
        session = Session(smb, username='TAUCLOUD\\bob', password=f.password, require_encryption=True, auth_protocol='ntlm')
        session.connect()
        tree = TreeConnect(session, r'\\127.0.0.1\acl-smb')
        tree.connect()
        denied(lambda:create(tree, 'private', access=1, disposition=1), 0xc0000022)
        set_acl(alice, h, attrs(acl=[(0, 0, FULL, 'OWNER@'), (0, 0, 1, 'bob@taucloud')]))
        opened = create(tree, 'private', access=1, disposition=1)
        assert opened.read(0, 6) == b'secret'
        opened.close()
        passed('NFS chmod and ACL changes govern new SMB opens of the same object')

        for c in clients:
            c.close() if isinstance(c, Client) else c.disconnect(close=False)
        clients.clear()
        f.stop(); f.start()
        alice, bob = client(), client(1001)
        read(bob, h)
        assert get(alice, h)[1] == 0o700
        passed('shared ACLs, symbolic principals and derived mode survive complete service restart')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc()
        raise
    finally:
        for c in clients:
            try:
                c.close() if isinstance(c, Client) else c.disconnect(close=False)
            except Exception:
                pass
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(report, indent=2)+'\n')
        f.close()

if __name__ == '__main__':
    main()
