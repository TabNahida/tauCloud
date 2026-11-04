#!/usr/bin/env python3
"""NFS special modes, masked updates and cross-protocol namespace enforcement."""
import argparse
import base64
import http.client
import json
import socket
import traceback
import uuid
from pathlib import Path
from pynfs_acceptance import fixture
from nfs_acl_integration import attrs, FULL, ZERO
from m7_integration import Client, op, t3, t4
from m5_integration import create, setinfo, denied
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.file_info import FileDispositionInformation, FileRenameInformation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sanitizers', action='store_true')
    args = parser.parse_args()
    f, port = fixture(args.bin, 512 if args.sanitizers else 256)
    clients = []
    report = dict(status='failed', checks=[])

    def passed(text):
        report['checks'].append(text)
        print('PASS '+text, flush=True)

    def client(uid=1000, gid=1000):
        c = Client(port, uid=uid, gid=gid)
        clients.append(c)
        c.session()
        return c

    def stat(c, h):
        r = c.v3('GETATTR', t3.GETATTR3args(t3.nfs_fh3(h)), 1)
        assert r.status == 0, r
        return r.resok.obj_attributes

    def acl(c, h):
        r = c.compound([op.putfh(h), op.getattr([1 << 12])])
        assert r.status == 0, r
        return r.resarray[-1].opgetattr.resok4.obj_attributes.attr_vals

    def setattrs(c, h, value, expected=0):
        r = c.compound([op.putfh(h), op.setattr(ZERO, value)])
        assert r.status == expected, r

    def mkdir(c, root, name, mode):
        r = c.compound([op.putfh(root), op.create(t4.createtype4(2), name, attrs(mode=mode)), op.getfh()])
        assert r.status == 0, r
        return r.resarray[-1].opgetfh.resok4.object

    def file(c, root, name, mode=0o666):
        a = t3.sattr3(t3.set_mode3(True, mode), t3.set_uid3(False), t3.set_gid3(False),
                      t3.set_size3(False), t3.set_atime(0), t3.set_mtime(0))
        r = c.v3('CREATE', t3.CREATE3args(t3.diropargs3(t3.nfs_fh3(root), name), t3.createhow3(1, a)), 8)
        assert r.status == 0, r
        return r.resok.obj.handle.data

    def writer(protocol):
        for share, kind in [('nfs', 'nfs'), ('mode-smb', 'smb'), ('mode-dav', 'webdav')]:
            f.api('shares', f.admin, dict(id=share, space='nfsdata', update=True, exposures={kind:'r'}))
        share = {'nfs':'nfs', 'smb':'mode-smb', 'webdav':'mode-dav'}[protocol]
        f.api('shares', f.admin, dict(id=share, space='nfsdata', update=True, exposures={protocol:'rw'}))

    def smb(user):
        c = Connection(uuid.uuid4(), '127.0.0.1', smbport, require_signing=True)
        clients.append(c)
        c.connect(dialect=0x311)
        s = Session(c, username='TAUCLOUD\\'+user, password=f.password, require_encryption=True, auth_protocol='ntlm')
        s.connect()
        tree = TreeConnect(s, r'\\127.0.0.1\mode-smb')
        tree.connect()
        return tree

    try:
        f.stop()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            smbport = sock.getsockname()[1]
        cfg = json.loads((f.state/'config.json').read_text())
        cfg['smb_port'] = smbport
        (f.state/'config.json').write_text(json.dumps(cfg))
        f.start()
        f.api('groups', f.admin, dict(name='limited'))
        f.api('memberships', f.admin, dict(username='bob', group='limited'))
        f.api('grants', f.admin, dict(space='nfsdata', subject_type='user', subject='bob', rights='rw'))
        f.api('nfs-exports', f.admin, dict(id='nfs', update=True, trust='loopback-auth-sys', anonymous='bob',
              uids={'1000':'alice', '1001':'bob'}, gids={'100':'unix', '1000':'unix', '1001':'limited'}))
        for share, kind in [('mode-smb', 'smb'), ('mode-dav', 'webdav')]:
            f.api('shares', f.admin, dict(id=share, space='nfsdata', exposures={kind:'r'}))
        for user in ('alice', 'bob'):
            f.api('smb/credentials', f.admin, dict(username=user, password=f.password))
        alice, bob = client(), client(1001, 1001)
        status, root = alice.mount()
        assert status == 0
        h = file(alice, root, b'special', 0o6755)
        assert stat(alice, h).mode == 0o6755
        initial_acl = acl(alice, h)
        setattrs(alice, h, attrs(mode_mask=(0, 0o4000)))
        assert stat(alice, h).mode == 0o2755 and acl(alice, h) == initial_acl
        setattrs(alice, h, attrs(mode_mask=(0o4000, 0)))
        assert stat(alice, h).mode == 0o2755 and acl(alice, h) == initial_acl
        setattrs(alice, h, attrs(mode_mask=(0, 0o044)))
        assert stat(alice, h).mode == 0o2711
        setattrs(alice, h, attrs(acl=[(0, 0, FULL, 'OWNER@')], mode_mask=(0o4000, 0o4000)))
        assert stat(alice, h).mode == 0o6700
        requested = [0, 0, 0]
        for n in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 19, 20, 27, 28, 29, 30, 31,
                  33, 35, 36, 37, 42, 43, 44, 45, 47, 51, 52, 53, 55, 75]:
            requested[n//32] |= 1 << (n%32)
        r = alice.compound([op.putfh(h), op.getattr(requested)])
        assert r.status == 0, r
        observed = r.resarray[-1].opgetattr.resok4.obj_attributes
        r = alice.compound([op.putfh(h), op.verify(observed)])
        assert r.status == 0, r
        r = alice.compound([op.putfh(h), op.nverify(observed)])
        assert r.status == 10009, r
        passed('v3 special mode creation and v4 masked updates preserve unmasked bits; high-only masks preserve exact ACL bytes; combined masked mode applies before ACL')

        for value in [attrs(mode=0o10000), attrs(mode_mask=(0o10000, 0)),
                      attrs(mode_mask=(0, 0o10000)), attrs(mode=0o600, mode_mask=(0, 0))]:
            setattrs(alice, h, value, 22)
        for operation in [op.getattr([0, 0, 1 << 10]), op.verify(attrs(mode_mask=(0, 0))),
                          op.nverify(attrs(mode=0o10000, size=0))]:
            r = alice.compound([op.putfh(h), operation])
            assert r.status == 22, r
        r = alice.compound([op.putfh(root), op.create(t4.createtype4(2), b'bad-mode', attrs(mode_mask=(0, 0)))])
        assert r.status == 22 and not (f.root/'nfsdata/bad-mode').exists(), r
        empty = mkdir(alice, root, b'empty', 0o700)
        r = alice.compound([op.putfh(empty), op.readdir(0, b'\0'*8, 1024, 1024, [0, 0, 1 << 10])])
        assert r.status == 22, r
        how = t4.openflag4(1, t4.createhow4(1, attrs(mode_mask=(0, 0))))
        r = alice.compound([op.putfh(root), op.open(0, 3, 0, t4.open_owner4(alice.cid, b'bad-mode'), how,
                            t4.open_claim4(0, file=b'bad-file'))])
        assert r.status == 22 and not (f.root/'nfsdata/bad-file').exists(), r
        setattrs(alice, h, attrs(acl=[(0, 0, FULL, 'OWNER@'), (0, 0, 0x40000, 'bob@taucloud')], mode=0o700))
        setattrs(bob, h, attrs(mode_mask=(0o4000, 0o4000)), 13)
        assert stat(alice, h).mode == 0o700
        passed('undefined mode bits, conflicting mode attributes and masked mode in CREATE/OPEN/GETATTR/VERIFY reject without creation')

        setattrs(alice, h, attrs(mode=0o6755))
        r = alice.v3('WRITE', t3.WRITE3args(t3.nfs_fh3(h), 0, 1, 2, b'x'), 7)
        assert r.status == 0 and stat(alice, h).mode == 0o755, r
        setattrs(alice, h, attrs(mode=0o6755))
        setattrs(alice, h, attrs(size=0))
        assert stat(alice, h).mode == 0o755
        setattrs(alice, h, attrs(mode=0o6755))
        setattrs(alice, h, attrs(gid=1000))
        assert stat(alice, h).mode == 0o755
        passed('NFS data writes, truncation and ownership setters clear file set-ID bits')

        parent = mkdir(alice, root, b'group-parent', 0o2777)
        child = file(bob, parent, b'child', 0o660)
        sub = mkdir(bob, parent, b'sub', 0o770)
        assert (stat(bob, child).uid, stat(bob, child).gid, stat(bob, child).mode) == (1001, 1000, 0o660)
        assert stat(bob, sub).gid == 1000 and stat(bob, sub).mode == 0o2770
        setattrs(bob, child, attrs(mode=0o2660), 13)
        passed('setgid directories transmit the exact parent GID alias and directory setgid to nonmember creators; explicit setgid requires verified group membership')

        sticky = mkdir(alice, root, b'sticky', 0o1777)
        victim = file(alice, sticky, b'victim')
        own = file(bob, sticky, b'own')
        r = bob.compound([op.putfh(sticky), op.remove(b'victim')])
        assert r.status == 13, r
        for source, dest in [(b'victim', b'moved'), (b'own', b'victim')]:
            r = bob.compound([op.putfh(sticky), op.savefh(), op.rename(source, dest)])
            assert r.status == 13, r
        r = bob.compound([op.putfh(sticky), op.remove(b'own')])
        assert r.status == 0, r
        assert stat(alice, victim).mode == 0o666
        passed('sticky directories reject foreign unlink, rename and replacement while permitting the object owner')

        setattrs(alice, h, attrs(mode=0o6755))
        writer('smb')
        atree, btree = smb('alice'), smb('bob')
        opened = create(atree, 'special', access=3, disposition=1)
        opened.write(b'smb')
        opened.close()
        assert stat(alice, h).mode == 0o755
        foreign = create(btree, 'sticky/victim', access=0x10000, disposition=1)
        deletion = FileDispositionInformation()
        deletion['delete_pending'] = True
        denied(lambda:setinfo(foreign, deletion), 0xc0000022)
        rename = FileRenameInformation()
        rename['file_name'] = 'sticky/moved'
        denied(lambda:setinfo(foreign, rename), 0xc0000022)
        foreign.close()
        passed('encrypted SMB writes clear NFS set-ID bits; SMB disposition and rename cannot bypass NFS sticky directories')

        writer('nfs')
        setattrs(alice, h, attrs(mode=0o6755))
        writer('webdav')
        auth = 'Basic '+base64.b64encode(('alice:'+f.password).encode()).decode()
        connection = http.client.HTTPSConnection('127.0.0.1', f.davport, context=f.context, timeout=10)
        connection.request('PUT', '/dav/mode-dav/special', b'dav', {'Authorization':auth})
        response = connection.getresponse()
        body = response.read()
        assert response.status == 204, (response.status, body)
        connection.close()
        r = alice.compound([op.putfh(root), op.lookup(b'special'), op.getfh()])
        assert r.status == 0, r
        h = r.resarray[-1].opgetfh.resok4.object
        assert stat(alice, h).mode == 0o755
        writer('nfs')
        setattrs(alice, h, attrs(mode=0o4755))
        setattrs(alice, sticky, attrs(mode_mask=(0, 0o1000)))
        assert stat(alice, sticky).mode == 0o777
        r = bob.compound([op.putfh(sticky), op.remove(b'victim')])
        assert r.status == 0, r
        for c in clients:
            c.close() if isinstance(c, Client) else c.disconnect(close=False)
        clients.clear()
        f.stop()
        f.start()
        alice = client()
        assert stat(alice, h).mode == 0o4755 and stat(alice, parent).mode == 0o2777
        assert stat(alice, parent).gid == stat(alice, child).gid == stat(alice, sub).gid == 1000
        passed('staged DAV replacement clears set-ID; removing sticky restores unlink; special modes and inherited GID aliases persist through complete restart')
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
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2)+'\n')
        f.close()


if __name__ == '__main__':
    main()
