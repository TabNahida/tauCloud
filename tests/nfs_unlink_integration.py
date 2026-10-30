#!/usr/bin/env python3
"""Retained NFS opens: atomic replacement, unlink, quota and worker recovery."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import xdrlib3 as xdr

from m1_integration import wait
from m7_integration import Client, op
from pynfs_acceptance import fixture


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    args = p.parse_args()
    f, port = fixture(args.bin, 512 if args.sanitizers else 256)
    clients, checks = [], []

    def connect(owner=None, reclaim=False):
        c = Client(port)
        clients.append(c)
        c.session(owner, reclaim=reclaim)
        return c

    def expect(c, operations, status=0):
        r = c.compound(operations)
        assert r.status == status, r
        return r

    def write(c, handle, state, data, offset=0):
        expect(c, [op.putfh(handle), op.write(state, offset, 2, data)])

    def read(c, handle, state):
        r = expect(c, [op.putfh(handle), op.read(state, 0, 1024)])
        return r.resarray[-1].opread.resok4.data

    def free(c, root):
        r = expect(c, [op.putfh(root), op.getattr([0, 1 << 10])])
        u = xdr.Unpacker(r.resarray[-1].opgetattr.resok4.obj_attributes.attr_vals)
        value = u.unpack_uhyper()
        u.done()
        return value

    try:
        a, b = connect(), connect()
        root = a.root()
        original_free = free(a, root)
        old_state, old = a.open(root, b'target', True)
        write(a, old, old_state, b'old contents')
        other_state, other = b.open(root, b'target', owner=b'other')
        new_state, new = a.open(root, b'source', True, owner=b'new')
        write(a, new, new_state, b'new')
        expect(a, [op.putfh(root), op.savefh(), op.rename(b'source', b'target')])
        assert (f.root / 'nfsdata/target').read_bytes() == b'new'
        assert read(a, old, old_state) == read(b, other, other_state) == b'old contents'
        assert free(a, root) == original_free - len(b'old contentsnew')
        write(a, old, old_state, b' changed', len(b'old contents'))
        assert read(b, other, other_state) == b'old contents changed'
        assert (f.root / 'nfsdata/target').read_bytes() == b'new'
        expect(a, [op.putfh(old), op.close(0, old_state)])
        assert free(a, root) == original_free - len(b'old contents changednew')
        expect(b, [op.putfh(other), op.close(0, other_state)])
        assert free(a, root) == original_free - 3
        expect(a, [op.putfh(old), op.getattr([2])], 70)
        expect(a, [op.putfh(new), op.close(0, new_state)])
        checks.append('atomic rename preserves both old opens, isolates writes and charges retained data until last CLOSE')

        idle_state, idle_handle = a.open(root, b'idle', True, owner=b'idle')
        write(a, idle_handle, idle_state, b'idle bytes')
        expect(a, [op.putfh(root), op.remove(b'idle')])
        token = f.api('auth/login', data=dict(username='alice', password=f.password,
                                           scope='files'))['token']
        def used():
            return f.api('files/quota', token, dict(space='nfsdata', path=''))['used']
        charged = used()
        a.close(); b.close()
        # Poll only HTTPS: no NFS packet can drive expiry or orphan reaping.
        wait(lambda: used() == charged - len(b'idle bytes'), timeout=75)
        a = connect()
        checks.append('periodic lease expiry releases unlinked bytes without any NFS client traffic')

        state, handle = a.open(root, b'unlinked', True, owner=b'unlinked')
        write(a, handle, state, b'survives worker restart')
        expect(a, [op.putfh(root), op.remove(b'unlinked')])
        assert not (f.root / 'nfsdata/unlinked').exists()
        assert read(a, handle, state) == b'survives worker restart'
        durable_state, durable_handle = a.open(root, b'durable-unlink', True, owner=b'durable')
        durable_data = b'survives storage owner restart'
        write(a, durable_handle, durable_state, durable_data)
        expect(a, [op.putfh(root), op.remove(b'durable-unlink')])
        before_free = free(a, root)
        before = f.ctl('status')
        pid, owner = before['nfs']['identity']['pid'], a.owner
        if os.name == 'nt':
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True, check=True)
        else:
            os.kill(pid, signal.SIGKILL)
        wait(lambda: (entry := f.ctl('status')['nfs'])['status'] == 'running'
             and entry['identity']['pid'] != pid)
        assert f.ctl('status')['file']['identity']['pid'] == before['file']['identity']['pid']
        recovered = connect(owner, reclaim=True)
        state, handle = recovered.open(handle, b'', claim=1, owner=b'unlinked')
        durable_state, durable_handle = recovered.open(durable_handle, b'', claim=1, owner=b'durable')
        expect(recovered, [op.reclaim_complete(False)])
        assert read(recovered, handle, state) == b'survives worker restart'
        assert free(recovered, root) == before_free
        expect(recovered, [op.putfh(handle), op.close(0, state)])
        assert free(recovered, root) == original_free - 3 - len(durable_data)
        checks.append('unlink retains descriptor and quota across NFS worker crash; matching OPEN reclaim and last CLOSE release it')

        state, handle = durable_state, durable_handle
        before_free = free(recovered, root)
        pins = list((f.root / 'nfsdata').glob('.tc-nfs-*'))
        assert len(pins) == 1
        before = f.ctl('status')
        pid = before['file']['identity']['pid']
        if os.name == 'nt':
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True, check=True)
        else:
            os.kill(pid, signal.SIGKILL)
        wait(lambda: (entry := f.ctl('status')['file'])['status'] == 'running'
             and entry['identity']['pid'] != pid)
        assert f.ctl('status')['nfs']['identity']['pid'] == before['nfs']['identity']['pid']
        assert read(recovered, handle, state) == b'survives storage owner restart'
        assert free(recovered, root) == before_free
        write(recovered, handle, state, b'! ', 0)
        owner = recovered.owner
        for c in clients: c.close()
        f.stop(); f.start()
        recovered = connect(owner, reclaim=True)
        state, handle = recovered.open(handle, b'', claim=1, owner=b'durable')
        expect(recovered, [op.reclaim_complete(False)])
        assert read(recovered, handle, state) == b'! rvives storage owner restart'
        assert free(recovered, root) == before_free
        expect(recovered, [op.putfh(handle), op.close(0, state)])
        assert free(recovered, root) == original_free - 3
        assert not list((f.root / 'nfsdata').glob('.tc-nfs-*'))
        expect(recovered, [op.putfh(handle), op.getattr([2])], 70)
        checks.append('private links preserve data, identity and quota through file-domain kill and all-service restart; reclaim/CLOSE removes durable storage')
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
