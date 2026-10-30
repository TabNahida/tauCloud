#!/usr/bin/env python3
"""NLMv4/NSMv1 wire clients with a real bounded TCP callback peer."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import threading
import xdrlib3 as xdr

from m1_integration import wait
from m7_integration import Client, op, t3, t4
from pynfs_acceptance import fixture


class CallbackPeer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(handler):
                sock = handler.request
                sock.settimeout(5)
                def read(n):
                    out = b''
                    while len(out) < n:
                        data = sock.recv(n - len(out))
                        if not data: raise EOFError()
                        out += data
                    return out
                try:
                    marker = struct.unpack('>I', read(4))[0]
                    assert marker >> 31 and (marker & 0x7fffffff) <= 8192
                    u = xdr.Unpacker(read(marker & 0x7fffffff))
                    xid = u.unpack_uint()
                    assert (u.unpack_uint(), u.unpack_uint()) == (0, 2)
                    program, version, procedure = u.unpack_uint(), u.unpack_uint(), u.unpack_uint()
                    u.unpack_uint(); u.unpack_bytes(); u.unpack_uint(); u.unpack_bytes()
                    out = xdr.Packer()
                    for value in (xid, 1, 0, 0, 0, 0): out.pack_uint(value)
                    if program == 100000:
                        assert version == 2 and procedure == 3
                        p, v, protocol, _ = [u.unpack_uint() for _ in range(4)]
                        out.pack_uint(self.port if (p, v) in ((100021, 4), (100024, 1)) and protocol == 6 else 0)
                    elif program == 100021 and procedure == 5:
                        cookie = u.unpack_bytes()
                        exclusive = u.unpack_bool()
                        caller, handle, owner = u.unpack_string(), u.unpack_bytes(), u.unpack_bytes()
                        pid, start, length = u.unpack_uint(), u.unpack_uhyper(), u.unpack_uhyper()
                        self.events.append(('grant', cookie, owner, start, length))
                        out.pack_bytes(cookie); out.pack_uint(1 if self.reject else 0)
                    elif program == 100021:
                        assert version == 4 and procedure in (16, 24)
                        self.events.append(('monitor', u.unpack_string(), u.unpack_uint(), u.unpack_fopaque(16)))
                    else:
                        assert (program, version, procedure) == (100024, 1, 6)
                        self.events.append(('reboot', u.unpack_string(), u.unpack_uint()))
                    u.done()
                    body = out.get_buffer()
                    sock.sendall(struct.pack('>I', 0x80000000 | len(body)) + body)
                except (OSError, EOFError):
                    pass
        super().__init__(('127.0.0.1', 0), Handler)
        self.port = self.server_address[1]
        self.events, self.reject = [], False
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown(); self.server_close(); self.thread.join(timeout=2)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    args = p.parse_args()
    peer = CallbackPeer()
    f, port = fixture(args.bin, 512 if args.sanitizers else 256)
    clients, checks = [], []
    try:
        f.stop()
        config = json.loads((f.state / 'config.json').read_text())
        config['nfs_peer_rpcbind_port'] = peer.port
        (f.state / 'config.json').write_text(json.dumps(config)); f.start()
        def client(**kwargs):
            c = Client(port, **kwargs); clients.append(c); return c
        c = client()
        c.session(); root = c.root()
        state, handle = c.open(root, b'locked', True)
        other_state, other_handle = c.open(root, b'other', True, owner=b'other')
        assert c.compound([op.putfh(handle), op.close(0, state)]).status == 0
        assert c.compound([op.putfh(other_handle), op.close(0, other_state)]).status == 0

        def nlm(proc, owner=b'A', start=0, length=10, exclusive=True, block=False,
                reclaim=False, state=1, cookie=b'cookie', fh=handle, conn=None):
            body = xdr.Packer(); body.pack_bytes(cookie)
            if proc in (2, 3): body.pack_bool(block)
            if proc != 4: body.pack_bool(exclusive)
            body.pack_string(b'client-host'); body.pack_bytes(fh); body.pack_bytes(owner)
            body.pack_uint(42); body.pack_uhyper(start); body.pack_uhyper(length)
            if proc == 2: body.pack_bool(reclaim); body.pack_uint(state)
            u = xdr.Unpacker((conn or c).exchange((conn or c).packet(100021, 4, proc, body.get_buffer())))
            assert u.unpack_bytes() == cookie
            status = u.unpack_uint()
            holder = None
            if proc == 1 and status == 1:
                holder = (u.unpack_bool(), u.unpack_uint(), u.unpack_bytes(), u.unpack_uhyper(), u.unpack_uhyper())
            u.done()
            return status, holder

        def nsm(proc, body=b'', udp=False):
            packet = c.packet(100024, 1, proc, body)
            if not udp: return xdr.Unpacker(c.exchange(packet))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5); sock.sendto(packet, ('127.0.0.1', port)); reply = sock.recv(8192)
            u = xdr.Unpacker(reply)
            assert u.unpack_uint() == struct.unpack('>I', packet[:4])[0]
            assert [u.unpack_uint() for _ in range(5)] == [1, 0, 0, 0, 0]
            return xdr.Unpacker(reply[u.get_position():])

        assert nlm(2)[0] == 0
        assert nlm(2)[0] == 0, 'duplicate LOCK is idempotent'
        denied, holder = nlm(1, b'B')
        assert denied == 1 and holder == (True, 42, b'A', 0, 10), holder
        assert nlm(2, b'B')[0] == 1
        assert nlm(4, start=3, length=4)[0] == 0
        assert nlm(1, b'B', start=3, length=4)[0] == 0
        assert nlm(1, b'B', start=2, length=1)[0] == 1
        assert nlm(1, b'B', start=7, length=1)[0] == 1
        assert nlm(4, length=0)[0] == 0
        assert nlm(2, start=100, length=0, exclusive=False)[0] == 0
        assert nlm(2, b'B', start=100, length=0, exclusive=False)[0] == 0
        assert nlm(1, b'C', start=2**64 - 1, length=1)[0] == 1
        assert nlm(2, b'C', start=2**64 - 1, length=2)[0] == 8
        assert nlm(4, length=0)[0] == nlm(4, b'B', length=0)[0] == 0
        checks.append('NLM duplicate grants, holder information, partial unlock, shared locks, EOF ranges and overflow errors')

        f.api('grants', f.admin, dict(space='nfsdata', subject_type='user', subject='bob', rights='r'))
        readonly = client(uid=0, gid=0)
        assert nlm(2, b'RO', conn=readonly)[0] == 6
        assert nlm(2, b'RO', conn=readonly, exclusive=False)[0] == 0
        assert nlm(4, b'RO', conn=readonly)[0] == 0
        assert nlm(2)[0] == 0
        state, _ = c.open(root, b'locked', owner=b'v4')
        locker = t4.open_to_lock_owner4(0, state, 0, t4.lock_owner4(c.cid, b'v4-lock'))
        result = c.compound([op.putfh(handle), op.lock(2, False, 0, 10, t4.locker4(True, open_owner=locker))])
        assert result.status == 10010, result
        assert c.compound([op.putfh(handle), op.close(0, state)]).status == 0
        checks.append('exclusive locks require fresh write authority; NFSv4 byte locks conflict with NLM owners')

        assert nlm(2, b'B', block=True, cookie=b'blocked')[0] == 3
        assert nlm(4)[0] == 0
        wait(lambda: any(e[:2] == ('grant', b'blocked') for e in peer.events), timeout=10)
        assert nlm(1, b'C')[0] == 1
        assert nlm(4, b'B')[0] == 0
        assert nlm(2)[0] == 0
        assert nlm(2, b'B', block=True, cookie=b'cancel-me')[0] == 3
        assert nlm(3, b'B', block=True, cookie=b'different-cancel-cookie')[0] == 0
        assert nlm(4)[0] == 0
        assert nlm(2, b'C')[0] == 0
        assert nlm(4, b'C')[0] == 0
        assert not any(e[:2] == ('grant', b'cancel-me') for e in peer.events)
        checks.append('blocking LOCK receives and acknowledges a real TCP GRANTED callback; CANCEL matches owner/range independently of cookie')

        # A rejected upgrade must restore the owner's pre-existing shared lock.
        assert nlm(2, exclusive=False)[0] == nlm(2, b'B', exclusive=False)[0] == 0
        peer.reject = True
        assert nlm(2, block=True, cookie=b'reject-upgrade')[0] == 3
        assert nlm(4, b'B')[0] == 0
        wait(lambda: any(e[:2] == ('grant', b'reject-upgrade') for e in peer.events), timeout=10)
        wait(lambda: nlm(1, b'C', exclusive=False)[0] == 0, timeout=10)
        assert nlm(1, b'C')[0] == 1, 'rejected conversion must retain the original shared lock'
        assert nlm(4)[0] == 0
        peer.reject = False
        # Revoking a grant must not leave an inaccessible owner blocking others.
        assert nlm(2, b'RO', conn=readonly, exclusive=False)[0] == 0
        f.api('grants', f.admin, dict(space='nfsdata', subject_type='user', subject='bob', rights=''))
        assert nlm(2)[0] == 0
        assert nlm(4)[0] == 0
        checks.append('rejected blocking upgrades restore prior shared locks; revoked owners cannot leave stale conflicts')

        assert nlm(2)[0] == 0
        assert nlm(2, b'B', fh=other_handle)[0] == 0
        assert nlm(2, b'A', fh=other_handle, block=True, cookie=b'deadlock-a')[0] == 3
        assert nlm(2, b'B', block=True, cookie=b'deadlock-b')[0] == 5
        assert nlm(3, b'A', fh=other_handle, block=True, cookie=b'cancel')[0] == 0
        assert nlm(4)[0] == nlm(4, b'B', fh=other_handle)[0] == 0
        checks.append('wait-for cycles are rejected as deadlock without discarding existing locks')

        query = xdr.Packer(); query.pack_string(b'127.0.0.1')
        u = nsm(1, query.get_buffer()); assert u.unpack_uint() == 0; boot = u.unpack_uint(); u.done()
        u = nsm(1, query.get_buffer(), udp=True); assert (u.unpack_uint(), u.unpack_uint()) == (0, boot); u.done()
        monitor = xdr.Packer(); monitor.pack_string(b'client-host'); monitor.pack_string(b'localhost')
        for value in (100021, 4, 16): monitor.pack_uint(value)
        monitor.pack_fopaque(16, b'monitor-token-16')
        u = nsm(2, monitor.get_buffer()); assert (u.unpack_uint(), u.unpack_uint()) == (0, boot); u.done()
        assert nlm(2)[0] == 0
        notify = xdr.Packer(); notify.pack_string(b'client-host'); notify.pack_uint(3)
        nsm(6, notify.get_buffer(), udp=True).done()
        wait(lambda: any(e[:3] == ('monitor', b'client-host', 3) for e in peer.events), timeout=10)
        assert nlm(1, b'B')[0] == 0
        assert nlm(2, state=3)[0] == 0
        notify = xdr.Packer(); notify.pack_string(b'client-host'); notify.pack_uint(1)
        nsm(6, notify.get_buffer()).done()
        assert nlm(1, b'B')[0] == 1
        assert nlm(4)[0] == 0
        checks.append('TCP/UDP NSM discovery, bounded MON callback and reboot notification release old locks; stale state cannot revoke current locks')

        assert nlm(2, state=3)[0] == 0
        assert nlm(2, state=3, start=20, length=10)[0] == 0
        owner = c.owner
        def restart():
            nonlocal c
            pid = f.ctl('status')['nfs']['identity']['pid']
            if os.name == 'nt':
                import subprocess
                subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True, check=True)
            else: os.kill(pid, signal.SIGKILL)
            wait(lambda: (entry := f.ctl('status')['nfs'])['status'] == 'running' and entry['identity']['pid'] != pid)
            c = client()
        restart()
        assert nlm(2, b'B', state=3)[0] == 4
        assert nlm(2, reclaim=True, state=0)[0] == 0
        restart() # A second crash between two range reclaims must preserve both.
        assert nlm(2, reclaim=True, state=0)[0] == 0
        assert nlm(2, reclaim=True, state=0, start=20, length=10)[0] == 0
        assert nlm(2, reclaim=True, state=3, start=40, length=10)[0] == 9
        wait(lambda: any(e[0] == 'reboot' and e[2] != boot for e in peer.events), timeout=10)
        assert nlm(4, length=0)[0] == 0
        wait(lambda: nlm(1, b'B')[0] == 0, timeout=75)
        assert nlm(2, b'B', state=3)[0] == 0
        assert nlm(4, b'B')[0] == 0
        checks.append('server reboot advances NSM state, notifies peer and gates new locks; Linux-style zero-NSM-state reclaim matches persisted authority and ranges, survives a second crash, and grace expires normally')
        report = dict(status='passed', checks=checks,
                      callbacks=[dict(kind=e[0]) for e in peer.events])
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    finally:
        for c in clients: c.close()
        f.close(); peer.close()


if __name__ == '__main__':
    main()
