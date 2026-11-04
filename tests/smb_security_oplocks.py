#!/usr/bin/env python3
"""Security and size updates obey classic oplock ownership and ACL boundaries."""
import argparse
import json
from pathlib import Path
import struct
import time
import traceback
import uuid

from smbprotocol.connection import Connection
from smbprotocol.open import Open, SMB2SetInfoRequest
from smbprotocol.file_info import FileEndOfFileInformation
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from m5_integration import Fixture, create, denied, setinfo
from smb_security_integration import get_sd, set_sd, parse, descriptor, ace
from smb_oplock_integration import capture_breaks, Ack
from smb_blocking_locks import pending


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', required=True); p.add_argument('--output', required=True, type=Path)
    a = p.parse_args(); report = dict(status='failed', checks=[])
    f = None; connections = []
    def passed(message):
        report['checks'].append(message); print('PASS '+message, flush=True)
    def connect(dialect, user='alice'):
        c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
        connections.append(c); c.connect(dialect=dialect, timeout=10)
        q = capture_breaks(c, include_level=True)
        s = Session(c, 'TAUCLOUD\\'+user, f.password, require_encryption=dialect >= 0x300, auth_protocol='ntlm')
        s.connect(); t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect()
        return c, s, t, q
    try:
        f = Fixture(a.bin, memory=1024)
        f.api('grants', f.admin, dict(space='smbdata', subject_type='user', subject='bob', rights='rw'))
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, s, t, q = connect(dialect)
            pc, ps, pt, pq = connect(dialect)
            bc, bs, bt, bq = connect(dialect, 'bob')
            for level in (1, 8, 9):
                name = f'security-cache-{dialect:x}-{level}'
                initial = create(t, name, access=0x1f01ff)
                initial.write(b'contents'); owner = parse(get_sd(initial))['owner']; initial.close()
                h = Open(t, name); h.create(2, 0x1f01ff, 0x80, 7, 1, 0x40, oplock_level=level)
                assert h.oplock_level == level
                limited = create(pt, name, access=0x80, disposition=1)
                set_sd(h, descriptor([ace(owner)], control=0x9004))
                expected = get_sd(h)
                assert parse(expected)['dacl'][0][3] == owner
                denied(lambda: set_sd(limited, descriptor([])), 0xc0000022)
                denied(lambda: set_sd(h, b'bad'), 0xc0000079)
                forbidden_eof = FileEndOfFileInformation(); forbidden_eof['end_of_file'] = 0
                denied(lambda: setinfo(limited, forbidden_eof), 0xc0000022)
                forbidden_allocation = SMB2SetInfoRequest(); forbidden_allocation['info_type'] = 1
                forbidden_allocation['file_info_class'] = 19
                forbidden_allocation['file_id'] = limited.file_id
                forbidden_allocation['buffer'] = struct.pack('<Q', 0)
                denied(lambda: pc.receive(pc.send(forbidden_allocation, ps.session_id, pt.tree_connect_id)), 0xc0000022)
                assert get_sd(h) == expected and h.read(0, 8) == b'contents'
                if level != 1:
                    allocation = SMB2SetInfoRequest(); allocation['info_type'] = 1
                    allocation['file_info_class'] = 19; allocation['file_id'] = h.file_id
                    allocation['buffer'] = struct.pack('<Q', 65536)
                    response = c.receive(c.send(allocation, s.session_id, t.tree_connect_id))
                    assert not response['flags'].get_value() & 2
                    eof = FileEndOfFileInformation(); eof['end_of_file'] = 4
                    response = setinfo(h, eof)
                    assert not response['flags'].get_value() & 2 and h.read(0, 4) == b'cont'
                    h.write(b'contents')
                time.sleep(.3); c.echo(sid=s.session_id, timeout=5)
                assert q.empty() and pq.empty(), 'security mutation unexpectedly recalled a classic oplock'
                limited.close()
                time.sleep(.3); c.echo(sid=s.session_id, timeout=5)
                assert q.empty() and pq.empty(), 'metadata-peer close unexpectedly recalled a surviving cache'

                # A real data open still recalls EXCLUSIVE/BATCH. This proves
                # the security operation preserved the grant, rather than
                # silently discarding it without a wire notification.
                peer = Open(pt, name)
                packet, receive = peer.create(2, 0x1f01ff, 0x80, 7, 1, 0x40, oplock_level=1, send=False)
                request = pc.send(packet, ps.session_id, pt.tree_connect_id)
                if level != 1:
                    pending(request)
                    assert q.get(timeout=10) == (s.session_id, h.file_id, s.encrypt_data, 1)
                    c.receive(c.send(Ack(h.file_id, 1), s.session_id, t.tree_connect_id))
                receive(request); assert peer.oplock_level == 1
                set_sd(peer, descriptor([]))
                # The other client's read-cache and its originally granted
                # access survive a security change made through this open.
                assert h.read(0, 8) == b'contents' and peer.read(0, 8) == b'contents'
                time.sleep(.3); assert q.empty() and pq.empty()
                # Size changes through Level II are different: all readers,
                # including the originating open, must lose caching.
                eof = FileEndOfFileInformation(); eof['end_of_file'] = 4
                packet = SMB2SetInfoRequest(); packet['info_type'] = 1
                packet['file_info_class'] = eof.INFO_CLASS; packet['file_id'] = peer.file_id
                packet['buffer'] = eof
                request = pc.send(packet, ps.session_id, pt.tree_connect_id)
                assert q.get(timeout=10) == (s.session_id, h.file_id, s.encrypt_data, 0)
                assert pq.get(timeout=10) == (ps.session_id, peer.file_id, ps.encrypt_data, 0)
                pc.receive(request, timeout=10) # Level II does not acknowledge breaks.
                assert h.read(0, 4) == peer.read(0, 4) == b'cont'
                peer.close(); h.close()
                denied(lambda: create(bt, name, access=1, disposition=1), 0xc0000022)
                passed(f'{dialect:x}/{level}: security updates preserve classic caches and existing rights; new opens enforce ACLs; own exclusive allocation/EOF preserves cache, while Level II EOF invalidates all readers without ACK')
            for connection in (c, pc, bc): connection.disconnect()
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); raise
    finally:
        for c in connections:
            try: c.disconnect(close=False)
            except Exception: pass
        if f: f.close()
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__': main()
