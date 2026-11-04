#!/usr/bin/env python3
"""Security QUERY_INFO flag namespaces and dialect-specific error wire layouts."""
import argparse
import datetime
import json
from pathlib import Path
import platform
import struct
import traceback
import uuid

from smbprotocol.connection import Connection
from smbprotocol.exceptions import SMBResponseException
from smbprotocol.open import Open, SMB2QueryInfoRequest, SMB2QueryInfoResponse
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from m5_integration import Fixture, create, denied
from smb_security_integration import descriptor, ace, EVERYONE, set_sd
from smb_oplock_integration import capture_breaks, Ack
from smb_blocking_locks import pending


def query_packet(h, information=7, limit=65536, ignored_input=False):
    q = SMB2QueryInfoRequest()
    q['info_type'] = 3
    q['additional_information'].flag_strict = False
    q['additional_information'] = information
    q['output_buffer_length'] = limit
    q['file_id'] = h.file_id
    if ignored_input:
        # Deliberately points outside the packet. Security queries must not
        # dereference these fields or reject their values.
        q['input_buffer_offset'] = 0xffff
        q['input_buffer_length'] = 0xffffffff
        q['buffer'].size = 0
    return q


def query(h, information=7, limit=65536, ignored_input=False):
    q = query_packet(h, information, limit, ignored_input)
    t = h.tree_connect
    response = h.connection.receive(h.connection.send(q, t.session.session_id, t.tree_connect_id))
    result = SMB2QueryInfoResponse()
    result.unpack(response['data'].get_value())
    return result['buffer'].get_value()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    report = dict(status='failed', host=platform.platform(), checks=[],
                  recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    f = None
    clients = []
    def passed(message):
        report['checks'].append(message)
        print('PASS ' + message, flush=True)
    try:
        f = Fixture(a.bin, memory=1024)
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c = Connection(uuid.uuid4(), '127.0.0.1', f.smbport, require_signing=True)
            clients.append(c)
            c.connect(dialect=dialect, timeout=10)
            breaks = capture_breaks(c, include_level=True)
            s = Session(c, 'TAUCLOUD\\alice', f.password,
                        require_encryption=dialect >= 0x300, auth_protocol='ntlm')
            s.connect()
            t = TreeConnect(s, r'\\127.0.0.1\smb')
            t.connect()
            h = create(t, f'query-security-{dialect:x}', access=0x1f01ff)
            set_sd(h, descriptor([ace(EVERYONE)], control=0x9004), 0x80000004)
            expected = query(h)
            for flags in (0xa0000007, 0xffffffff & ~0x10078, 0x80000007, 0x20000007):
                assert query(h, flags) == expected, hex(flags)
            assert query(h, ignored_input=True) == expected
            passed(f'{dialect:x}: QUERY ignores unknown and SET-only protection flags, including both protection bits; unused input fields are ignored')

            empty = struct.pack('<BBHIIII', 1, 0, 0x8000, 0, 0, 0, 0)
            assert query(h, 0) == query(h, 0xa0000000) == empty
            for flags, expected_control in ((1, 0x8000), (2, 0x8000), (4, 0x9004)):
                data = query(h, flags)
                assert struct.unpack_from('<H', data, 2)[0] == expected_control
                offsets = struct.unpack_from('<IIII', data, 4)
                assert bool(offsets[0]) == bool(flags & 1)
                assert bool(offsets[1]) == bool(flags & 2)
                assert offsets[2] == 0 and bool(offsets[3]) == bool(flags & 4)
            passed(f'{dialect:x}: empty selector returns only self-relative header; section selection filters offsets and control flags')

            limited = create(t, h.file_name, access=0x80, disposition=1)
            assert query(limited, 0xa0000000) == empty
            denied(lambda: query(limited, 0xa0000007), 0xc0000022)
            denied(lambda: query(h, 0xa0000008), 0xc0000022)
            for flags in (0x10, 0x20, 0x40, 0x10000):
                denied(lambda flags=flags: query(h, flags), 0xc00000bb)
            limited.close()
            passed(f'{dialect:x}: ignored flags do not bypass READ_CONTROL/SACL checks; known unsupported security selectors remain explicit')

            for limit in (0, 1, len(expected) - 1):
                try:
                    query(h, limit=limit)
                except SMBResponseException as error:
                    assert error.status == 0xc0000023
                    required = struct.pack('<I', len(expected))
                    if dialect == 0x311:
                        wanted = struct.pack('<HBBIII', 9, 1, 0, 12, 4, 0) + required
                    else:
                        wanted = struct.pack('<HBBI', 9, 0, 0, 4) + required
                    actual = error.header['data'].get_value()
                    assert actual == wanted, (hex(dialect), limit, actual.hex(), wanted.hex())
                    assert error.error_details == [required]
                else:
                    raise AssertionError('undersized query unexpectedly succeeded')
            assert query(h, limit=len(expected)) == expected
            passed(f'{dialect:x}: exact required length, SMB3.1.1 error context and older-dialect raw error data; exact-fit retry succeeds')
            h.close()

            holder = Open(t, h.file_name)
            holder.create(2, 0x1f01ff, 0x80, 7, 1, 0x40, oplock_level=8)
            assert holder.oplock_level == 8
            contender = Open(t, h.file_name)
            opening, receive_open = contender.create(2, 0x120089, 0x80, 7, 1, 0x40, oplock_level=1, send=False)
            packet = query_packet(holder, limit=1)
            packet['file_id'] = b'\xff' * 16
            requests = c.send_compound([opening, packet], s.session_id, t.tree_connect_id, related=True)
            pending(requests[0]); pending(requests[1])
            observed = breaks.get(timeout=10)
            assert observed == (s.session_id, holder.file_id, s.encrypt_data, 1), observed
            c.receive(c.send(Ack(holder.file_id, 1), s.session_id, t.tree_connect_id))
            receive_open(requests[0])
            try:
                c.receive(requests[1])
            except SMBResponseException as error:
                assert error.status == 0xc0000023
                assert error.header['data'].get_value() == wanted
                assert error.header['flags'].get_value() & 2
                assert error.header['credit_response'].get_value() == 0
            else:
                raise AssertionError('asynchronous undersized query unexpectedly succeeded')
            assert query(contender) == expected
            contender.close(); holder.close()
            passed(f'{dialect:x}: related CREATE/QUERY resumed after cache recall preserves required-size error body, AsyncId and zero extra credits')
            c.disconnect()
            clients.remove(c)
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc()
        raise
    finally:
        for c in clients:
            try: c.disconnect()
            except Exception: pass
        if f:
            f.close()
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
