#!/usr/bin/env python3
"""Real signed/encrypted SMB clients exercising asynchronous byte-range locks."""
import argparse
import json
import platform
import datetime
import struct
import traceback
import time
from concurrent.futures import ThreadPoolExecutor
from smbprotocol.exceptions import SMBResponseException
import uuid
from pathlib import Path

from m5_integration import Fixture, Lock, create, denied, lock
from smbprotocol.connection import Connection, SMB2Echo, SMB2CancelRequest
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect


def send_lock(h, start=0, length=8, flags=2):
    return h.connection.send(Lock(h.file_id, [(start, length, flags)]),
                             h.tree_connect.session.session_id, h.tree_connect.tree_connect_id)


def pending(request):
    assert request.response_event.wait(10), 'no interim response'
    with request.response_event_lock:
        response = request.response
        assert response['status'].get_value() == 0x103, response
        assert request.async_id and int.from_bytes(request.async_id, 'little') != 0
        assert response['flags'].get_value() & 2
        assert not response['flags'].get_value() & 8, 'interim response should not be signed'


def completed(c, request):
    response = c.receive(request, timeout=10)
    assert response['status'].get_value() == 0
    assert response['structure_size'].get_value() == 64
    assert response['flags'].get_value() & 2
    assert response['credit_response'].get_value() == 0, 'final response grants credits twice'
    assert response['data'].get_value() == struct.pack('<HH', 4, 0)


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', required=True)
    parser.add_argument('--idle', action='store_true', help='Exercise actual 60-second idle timer across a pending lock')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = {'status': 'failed', 'host': platform.platform(),
              'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'checks': []}
    fixture = Fixture(args.bin)
    clients = []

    def connect(dialect):
        c = Connection(uuid.uuid4(), '127.0.0.1', fixture.smbport, require_signing=True)
        clients.append(c)
        c.connect(dialect=dialect, timeout=10)
        s = Session(c, username='TAUCLOUD\\alice', password=fixture.password,
                    require_encryption=dialect >= 0x300, auth_protocol='ntlm')
        s.connect()
        t = TreeConnect(s, r'\\127.0.0.1\smb')
        t.connect()
        return c, s, t

    def passed(text):
        report['checks'].append(text)
        print('PASS ' + text, flush=True)

    try:
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, s, t = connect(dialect)
            d, ds, dt = connect(dialect)
            h = create(t, f'locks-{dialect:x}')
            other = create(dt, h.file_name)
            third = create(t, h.file_name)
            lock(h, (0, 8, 0x12))
            req = send_lock(other)
            pending(req)
            # The same transport must remain usable while a lock is pending.
            d.echo(sid=ds.session_id, timeout=5)
            lock(other, (32, 8, 0x12))
            lock(other, (32, 8, 4))
            lock(h, (0, 8, 4))
            completed(d, req)
            denied(lambda: lock(h, (0, 8, 0x12)), 0xc0000055)
            lock(other, (0, 8, 4))
            passed(f'{dialect:x}: pending async ID, live same-connection ECHO/LOCK, unlock wakes waiter, final credits and granted exclusion')

            lock(h, (0, 8, 0x12))
            req = send_lock(other)
            pending(req)
            # Unknown async cancellation has no response and consumes no credit.
            d.send(SMB2CancelRequest(), sid=ds.session_id,
                   message_id=req.message['message_id'].get_value(),
                   async_id=bytes.fromhex('ffffffffffffffff'), credit_request=0)
            d.echo(sid=ds.session_id, timeout=5)
            pending(req)
            req.cancel()
            denied(lambda: d.receive(req, timeout=10), 0xc0000120)
            lock(h, (0, 8, 4))
            lock(third, (0, 8, 0x12)); lock(third, (0, 8, 4))
            # Cancellation by original MessageId remains accepted after PENDING.
            lock(h, (0, 8, 0x12))
            req = send_lock(other); pending(req)
            d.send(SMB2CancelRequest(), sid=ds.session_id,
                   message_id=req.message['message_id'].get_value(), credit_request=0)
            denied(lambda: d.receive(req, timeout=10), 0xc0000120)
            lock(h, (0, 8, 4))
            passed(f'{dialect:x}: async-ID and MessageId CANCEL, unknown CANCEL, no ghost lock or credit loss')

            # Arrival order is enforced across connections, not polling order.
            lock(h, (0, 8, 0x12))
            first = send_lock(other); pending(first)
            second = send_lock(third); pending(second)
            lock(h, (0, 8, 4))
            completed(d, first)
            pending(second)
            lock(other, (0, 8, 4))
            completed(c, second)
            lock(third, (0, 8, 4))
            # A queued writer must not be starved by later shared readers.
            lock(h, (0, 8, 0x11))
            first = send_lock(other); pending(first)
            second = send_lock(third, flags=1); pending(second)
            lock(h, (0, 8, 4)); completed(d, first); pending(second)
            lock(other, (0, 8, 4)); completed(c, second); lock(third, (0, 8, 4))
            passed(f'{dialect:x}: cross-connection FIFO for conflicts and queued writer fairness')

            lock(h, (0, 8, 0x12))
            req = send_lock(other); pending(req)
            other.close()
            denied(lambda: d.receive(req, timeout=10), 0xc000007e)
            lock(h, (0, 8, 4))
            lock(third, (0, 8, 0x12)); lock(third, (0, 8, 4))
            other = create(dt, h.file_name)
            lock(h, (0, 8, 0x12))
            req = send_lock(other); pending(req)
            h.close()
            completed(d, req)
            lock(other, (0, 8, 4))
            other.close(); third.close()
            c.disconnect(); d.disconnect()
            passed(f'{dialect:x}: CLOSE cancels waiting requests and releases held ranges to another connection')

        c, s, t = connect(0x311)
        h = create(t, 'compound-waiter'); other = create(t, 'compound-waiter')
        lock(h, (0, 8, 0x12))
        requests = c.send_compound([Lock(other.file_id, [(0, 8, 2)]), SMB2Echo()],
                                   s.session_id, t.tree_connect_id, related=False)
        c.receive(requests[1], timeout=10); pending(requests[0])
        lock(h, (0, 8, 4)); completed(c, requests[0]); lock(other, (0, 8, 4))
        lock(h, (0, 8, 0x12))
        close_request, close_receive = other.close(send=False)
        requests = c.send_compound([Lock(other.file_id, [(0, 8, 2)]), close_request],
                                   s.session_id, t.tree_connect_id, related=False)
        close_receive(requests[1])
        denied(lambda: c.receive(requests[0], timeout=10), 0xc000007e)
        lock(h, (0, 8, 4)); h.close()
        passed('compound LOCK/ECHO and LOCK/CLOSE preserve interim/final ordering and connection progress')
        h = create(t, 'tree-close'); other = create(t, 'tree-close')
        lock(h, (0, 8, 0x12)); req = send_lock(other); pending(req)
        t.disconnect(); denied(lambda: c.receive(req, timeout=10), 0xc000007e)
        c.disconnect(close=False)
        passed('TREE_DISCONNECT cancels pending locks before removing the tree')
        c, s, t = connect(0x311)
        h = create(t, 'session-close'); other = create(t, 'session-close')
        lock(h, (0, 8, 0x12)); req = send_lock(other); pending(req)
        s.disconnect(close=False); denied(lambda: c.receive(req, timeout=10), 0xc000007e)
        c.disconnect()
        passed('session teardown cancels pending locks before discarding signing and encryption keys')

        c, s, t = connect(0x311)
        d, ds, dt = connect(0x311)
        h = create(t, 'disconnect-locks'); other = create(dt, 'disconnect-locks')
        lock(h, (0, 8, 0x12)); req = send_lock(other); pending(req)
        d.disconnect(close=False)
        # The later waiter is on the original connection and must survive peer EOF.
        third = create(t, 'disconnect-locks')
        second = send_lock(third); pending(second)
        lock(h, (0, 8, 4)); completed(c, second); lock(third, (0, 8, 4))
        h.close(); third.close()
        passed('peer disconnect removes a pending waiter before granting the next connection')

        d, ds, dt = connect(0x311)
        h = create(t, 'holder-disconnect'); other = create(dt, 'holder-disconnect')
        lock(h, (0, 8, 0x12)); req = send_lock(other); pending(req)
        c.disconnect(close=False); completed(d, req); lock(other, (0, 8, 4)); other.close()
        passed('holder disconnect releases locks and wakes the surviving client')

        c, s, t = connect(0x311)
        h = create(t, 'cancel-race'); other = create(dt, 'cancel-race')
        with ThreadPoolExecutor(max_workers=2) as workers:
            for _ in range(32):
                lock(h, (0, 8, 0x12)); req = send_lock(other); pending(req)
                cancelled = workers.submit(req.cancel)
                unlocked = workers.submit(lock, h, (0, 8, 4))
                cancelled.result(timeout=10); unlocked.result(timeout=10)
                try:
                    completed(d, req)
                    lock(other, (0, 8, 4))
                except SMBResponseException as error:
                    assert error.status == 0xc0000120
                lock(h, (0, 8, 0x12)); lock(h, (0, 8, 4))
                d.echo(sid=ds.session_id, timeout=5)
        h.close(); other.close(); c.disconnect()
        passed('32 concurrent CANCEL/unlock races produce one final result and no leaked lock or duplicate response')
        c, s, t = connect(0x311)
        h = create(t, 'close-race')
        with ThreadPoolExecutor(max_workers=2) as workers:
            for _ in range(16):
                other = create(dt, 'close-race')
                lock(h, (0, 8, 0x12)); req = send_lock(other); pending(req)
                closed = workers.submit(other.close)
                unlocked = workers.submit(lock, h, (0, 8, 4))
                closed.result(timeout=10); unlocked.result(timeout=10)
                try:
                    completed(d, req)
                except SMBResponseException as error:
                    assert error.status == 0xc000007e
                lock(h, (0, 8, 0x12)); lock(h, (0, 8, 4))
                d.echo(sid=ds.session_id, timeout=5)
        h.close(); c.disconnect()
        passed('16 concurrent CLOSE/unlock races produce one final result and release every acquired range')


        h = create(dt, 'bounded-waiters'); other = create(dt, 'bounded-waiters')
        lock(h, (0, 8, 0x12))
        requests = []
        for _ in range(16):
            req = send_lock(other); pending(req); requests.append(req)
        denied(lambda: d.receive(send_lock(other), timeout=10), 0xc000009a)
        for req in requests:
            req.cancel(); denied(lambda req=req: d.receive(req, timeout=10), 0xc0000120)
        lock(h, (0, 8, 4)); lock(other, (0, 8, 0x12)); lock(other, (0, 8, 4))
        h.close(); other.close()
        passed('bounded pending requests return INSUFFICIENT_RESOURCES and all cancelled capacity is reusable')

        h = create(dt, 'revoked-waiter'); other = create(dt, 'revoked-waiter')
        lock(h, (0, 8, 0x12)); req = send_lock(other); pending(req)
        fixture.api('smb/credentials', fixture.admin, dict(username='alice', enabled=False))
        denied(lambda: d.receive(req, timeout=10), 0xc0000022, 0xc000006d)
        d.disconnect(close=False)
        fixture.api('smb/credentials', fixture.admin, dict(username='alice', password=fixture.password))
        c, s, t = connect(0x311)
        h = create(t, 'revoked-waiter'); lock(h, (0, 8, 0x12)); lock(h, (0, 8, 4)); h.close()
        passed('credential revocation fails pending locks promptly and leaves no stale authority locks')
        if args.idle:
            h = create(t, 'long-wait'); other = create(t, 'long-wait')
            lock(h, (0, 8, 0x12)); req = send_lock(other); pending(req)
            time.sleep(65)
            pending(req)
            lock(h, (0, 8, 4)); completed(c, req); lock(other, (0, 8, 4))
            h.close(); other.close()
            print('PASS pending lock survives the 60-second read timeout; checking resumed idle expiry', flush=True)
            deadline = time.monotonic() + 70
            while c.transport.connected and time.monotonic() < deadline:
                time.sleep(0.1)
            assert not c.transport.connected, 'completed lock left the connection exempt from idle expiry'
            passed('pending lock survives 65 seconds without client traffic; normal idle expiry resumes after its final response')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc()
        raise
    finally:
        for c in clients:
            try: c.disconnect(close=False)
            except Exception: pass
        fixture.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    run()
