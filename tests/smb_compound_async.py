#!/usr/bin/env python3
"""Independent signed/encrypted clients verify dependent asynchronous compounds."""
import argparse
import datetime
import json
from pathlib import Path
import platform
import traceback
import uuid

from smbprotocol.connection import Connection, SMB2Echo
from smbprotocol.session import SMB2Logoff
from smbprotocol.tree import SMB2TreeDisconnect
from smbprotocol.change_notify import SMB2ChangeNotifyRequest
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open
from m5_integration import Fixture, Lock, create, denied, lock
from smb_blocking_locks import pending, completed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = dict(status='failed', host=platform.platform(), checks=[],
                  recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    fixture = None
    clients = []
    def passed(text):
        report['checks'].append(text)
        print('PASS ' + text, flush=True)
    def connect(dialect):
        c = Connection(uuid.uuid4(), '127.0.0.1', fixture.smbport, require_signing=True)
        clients.append(c)
        c.connect(dialect=dialect, timeout=10)
        s = Session(c, username='TAUCLOUD\\alice', password=fixture.password,
                    require_encryption=dialect >= 0x300, auth_protocol='ntlm')
        s.connect()
        t = TreeConnect(s, r'\\127.0.0.1\smb'); t.connect()
        return c, s, t
    def chain(c, s, t, bodies):
        requests = c.send_compound(bodies, s.session_id, t.tree_connect_id, related=True)
        for request in requests: pending(request)
        ids = [request.async_id for request in requests]
        assert len(set(ids)) == len(ids), 'dependent operations share an AsyncId'
        c.echo(sid=s.session_id, timeout=5)
        return requests
    def final(c, request, status=0):
        if status:
            denied(lambda: c.receive(request, timeout=10), status)
            response = request.response
        else:
            response = c.receive(request, timeout=10)
            assert response['status'].get_value() == 0
        assert response['flags'].get_value() & 2
        assert response['credit_response'].get_value() == 0
        return response
    try:
        fixture = Fixture(args.bin)
        for dialect in (0x210, 0x300, 0x302, 0x311):
            c, s, t = connect(dialect)
            holder = create(t, f'dependent-{dialect:x}')
            waiter = create(t, holder.file_name)
            holder.write(b'old data')
            lock(holder, (0, 8, 0x12))
            write, receive_write = waiter.write(b'new data', send=False)
            read, receive_read = waiter.read(0, 8, send=False)
            close, receive_close = waiter.close(send=False)
            for body in (write, read, close): body['file_id'] = b'\xff' * 16
            requests = chain(c, s, t, [Lock(waiter.file_id, [(0, 8, 2)]), write, read,
                                      Lock(b'\xff' * 16, [(0, 8, 4)]), close])
            assert holder.read(0, 8) == b'old data', 'dependent write ran before LOCK'
            lock(holder, (0, 8, 4)); completed(c, requests[0])
            final(c, requests[1]); assert receive_write(requests[1]) == 8
            final(c, requests[2]); assert receive_read(requests[2]) == b'new data'
            completed(c, requests[3]); final(c, requests[4]); receive_close(requests[4])
            assert holder.read(0, 8) == b'new data'
            passed(f'{dialect:x}: LOCK/WRITE/READ/UNLOCK/CLOSE waits in order, resolves inherited FileIds, keeps ECHO live and grants final credits once')

            waiter = create(t, holder.file_name)
            lock(holder, (0, 8, 0x12)); lock(holder, (16, 8, 0x12))
            read, receive_read = waiter.read(0, 8, send=False); read['file_id'] = b'\xff' * 16
            requests = chain(c, s, t, [Lock(waiter.file_id, [(0, 8, 2)]),
                                      Lock(b'\xff' * 16, [(16, 8, 2)]), read])
            second_id = requests[1].async_id
            lock(holder, (0, 8, 4)); completed(c, requests[0])
            pending(requests[1]); pending(requests[2]); c.echo(sid=s.session_id)
            assert requests[1].async_id == second_id
            lock(holder, (16, 8, 4)); completed(c, requests[1])
            final(c, requests[2]); assert receive_read(requests[2]) == b'new data'
            lock(waiter, (0, 8, 4)); lock(waiter, (16, 8, 4))
            passed(f'{dialect:x}: a resumed LOCK can wait again without replacing its announced AsyncId or executing its dependent READ')

            for cancel_index in (0, 1):
                lock(holder, (0, 8, 0x12))
                write, _ = waiter.write(b'bad data', send=False); write['file_id'] = b'\xff' * 16
                close, _ = waiter.close(send=False); close['file_id'] = b'\xff' * 16
                requests = chain(c, s, t, [Lock(waiter.file_id, [(0, 8, 2)]), write, close])
                requests[cancel_index].cancel()
                for request in requests[cancel_index:]: final(c, request, 0xc0000120)
                lock(holder, (0, 8, 4))
                if cancel_index:
                    completed(c, requests[0]); lock(waiter, (0, 8, 4))
                assert holder.read(0, 8) == b'new data'
                assert waiter.read(0, 8) == b'new data', 'cancelled chain closed its handle'
            passed(f'{dialect:x}: cancelling the predecessor or a dependent operation propagates failure without writes, CLOSE side effects or ghost locks')

            # A deferred CREATE generates a new FileId for the following work.
            lock(holder, (0, 8, 0x12))
            created = Open(t, f'created-after-{dialect:x}')
            opening, receive_open = created.create(2, 0x13019f, 0x80, 7, 3, 0x40, send=False)
            write, receive_write = waiter.write(b'created!', send=False); write['file_id'] = b'\xff' * 16
            close, _ = waiter.close(send=False); close['file_id'] = b'\xff' * 16
            requests = chain(c, s, t, [Lock(waiter.file_id, [(0, 8, 2)]), opening, write, close])
            assert not (fixture.root/'smbdata'/created.file_name).exists()
            lock(holder, (0, 8, 4)); completed(c, requests[0]); final(c, requests[1]); receive_open(requests[1])
            final(c, requests[2]); assert receive_write(requests[2]) == 8
            final(c, requests[3]); lock(waiter, (0, 8, 4))
            assert (fixture.root/'smbdata'/created.file_name).read_bytes() == b'created!'
            assert holder.read(0, 8) == b'new data'
            waiter.close(); holder.close(); c.disconnect()
            passed(f'{dialect:x}: deferred CREATE changes the inherited FileId and dependent writes target only the newly opened object')

        # An already waiting notification precedes a deferred notification even
        # when the latter was assigned its transport AsyncId earlier.
        from smb_notify_integration import notify, events
        c, s, t = connect(0x311)
        holder = create(t, 'notify-order'); waiter = create(t, holder.file_name)
        directory = create(t, 'notify-dir', options=1, access=0x120089)
        lock(holder, (0, 8, 0x12))
        watch = SMB2ChangeNotifyRequest(); watch['file_id'] = directory.file_id
        watch['completion_filter'] = 1; watch['output_buffer_length'] = 65536
        requests = chain(c, s, t, [Lock(waiter.file_id, [(0, 8, 2)]), watch, SMB2Echo()])
        older = notify(directory, 1)
        lock(holder, (0, 8, 4)); completed(c, requests[0])
        # Resume and register the dependent watch before producing its events.
        import time
        time.sleep(.15); c.echo(sid=s.session_id)
        create(t, 'notify-dir/first').close(); assert events(c, older) == [(1, 'first')]
        pending(requests[1]); pending(requests[2])
        create(t, 'notify-dir/second').close(); assert events(c, requests[1]) == [(1, 'second')]
        final(c, requests[2]); waiter.close(); holder.close(); directory.close(); c.disconnect()
        passed('deferred CHANGE_NOTIFY keeps its AsyncId, honors actual registration FIFO and releases its dependent ECHO only after notification')

        # Teardown itself can be the dependent operation; it must not cancel
        # its own response while cancelling other pending work on the tree.
        for action in ('tree', 'session'):
            c, s, t = connect(0x311)
            holder = create(t, 'deferred-' + action); waiter = create(t, holder.file_name)
            lock(holder, (0, 8, 0x12))
            teardown = SMB2TreeDisconnect() if action == 'tree' else SMB2Logoff()
            requests = chain(c, s, t, [Lock(waiter.file_id, [(0, 8, 2)]), teardown])
            lock(holder, (0, 8, 4)); completed(c, requests[0]); final(c, requests[1])
            c.disconnect(close=False)
        passed('deferred TREE_DISCONNECT and LOGOFF complete successfully without cancelling their own response')

        c, s, t = connect(0x311)
        holder = create(t, 'bounded-chain'); waiter = create(t, holder.file_name)
        holder.write(b'unchanged'); lock(holder, (0, 8, 0x12))
        waiting = []
        for size in [15] * 8 + [8]:
            waiting.append(chain(c, s, t, [Lock(waiter.file_id, [(0, 8, 2)])] +
                                 [SMB2Echo() for _ in range(size)]))
        write, _ = waiter.write(b'bad!', send=False)
        close, _ = waiter.close(send=False)
        rejected = c.send_compound([Lock(waiter.file_id, [(0, 8, 2)]), write, close],
                                   s.session_id, t.tree_connect_id, related=True)
        pending(rejected[0])
        for request in rejected[1:]: denied(lambda request=request: c.receive(request, timeout=10), 0xc000009a)
        rejected[0].cancel(); final(c, rejected[0], 0xc0000120)
        for requests in waiting:
            requests[0].cancel()
            for request in requests: final(c, request, 0xc0000120)
        lock(holder, (0, 8, 4))
        assert waiter.read(0, 9) == b'unchanged'
        lock(holder, (0, 8, 0x12))
        recycled = chain(c, s, t, [Lock(waiter.file_id, [(0, 8, 2)]), SMB2Echo()])
        lock(holder, (0, 8, 4)); completed(c, recycled[0]); final(c, recycled[1])
        waiter.close(); holder.close(); c.disconnect()
        passed('128 dependent-command bound rejects excess work and its descendants without side effects; cancellation releases all capacity for reuse')

        # Teardown must complete dependent commands under the old session keys.
        for action in ('tree', 'session'):
            c, s, t = connect(0x311)
            holder = create(t, action); waiter = create(t, action)
            lock(holder, (0, 8, 0x12))
            write, _ = waiter.write(b'forbidden', send=False)
            requests = chain(c, s, t, [Lock(waiter.file_id, [(0, 8, 2)]), write])
            if action == 'tree': t.disconnect()
            else: s.disconnect(close=False)
            for request in requests: final(c, request, 0xc000007e)
            c.disconnect(close=False)
        passed('TREE_DISCONNECT and LOGOFF finish pending dependencies under their owning encryption keys')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if fixture:
            fixture.log.flush()
            report['server_log'] = (fixture.base/'supervisor.log').read_text(errors='replace')[-18000:]
    finally:
        for c in clients:
            try: c.disconnect(close=False)
            except Exception: pass
        if fixture:
            try: fixture.close()
            except Exception:
                report['status'] = 'failed'; report['cleanup_error'] = traceback.format_exc()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(main())
