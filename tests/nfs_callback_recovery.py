#!/usr/bin/env python3
"""NFS callback session readiness and definitive CB_SEQUENCE error recovery."""
import argparse
import json
from pathlib import Path
import struct
import time
import traceback
from nfs_backchannel_integration import CallbackClient
from m7_integration import op, t4
from pynfs_acceptance import fixture


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    a = p.parse_args(); f = None; clients = []; report = dict(status='failed',checks=[])
    def passed(s): report['checks'].append(s); print('PASS '+s,flush=True)
    def client():
        c = CallbackClient(port); c.hold_sequence = True; clients.append(c); return c
    def error_reply(c, code, tail=b''):
        c.acknowledge_sequence(body=struct.pack('>5I',code,0,1,11,code)+tail)
    def reprobe(c):
        r = c.compound([op.backchannel_ctl(c.program,[t4.callback_sec_parms4(0)])]); assert r.status==0,r
        c.path(False)
    try:
        f,port = fixture(a.bin,1024 if a.sanitizers else 256)
        c = client(); c.establish()
        # A callback may race session installation. This session deliberately
        # carries no forechannel SEQUENCE until the backchannel is established.
        for _ in range(50):
            assert c.compound([],False).status == 0
            if c.sequences: break
            time.sleep(.02)
        assert c.probes and len(c.sequences)==1
        original=c.sequences[-1][1]
        error_reply(c,10052)
        for _ in range(50):
            assert c.compound([],False).status == 0
            if len(c.sequences)==2: break
            time.sleep(.02)
        assert len(c.sequences)==2 and c.sequences[-1][1]==original
        c.acknowledge_sequence(); c.path(True)
        passed('initial CB_SEQUENCE BADSESSION retries exact slot after session-installation race, without requiring forechannel SEQUENCE on a callback-only session')

        q=client(); q.establish()
        for _ in range(50):
            assert q.compound([],False).status==0
            if q.sequences: break
            time.sleep(.02)
        assert len(q.sequences)==1
        original=q.sequences[-1][1]
        q.flags()  # Forechannel progress overtakes the initial callback reply.
        error_reply(q,10052); q.sequence_count(2)
        assert q.sequences[-1][1]==original and not q.flags() & 0x400
        q.acknowledge_sequence(); q.path(True); q.close()
        passed('initial-callback classification is captured when sent, so a forechannel SEQUENCE overtaking its BADSESSION reply cannot create a false permanent fault')

        # DELAY is a completed, authenticated error, not lost execution.
        # Retrying the same sequence on the live transport is safe.
        reprobe(c); original = c.sequences[-1][1]; count=len(c.sequences)
        error_reply(c,10008)
        assert not c.flags() & 0x400
        c.sequence_count(count+1)
        assert c.sequences[-1][1] == original
        c.acknowledge_sequence(); c.path(True)
        passed('CB_SEQUENCE DELAY retains exact request/slot, retries after backoff on the live connection and leaves ordinary file operations usable')

        # Terminal slot errors cannot be repaired by pretending the slot advanced.
        for code in (10052,10053,10063,10076):
            q=client(); q.establish(); q.path(False)
            q.acknowledge_sequence(); q.path(True); reprobe(q); count=len(q.sequences)
            error_reply(q,code)
            flags=q.flags()
            assert flags & 0x400 and flags & 1, (code,flags)
            for _ in range(5):
                assert q.compound([],False).status==0
                time.sleep(.02)
            assert len(q.sequences)==count
            r=q.compound([op.destroy_session(q.sid)],False); assert r.status==0,r
            q.establish(); q.path(False)
            assert not q.flags() & 0x400
            q.acknowledge_sequence(); q.path(True); q.close()
        passed('BADSESSION, BADSLOT, SEQ_MISORDERED and SEQ_FALSE_RETRY report BACKCHANNEL_FAULT without tearing down the shared TCP stream; a new session recovers')

        q=client(); q.establish(); q.path(False); original=q.sequences[-1][1]
        error_reply(q,10055)
        q.path(False); count=len(q.sequences)
        assert not q.flags() & 0x400
        r=q.compound([op.bind_conn_to_session(q.sid,3,False)],False); assert r.status==0,r
        q.sequence_count(count+1)
        assert q.sequences[-1][1]==original
        q.acknowledge_sequence(); q.path(True)
        passed('CONN_NOT_BOUND_TO_SESSION withdraws callback readiness; explicit rebind retries the same sequence without marking a permanent session fault')

        q=client(); q.establish(); q.path(False); original=q.sequences[-1][1]
        error_reply(q,10008,b'junk'); q.wait_closed()
        count=len(q.sequences); q.reconnect(); q.sequence_count(count+1)
        assert q.sequences[-1][1]==original
        q.acknowledge_sequence(); q.path(True)
        passed('an error reply with trailing XDR remains invalid and must disconnect before an exact retry')
        report['status']='passed'
    except Exception:
        report['error']=traceback.format_exc(); print(report['error'],flush=True)
        if f:
            f.log.flush(); report['server_log']=(f.base/'supervisor.log').read_text(errors='replace')[-12000:]
    finally:
        for c in clients:
            try: c.close()
            except Exception: pass
        if f:
            try: f.close()
            except Exception: report['status']='failed'; report['cleanup_error']=traceback.format_exc()
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
    return int(report['status']!='passed')

if __name__=='__main__':raise SystemExit(main())
