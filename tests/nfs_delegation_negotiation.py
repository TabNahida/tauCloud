#!/usr/bin/env python3
"""NFSv4.1 delegation preferences, refusal reasons, authority and slot replay.

These checks do not establish delegation grants or CB_RECALL conformance.
The separate, unmodified pynfs delegation suite retains those failures.
"""
import argparse
import datetime
import json
from pathlib import Path
import struct
import traceback

from m7_integration import Client, op, t4, p4
from pynfs_acceptance import fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sanitizers', action='store_true')
    args = parser.parse_args()
    f, port = fixture(args.bin, 1024 if args.sanitizers else 256)
    clients = []
    report = dict(status='failed', checks=[], recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())

    def passed(text):
        report['checks'].append(text); print('PASS ' + text, flush=True)

    def client(uid=1000, reclaim=False, owner=None):
        c = Client(port, uid=uid); clients.append(c); c.session(owner, reclaim=reclaim); return c

    def call(c, operations, status=0, **kwargs):
        r = c.compound(operations, **kwargs)
        assert r.status == status, r
        return r

    def encoded(result):
        packer = p4.NFS4Packer(); packer.pack_COMPOUND4res(result); return packer.get_buffer()

    def refusal(delegation, why=None):
        packer = p4.NFS4Packer(); packer.pack_open_delegation4(delegation)
        expected = struct.pack('>I', 0) if why is None else struct.pack('>II', 3, why)
        if why == 2: expected += struct.pack('>I', 0)  # No promised availability callback.
        assert packer.get_buffer() == expected, delegation

    def opening(c, parent, name, access, create=True, claim=0):
        how = t4.openflag4(1, t4.createhow4(0, t4.fattr4([], b''))) if create else t4.openflag4(0)
        return [op.putfh(parent), op.open(0, access, 0, t4.open_owner4(c.cid, b'owner'), how,
                t4.open_claim4(claim, file=name if claim == 0 else None)), op.getfh()]

    def want(handle, flags, claim=4):
        return [op.putfh(handle), op.want_delegation(flags, t4.deleg_claim4(claim)), op.getfh()]

    try:
        c = client(); root = c.root()
        for access in (1, 2, 3):
            for preference in (0, 0x100, 0x200, 0x300, 0x400, 0x500):
                for hints in (0, 0x10000, 0x20000, 0x30000):
                    flags = access | preference | hints
                    r = call(c, opening(c, root, b'preferences', flags))
                    opened = r.resarray[2].opopen.resok4; fh = r.resarray[3].opgetfh.resok4.object
                    why = None if not (preference | hints) else 0 if preference == 0x400 else 7 if preference == 0x500 else 2
                    refusal(opened.delegation, why)
                    if access == 1: call(c, [op.putfh(fh), op.write(opened.stateid, 0, 2, b'bad')], 10038)
                    if access == 2: call(c, [op.putfh(fh), op.read(opened.stateid, 0, 1)], 10038)
                    call(c, [op.putfh(fh), op.close(0, opened.stateid)])
        passed('all 72 OPEN access/preference/hint combinations encode exact NONE/NONE_EXT reasons without gaining data rights or promising callbacks')

        for access in (0, 0x100, 4, 0x603, 0x1003, 0x40003, 0x80000003):
            name = f'invalid-{access:x}'.encode()
            r = call(c, opening(c, root, name, access), 22)
            assert len(r.resarray) == 3 and r.resarray[-1].resop == 18
            assert not (f.root/'nfsdata'/name.decode()).exists()
        passed('invalid OPEN preferences/access bits stop before CREATE and do not mutate the namespace')

        r = call(c, opening(c, root, b'preferences', 0x401, create=False))
        opened = r.resarray[2].opopen.resok4; fh = r.resarray[3].opgetfh.resok4.object
        operations = opening(c, fh, b'', 0x503, create=False, claim=4)
        result = call(c, operations); sequence = c.seq
        upgraded = result.resarray[2].opopen.resok4
        refusal(upgraded.delegation, 7)
        assert upgraded.stateid.seqid == opened.stateid.seqid + 1
        assert encoded(call(c, operations, seq=sequence)) == encoded(result)
        call(c, [op.putfh(fh), op.write(upgraded.stateid, 0, 2, b'current')])
        call(c, [op.putfh(fh), op.close(0, upgraded.stateid)])
        passed('CLAIM_FH honors cancellation while upgrading ordinary OPEN rights; exact slot replay does not advance the state twice')

        for preference, why in ((0x100, 2), (0x200, 2), (0x300, 2), (0x500, 7)):
            for ignored in (0, 1, 2, 3):
                for hints in (0, 0x30000):
                    r = call(c, want(fh, preference | ignored | hints))
                    refusal(r.resarray[2].opwant_delegation.wdr_resok4, why)
                    assert r.resarray[-1].opgetfh.resok4.object == fh
        passed('standalone WANT_DELEGATION ignores data-access bits, returns extended reasons, supports idempotent cancellation and preserves the current filehandle')

        for flags in (0, 1, 3, 0x400, 0x403, 0x10000, 0x600, 0x40000, 0x80000100):
            r = call(c, want(fh, flags), 22)
            assert len(r.resarray) == 3 and r.resarray[-1].resop == 56
        call(c, [op.want_delegation(0x100, t4.deleg_claim4(4))], 10020)
        r = call(c, want(root, 0x100))
        refusal(r.resarray[2].opwant_delegation.wdr_resok4, 8)
        call(c, want(fh, 0x100, claim=6), 10004)
        call(c, [op.putfh(fh), op.want_delegation(0x100, t4.deleg_claim4(1, dc_delegate_type=1))], 10033)
        pending = client(reclaim=True)
        call(pending, want(fh, 0x100), 10013)
        passed('standalone validation distinguishes invalid preference, missing handle, directory refusal, unsupported previous-client recovery and grace/reclaim errors')

        # A refusal is still a file-sensitive reply. Replaying it must not
        # bypass revoked export/mapping authority, and it creates no OPEN.
        isolated = client()
        operations = want(fh, 0x30100)
        result = call(isolated, operations); sequence = isolated.seq
        assert encoded(call(isolated, operations, seq=sequence)) == encoded(result)
        call(isolated, [op.destroy_session(isolated.sid)])
        call(isolated, [op.destroy_clientid(isolated.cid)], session=False)
        outsider = client(uid=1001)
        call(outsider, want(fh, 0x100), 13)
        result = call(c, operations); sequence = c.seq
        f.api('nfs-exports', f.admin, dict(id='nfs', trust='loopback-auth-sys', anonymous='bob',
              uids={'1000':'alice'}, gids={'1000':'unix'}, enabled=False, update=True))
        call(c, operations, 10008, seq=sequence)
        call(c, operations, 13)
        passed('WANT refuses unmapped callers, reauthorizes cached replies after export revocation and creates no hidden OPEN/client-busy state')

        f.api('nfs-exports', f.admin, dict(id='nfs', trust='loopback-auth-sys', anonymous='bob',
              uids={'1000':'alice'}, gids={'1000':'unix'}, enabled=True, update=True))
        _, retained = c.open(root, b'recovery-probe', create=True)
        owner = c.owner
        for old in clients: old.close()
        f.stop(); f.start()
        recovered = client(owner=owner, reclaim=True)
        reclaim_delegation = [op.putfh(retained),
            op.want_delegation(0x100, t4.deleg_claim4(1, dc_delegate_type=1))]
        call(recovered, reclaim_delegation, 10034)
        call(recovered, want(retained, 0x100), 10013)
        state, retained = recovered.open(retained, b'', claim=1)
        call(recovered, [op.reclaim_complete(False)])
        call(recovered, reclaim_delegation, 10033)
        call(recovered, [op.putfh(retained), op.close(0, state)])
        passed('real service restart preserves ordinary OPEN reclaim while rejecting invented delegation recovery during grace and after RECLAIM_COMPLETE')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        report['worker_logs'] = {role: path.read_text(errors='replace')[-16000:] for role in ('nfs', 'file')
            if (path := f.state/'logs'/(role+'.jsonl')).exists()}
    finally:
        for c in clients: c.close()
        f.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2)+'\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(main())
