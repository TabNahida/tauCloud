#!/usr/bin/env python3
"""Independent NFSv4.1 channel negotiation, retry and session usability checks."""
import argparse
import json
import uuid
from pathlib import Path
from pynfs_acceptance import fixture
from m7_integration import Client, op, t4, p4


def run(args):
    f, port = fixture(args.bin, 512 if args.sanitizers else 256)
    c = Client(port)
    checks = []
    fields = ('ca_headerpadsize', 'ca_maxrequestsize', 'ca_maxresponsesize',
              'ca_maxresponsesize_cached', 'ca_maxoperations', 'ca_maxrequests')
    try:
        for size, operations, requests in ((128, 2, 2), (256, 16, 8),
                                           (4095, 128, 64), (8192, 0xffffffff, 0xffffffff)):
            owner = t4.client_owner4(b'12345678', uuid.uuid4().hex.encode())
            r = c.compound([op.exchange_id(owner, 0, t4.state_protect4_a(0), [])], False)
            assert r.status == 0, r
            exchanged = r.resarray[0].opexchange_id.eir_resok4
            fore = t4.channel_attrs4(64, 262144, 262144, 8192, 128, 2049, [57])
            back = t4.channel_attrs4(32, size, size, size, operations, requests, [57])
            request = op.create_session(exchanged.eir_clientid, exchanged.eir_sequenceid,
                                        0, fore, back, 123, [])
            r = c.compound([request], False)
            assert r.status == 0, r
            result = r.resarray[0].opcreate_session.csr_resok4
            for direction, offered, returned in (('fore', fore, result.csr_fore_chan_attrs),
                                                  ('back', back, result.csr_back_chan_attrs)):
                for field in fields[:4]:
                    assert getattr(returned, field) <= getattr(offered, field), (direction, field, offered, returned)
                assert returned.ca_maxresponsesize_cached <= returned.ca_maxresponsesize
                if direction == 'back':
                    assert returned.ca_maxoperations == operations, returned
                    assert returned.ca_maxrequests == requests, returned
                else:
                    assert 0 < returned.ca_maxoperations <= fore.ca_maxoperations
                    assert 0 < returned.ca_maxrequests <= fore.ca_maxrequests
                assert not returned.ca_rdma_ird or (len(returned.ca_rdma_ird) == 1 and returned.ca_rdma_ird[0] <= 57)
            assert result.csr_sequence == exchanged.eir_sequenceid and result.csr_flags == 0
            # CREATE_SESSION has a separate replay cache. Changing offers on a
            # retry must return the original session and negotiated attributes.
            retry = op.create_session(exchanged.eir_clientid, exchanged.eir_sequenceid,
                                      0, back, fore, 456, [])
            replay = c.compound([retry], False)
            assert replay.status == 0, replay
            encoded = []
            for response in (r, replay):
                packer = p4.NFS4Packer()
                packer.pack_CREATE_SESSION4res(response.resarray[0].opcreate_session)
                encoded.append(packer.get_buffer())
            assert encoded[0] == encoded[1], (r, replay)
            c.sid = result.csr_sessionid; c.seq = 0
            r = c.compound([op.putrootfh(), op.getfh()])
            assert r.status == 0 and r.resarray[-1].opgetfh.resok4.object == b'tauCloud:nfs:root', r
            r = c.compound([op.destroy_session(c.sid)], False); assert r.status == 0, r
            r = c.compound([op.destroy_clientid(exchanged.eir_clientid)], False); assert r.status == 0, r
        checks.append('four backchannel offers preserve operation/concurrency counts and never increase buffer/RDMA limits; forechannel stays bounded')
        checks.append('CREATE_SESSION retries preserve the original negotiated session; subsequent SEQUENCE/GETFH and explicit destruction work')
        report = dict(status='passed', checks=checks, sanitizers=args.sanitizers)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report))
    finally:
        c.close(); f.close()


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    run(p.parse_args())
