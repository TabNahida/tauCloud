#!/usr/bin/env python3
"""Explicit SMB ownership authority with independent security descriptor codecs."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import traceback

from m5_integration import Fixture, create, denied, query
from smb_security_integration import FULL, EVERYONE, CREATOR, ace, descriptor, get_sd, set_sd, parse
from smbprotocol.open import Open, ImpersonationLevel
from smbprotocol.create_contexts import SMB2CreateContextRequest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    args = p.parse_args(); f = None; connections = []
    report = dict(status='failed', checks=[])

    def passed(message):
        report['checks'].append(message); print('PASS ' + message, flush=True)

    try:
        f = Fixture(args.bin, 512 if args.sanitizers else 256)
        f.api('grants', f.admin, dict(space='smbdata', subject_type='user', subject='bob', rights='rw'))
        f.api('shares', f.admin, dict(id='owner-readonly', space='smbdata', exposures={'smb':'r'}))
        f.api('spaces', f.admin, dict(id='other-owner', root='data', path='other-owner', owner='alice', quota=2**20))
        f.api('grants', f.admin, dict(space='other-owner', subject_type='user', subject='bob', rights='rw'))
        f.api('shares', f.admin, dict(id='other-owner', space='other-owner', exposures={'smb':'rw'}))
        member = f.api('auth/login', data=dict(username='bob', password=f.password, scope='files'))['token']
        assignment = dict(id='bob-owner', username='bob', space='smbdata', mode='take')
        f.api('smb-owner-authority', member, assignment, expected=403)
        f.api('smb-owner-authority', member, expected=403)
        f.api('smb-owner-authority', f.admin, dict(assignment, mode='admin'), expected=400)

        def tree(user='alice', share='smb'):
            c, _, t = f.connect(user=user, share=share); connections.append(c); return t

        t, bt = tree(), tree('bob')
        h = create(t, 'denied-owner', access=FULL); alice = parse(get_sd(h))['owner']
        set_sd(h, descriptor([])); h.close()
        h = create(bt, 'bob-id', access=FULL); bob = parse(get_sd(h))['owner']; h.close()
        denied(lambda: create(bt, 'denied-owner', access=0x80000, disposition=1), 0xc0000022)
        f.api('smb-owner-authority', f.admin, assignment)
        f.api('smb-owner-authority', f.admin, dict(assignment, id='duplicate'), expected=409)
        assert any(x['id'] == 'bob-owner' and x['mode'] == 'take' for x in f.api('smb-owner-authority', f.admin))
        t, bt = tree(), tree('bob')
        h = create(bt, 'denied-owner', access=0x02000000, disposition=1)
        rights = struct.unpack('<I', query(h, 8))[0]
        assert rights & 0x80000 and not rights & (1 | 2 | 0x40000)
        denied(lambda: set_sd(h, descriptor(owner=EVERYONE), 1), 0xc000005a)
        set_sd(h, descriptor(owner=bob), 1); h.close()
        h = create(bt, 'denied-owner', access=0x60000, disposition=1)
        assert parse(get_sd(h))['owner'] == bob
        set_sd(h, descriptor([ace(EVERYONE)])); h.close()
        passed('admin-only scoped ownership assignment; take overrides denied WRITE_OWNER and MAXIMUM_ALLOWED only, allows self ownership and denies arbitrary SIDs')

        assignment['mode'] = 'restore'
        f.api('smb-owner-authority', f.admin, dict(assignment, update=True))
        t, bt = tree(), tree('bob')
        h = create(bt, 'restore-owner', access=FULL)
        group = bytes.fromhex('010500000000000515000000') + hashlib.sha256(b'tauCloud/group/restored').digest()[:16]
        set_sd(h, descriptor(owner=EVERYONE, group=group), 3)
        result = parse(get_sd(h)); assert result['owner'] == EVERYONE and result['group'] == group
        before = get_sd(h)
        denied(lambda: set_sd(h, descriptor(owner=b'', group=group), 3), 0xc000005a)
        assert get_sd(h) == before
        denied(lambda: create(bt, 'restore-owner', access=0x01000000, disposition=1), 0xc0000061)
        h.close()
        h = create(t, 'write-denied', access=FULL); set_sd(h, descriptor([])); h.close()
        denied(lambda: create(bt, 'write-denied', access=0x80000, disposition=1), 0xc0000022)
        h = create(bt, 'write-denied', access=0x02000000, disposition=1)
        assert not struct.unpack('<I', query(h, 8))[0] & 0x80000
        h.close()
        h = create(bt, 'write-denied', access=0x80000, disposition=1, options=0x4040)
        set_sd(h, descriptor(owner=EVERYONE), 1); h.close()
        denied(lambda: create(bt, 'write-denied', access=2, disposition=1), 0xc0000022)
        denied(lambda: create(bt, 'write-denied', access=0x40000, disposition=1), 0xc0000022)
        denied(lambda: create(bt, 'write-denied', access=2, disposition=1, options=0x4040), 0xc0000022)
        denied(lambda: create(bt, 'write-denied', access=0x40000, disposition=1, options=0x4040), 0xc0000022)
        denied(lambda: create(tree('bob', 'owner-readonly'), 'restore-owner', access=0x80000, disposition=1), 0xc0000022)
        other = create(tree('alice', 'other-owner'), 'private', access=FULL)
        set_sd(other, descriptor([])); other.close()
        denied(lambda: create(tree('bob', 'other-owner'), 'private', access=0x80000, disposition=1), 0xc0000022)
        passed('restore accepts valid arbitrary owner/group SIDs atomically and overrides WRITE_OWNER only with backup intent; it cannot bypass data/WRITE_DAC/SACL rights, readonly shares or its configured space')

        parent = create(t, 'inherit-owner', access=FULL, options=1)
        creator_group = bytes.fromhex('010100000000000301000000')
        set_sd(parent, descriptor([ace(EVERYONE), ace(CREATOR, 0x120089, flags=3), ace(creator_group, 1, flags=3)]))
        parent.close()
        for explicit in (False, True):
            ctx = SMB2CreateContextRequest(); ctx['buffer_name'] = b'SecD'
            ctx['buffer_data'] = descriptor([ace(EVERYONE)] if explicit else None,
                owner=alice, group=group, control=0x8004 if explicit else 0x8000)
            child = Open(bt, 'inherit-owner/' + str(explicit))
            child.create(ImpersonationLevel.Impersonation, FULL, 0x80, 7, 3, 0x40, create_contexts=[ctx])
            sd = parse(get_sd(child)); assert sd['owner'] == alice and sd['group'] == group
            assert any(x[3] == alice and x[2] == 0x120089 for x in sd['dacl']), sd
            assert any(x[3] == group and x[2] == 1 for x in sd['dacl']), sd
            child.close()
        passed('SecD restores initial owner/group and resolves inherited CREATOR OWNER/GROUP against those identities, with or without an explicit DACL')

        h = create(bt, 'restore-owner', access=FULL, disposition=1)
        f.api('smb-owner-authority', f.admin, dict(assignment, mode='none', update=True))
        denied(lambda: set_sd(h, descriptor(owner=alice), 1), 0xc0000128)
        bt = tree('bob'); h = create(bt, 'restore-owner', access=FULL, disposition=1)
        denied(lambda: set_sd(h, descriptor(owner=alice), 1), 0xc000005a)
        h.close()
        f.api('smb-owner-authority', f.admin, dict(assignment, update=True))
        for c in connections:
            c.disconnect(close=False)
        connections.clear(); f.stop(); f.start()
        h = create(tree('bob'), 'restore-owner', access=FULL, disposition=1)
        set_sd(h, descriptor(owner=alice), 1); assert parse(get_sd(h))['owner'] == alice; h.close()
        passed('authority revocation drains old privileged handles; fresh ordinary handles cannot restore, and explicitly restored authority persists across service restart')
        report['status'] = 'passed'
    except Exception:
        report['error'] = traceback.format_exc(); print(report['error'], flush=True)
        if f:
            f.log.flush(); report['server_log'] = (f.base / 'supervisor.log').read_text(errors='replace')[-8000:]
    finally:
        for c in connections:
            try: c.disconnect(close=False)
            except Exception: pass
        if f: f.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
