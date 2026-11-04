#!/usr/bin/env python3
"""Run unmodified Samba torture tests on a disposable authenticated share."""
import argparse
import datetime
import json
import os
import re
from pathlib import Path
import platform
import subprocess
from m5_integration import Fixture

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--client', default='smbtorture')
    p.add_argument('--sanitizers', action='store_true', help='Allow 1 GiB for ASan shadow/quarantine overhead; release keeps 512 MiB')
    p.add_argument('--owner-restore', action='store_true', help='Explicitly authorize arbitrary owner restoration for the test account and space')
    p.add_argument('--timeout', type=int, default=300,
                   help='Per-selector runtime; credit stress performs 8191 durable writes')
    p.add_argument('selectors', nargs='*', help='Defaults to the versioned bounded-profile regression selection')
    args = p.parse_args()
    applicability = []
    if not args.selectors:
        profile = json.loads(Path(__file__).with_name('samba-profile.json').read_text())
        args.selectors = profile['selectors']
        applicability = profile.get('standard_differences', [])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(host=platform.platform(), recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), tests=[])
    report['standard_differences_not_counted_as_passes'] = applicability
    f = Fixture(args.bin, 1024 if args.sanitizers else 512)
    report["memory_limit_mib"] = 1024 if args.sanitizers else 512
    def services():
        result = f.ctl('status')
        if os.name != 'nt':
            for entry in result.values():
                identity = entry.get('identity') or {}
                try:
                    entry['open_descriptors'] = len(list(Path('/proc', str(identity['pid']), 'fd').iterdir()))
                except (OSError, KeyError): pass
        return result
    try:
        if args.owner_restore:
            f.api('smb-owner-authority', f.admin, dict(id='samba-owner', username='alice', space='smbdata', mode='restore'))
            report['owner_authority'] = 'explicit restore grant for alice in smbdata'
        if any('acls' in selector for selector in args.selectors):
            f.api('shares', f.admin, dict(id='hideunread', space='smbdata', exposures={'smb':'rw'}, access_based_enumeration=True))
        credentials = f.base / 'samba-credentials'
        credentials.write_text('username=alice\npassword='+f.password+'\ndomain=TAUCLOUD\n')
        credentials.chmod(0o600)
        config = f.base / 'smb.conf'
        config.write_text('[global]\nclient min protocol = SMB2_10\nclient max protocol = SMB3_11\nclient signing = required\n')
        for selector in args.selectors:
            log = args.output.parent / (args.output.stem + '-' + selector + '.log')
            cmd = [args.client, '//127.0.0.1/smb', '-p', str(f.smbport), '-A', str(credentials),
                   '-s', str(config), '--use-kerberos=off', '--maximum-runtime='+str(args.timeout), selector]
            before = services()
            try:
                with log.open('w') as out:
                    result = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT, timeout=args.timeout+10)
                raw = log.read_text(errors='replace')
                counts = {kind:len(re.findall('^'+kind+':', raw, re.MULTILINE))
                          for kind in ('success','failure','error','skip')}
                state = 'failed' if result.returncode or counts['failure'] or counts['error'] else (
                    'partial' if counts['success'] and counts['skip'] else
                    'passed' if counts['success'] else 'skipped' if counts['skip'] else 'unverified')
                item = dict(selector=selector, returncode=result.returncode,
                            status=state, counts=counts, log=log.name)
            except subprocess.TimeoutExpired:
                item = dict(selector=selector, status='failed', error='client timeout', log=log.name)
            item['services_before'] = before
            try: item['services_after'] = services()
            except Exception as error: item['status_error'] = type(error).__name__
            report['tests'].append(item)
            print(selector + ': ' + item['status'], flush=True)
    finally:
        f.log.flush()
        report['server_log']=(f.base/'supervisor.log').read_text()[-65536:]
        f.close()
        report['status'] = 'passed' if report['tests'] and all(t['status']=='passed' for t in report['tests']) else 'failed'
        args.output.write_text(json.dumps(report, indent=2)+'\n')
    return int(report['status'] != 'passed')

if __name__ == '__main__':
    raise SystemExit(main())
