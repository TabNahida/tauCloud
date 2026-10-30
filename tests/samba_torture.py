#!/usr/bin/env python3
"""Run unmodified Samba torture tests on a disposable authenticated share."""
import argparse
import datetime
import json
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
    p.add_argument('--timeout', type=int, default=300,
                   help='Per-selector runtime; credit stress performs 8191 durable writes')
    p.add_argument('selectors', nargs='+')
    args = p.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(host=platform.platform(), recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), tests=[])
    f = Fixture(args.bin)
    try:
        credentials = f.base / 'samba-credentials'
        credentials.write_text('username=alice\npassword='+f.password+'\ndomain=TAUCLOUD\n')
        credentials.chmod(0o600)
        config = f.base / 'smb.conf'
        config.write_text('[global]\nclient min protocol = SMB2_10\nclient max protocol = SMB3_11\nclient signing = required\n')
        for selector in args.selectors:
            log = args.output.parent / (args.output.stem + '-' + selector + '.log')
            cmd = [args.client, '//127.0.0.1/smb', '-p', str(f.smbport), '-A', str(credentials),
                   '-s', str(config), '--use-kerberos=off', '--maximum-runtime='+str(args.timeout), selector]
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
