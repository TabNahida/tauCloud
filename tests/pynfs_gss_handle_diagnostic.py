#!/usr/bin/env python3
"""Retain the two upstream fake-GSS-handle conflicts; never report them as passes."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def classify(report, returncode):
    failures = [case for case in report.get('testcase', []) if case.get('failure')]
    expected = {'CSESS16', 'CSESS16a'}
    exact = (returncode == 1 and report.get('failures') == 2 and report.get('errors') == 0
             and report.get('tests', 0) - report.get('skipped', 0) == 2
             and {case.get('code') for case in failures} == expected
             and all(case['failure'].get('message', '').strip() ==
                     'nfs4lib.NFS4Error: OP_CREATE_SESSION should return NFS4_OK, instead got NFS4ERR_NOENT'
                     for case in failures))
    return dict(status='upstream-expectation-conflict' if exact else 'unexpected-result',
                upstream_passed=0, upstream_failed=len(failures),
                specification='https://www.rfc-editor.org/rfc/rfc8881.html#section-18.36.3',
                reason='Both upstream cases offer the literal unestablished Handle from server. '
                       'RFC 8881 requires NOENT for a handle absent on the server, even in a mixed flavor array. '
                       'The original failures remain failures; this diagnostic checks their exact cause.',
                cases=failures)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sanitizers', action='store_true')
    args = p.parse_args()
    raw = args.output.with_suffix('.upstream.json')
    command = [sys.executable, str(Path(__file__).with_name('pynfs_acceptance.py')),
               '--bin', str(args.bin), '--output', str(raw)]
    if args.sanitizers: command += ['--sanitizers']
    result = subprocess.run(command + ['CSESS16', 'CSESS16a'], timeout=120)
    report = classify(json.loads(raw.read_text()), result.returncode)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return report['status'] != 'upstream-expectation-conflict'


if __name__ == '__main__':
    raise SystemExit(main())
