#!/usr/bin/env python3
"""Public-only GN2 proposal/combine; no owner key or broadcast API."""
import argparse
import os
from pathlib import Path

from gn2_common import encoded, need, outside, parse, public_bytes, regular
from gn2_entry import combine, prepare_genesis
from gn2_runtime import GENERIC, Runtime
from gn2_selection import load_profile


def main(args):
    outside(args.output)
    public_inputs = [args.profile, args.sources, *args.owners] if args.operation == 'prepare' else [
        args.profile, args.case, *args.approvals]
    for path in public_inputs:
        regular(path)
    profile = load_profile(args.profile, args.profile_sha256)
    runtime = Runtime(paths={r: Path(args.assets) / r for r in GENERIC} if args.assets else None)
    for role in GENERIC:
        need(profile.executables[role]['sha256'] == GENERIC[role][1], 'selected-generic-runtime-identity')
    if args.operation == 'prepare':
        owners = [parse(public_bytes(p)) for p in args.owners]
        sources = parse(public_bytes(args.sources))
        case, result = prepare_genesis(profile, args.trial_id, owners, sources,
            runtime, args.output, args.fee_rate)
        return {'case_path': str(args.output / 'proposed-case.json'),
                'fee_sompi': result['metrics']['actual_fee_sompi'], 'broadcast_performed': False}
    case = parse(public_bytes(args.case))
    approvals = [parse(public_bytes(p)) for p in args.approvals]
    case, result = combine(profile, args.trial_id, case, approvals, runtime, args.output, args.fee_rate)
    return {'case_path': str(args.output / 'selected-case.json'),
            'founding_outpoint': result['founding_outpoint'], 'broadcast_performed': False}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    for name in ('prepare', 'combine'):
        command = sub.add_parser(name)
        command.add_argument('--profile', type=Path, required=True)
        command.add_argument('--profile-sha256', required=True)
        command.add_argument('--trial-id', required=True)
        command.add_argument('--output', type=Path, required=True)
        command.add_argument('--assets', type=Path)
        command.add_argument('--fee-rate', type=int, default=100)
        if name == 'prepare':
            command.add_argument('--owners', type=Path, nargs=2, required=True)
            command.add_argument('--sources', type=Path, required=True)
        else:
            command.add_argument('--case', type=Path, required=True)
            command.add_argument('--approvals', type=Path, nargs=2, required=True)
    arguments = parser.parse_args()
    try:
        print(encoded(main(arguments)).decode())
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, 'public GN2 entry operation refused\n')
