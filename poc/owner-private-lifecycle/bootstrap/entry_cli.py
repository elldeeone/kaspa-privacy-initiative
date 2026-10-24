#!/usr/bin/env python3
"""Public GN3 proposal/combine. No key, seed, submit or network operation."""
import argparse
from pathlib import Path

from gn3_common import encoded, hx, parse, public_bytes
from gn3_entry import combine, prepare_genesis
from gn3_runtime import Runtime
from gn3_selection import load


def main(args):
    selection = load(args.selection, args.selection_sha256)
    runtime = Runtime()
    case = parse(public_bytes(args.case)) if args.operation == 'combine' else None
    if args.operation == 'prepare':
        records = [hx(value, 496) for value in parse(public_bytes(args.records))]
        sources = parse(public_bytes(args.sources))
        _, result = prepare_genesis(selection, args.trial_id, records, sources,
            runtime, args.output, args.fee_rate)
    else:
        approvals = [parse(public_bytes(path)) for path in args.approvals]
        _, result = combine(selection, args.trial_id, case, approvals,
            runtime, args.output, args.fee_rate)
    return {'status': 'LOCAL_PUBLIC_GN3_COMPLETE', 'operation': args.operation,
        'output': str(args.output), 'broadcast_performed': False,
        'fee_sompi': result.get('metrics', {}).get('actual_fee_sompi')}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    for operation in ('prepare', 'combine'):
        command = sub.add_parser(operation)
        command.add_argument('--selection', type=Path, required=True)
        command.add_argument('--selection-sha256', required=True)
        command.add_argument('--trial-id', required=True)
        command.add_argument('--output', type=Path, required=True)
        command.add_argument('--fee-rate', type=int, default=100)
        if operation == 'prepare':
            command.add_argument('--records', type=Path, required=True)
            command.add_argument('--sources', type=Path, required=True)
        else:
            command.add_argument('--case', type=Path, required=True)
            command.add_argument('--approvals', type=Path, nargs=3, required=True)
    try:
        print(encoded(main(parser.parse_args())).decode())
    except (OSError, ValueError, TypeError, KeyError):
        parser.exit(1, 'GN3 public assembly refused\n')
