#!/usr/bin/env python3
"""Run the unchanged fixed offline native/financial preflight in a public pool."""
import argparse
from pathlib import Path
import pool_bridge
from pool_bridge import encoded
import cache_common


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=('consolidate', 'genesis', 'lifecycle'), required=True)
    for name in ('selection', 'case', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('selection-sha256', 'case-sha256', 'trial-id', 'stage'):
        p.add_argument('--' + name, required=True)
    for name in ('assets', 'parameters', 'descriptor', 'fetch'):
        p.add_argument('--' + name, type=Path)
        p.add_argument('--' + name + '-sha256')
    p.add_argument('--codec', type=Path)
    p.add_argument('--codec-sha256')
    p.add_argument('--bundle-directory', type=Path)
    # These legacy flags remain accepted by the host CLI but are never passed
    # into the capsule: unchanged preflight always uses its fixed public guard.
    for name in ('exclude-old-trial', 'exclude-private-directory'):
        p.add_argument('--' + name, action='append', default=[])
    for name in ('crypto', 'node', 'native-validator', 'sdk-directory',
                 'sessions', 'sessions-sha256', 'source-pins', 'source-pins-sha256'):
        p.add_argument('--' + name)
    cache_common.flags(p)
    pool_bridge.flags(p)
    return p


def run(a):
    request = a.output.parent.parent / (a.output.parent.name + '.POOL-REQUEST.json')
    return pool_bridge.invoke(a, 'preflight', request)


if __name__ == '__main__':
    p = parser()
    try:
        print(encoded(run(p.parse_args())).decode())
    except (ValueError, OSError, KeyError, TypeError):
        p.exit(1, 'exact offline pool preflight incomplete\n')
