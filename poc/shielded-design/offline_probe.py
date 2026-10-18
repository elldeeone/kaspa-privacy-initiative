#!/usr/bin/env python3
"""Python-only network audit/block for an offline CLI experiment, not a sandbox.

Observe event names only; never log audit arguments containing user data.
Child processes/native code are outside this instrumentation's guarantee.
"""
import argparse
import runpy
import sys

from recovery_format import SCOPE, write_private_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace')
    parser.add_argument('script')
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    attempts = []

    def audit(event, arguments):
        if event.startswith('socket.'):
            attempts.append(event)
            raise RuntimeError('network forbidden in offline probe')

    sys.addaudithook(audit)
    sys.argv = [args.script, *args.arguments]
    try:
        runpy.run_path(args.script, run_name='__main__')
    finally:
        write_private_json(args.trace, {'scope': SCOPE, 'network_attempts': attempts,
                                       'os_sandbox': False})


if __name__ == '__main__':
    main()
