#!/usr/bin/env python3
"""Declared untrusted observer: public stdin only, no execution request API."""
from pathlib import Path
import sys

from codec import canonical_json, hex32, need, parse_json, scalar, session, unpack_row, pack_row


def main():
    packet = parse_json(sys.stdin.buffer.read())
    need(set(packet) == {'schema', 'session', 'session_sha256', 'prepared_sha256',
                         'party_projections', 'party_completion_observed_seconds'} and
         packet['schema'] == 'kpx7-coordinator-public-ipc/v1', 'public-ipc-schema')
    _, sid = session(canonical_json(packet['session']), packet['session']['program_source_sha256'])
    need(sid == hex32(packet['session_sha256']), 'public-ipc-session')
    hex32(packet['prepared_sha256'])
    projections = packet['party_projections']
    need(type(projections) is list and len(projections) == 3 and
         projections[0] == projections[1] == projections[2], 'three-identical-public-projections')
    value = projections[0]
    need(set(value) == {'schema', 'session_sha256', 'rows_hex', 'delta_decimal', 'tuple_bytes',
                        'row_count', 'scope'} and value['schema'] == 'kpx7-mixed-complete-outputs/v1'
         and value['session_sha256'] == sid and value['tuple_bytes'] == 520 and
         value['row_count'] == 6 and len(value['rows_hex']) == 6 and
         value['scope'] == 'CHECKED_MPC_OUTPUTS_NOT_FINANCIAL_AUTHORIZATION', 'complete-public-shape')
    for row in value['rows_hex']:
        need(type(row) is str and len(row) == 1040 and row == row.lower(), 'canonical-complete-row-hex')
        need(unpack_row(pack_row(bytes.fromhex(row))).hex() == row, 'public-complete-row-roundtrip')
    delta = value['delta_decimal']
    need(type(delta) is str and (delta == '0' or (delta.isdecimal() and delta[0] != '0')),
         'canonical-public-aggregate')
    scalar(int(delta))
    # This local check reports actual visible namespace surfaces, not source
    # intent. No host path or daemon service is available to this process.
    need(not Path('/var/run/docker.sock').exists() and not Path('/home/luke').exists() and
         not Path('/input').exists() and not Path('/work/Player-Data').exists(),
         'coordinator-has-no-private-or-docker-surface')
    interfaces = [line.split(':')[0].strip()
                  for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    need(interfaces == ['lo'], 'coordinator-network-isolated')
    root = Path('/out')
    with (root / 'MIXED.json').open('xb') as output:
        output.write(canonical_json(value))
    with (root / 'OBSERVER.json').open('xb') as output:
        output.write(canonical_json({'schema': 'kpx7-coordinator-observer-boundary/v1',
            'public_ipc_only': True, 'docker_socket_visible': False,
            'owner_paths_visible': False, 'host_home_visible': False,
            'visible_network_interfaces': interfaces, 'execution_request_api': False,
            'private_input_or_opening_received': False, 'party_projection_count': 3,
            'complete_mixed_row_count': 6, 'scope': 'LOCAL_PROCESS_ISOLATION_NOT_HOST_ADMIN_SECURITY'}))


if __name__ == '__main__':
    main()
