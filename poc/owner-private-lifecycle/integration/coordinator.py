#!/usr/bin/env python3
"""Public-only body assembly in a networkless least-privilege namespace."""
from pathlib import Path
import sys

from construction.codec import canonical_json, parse_json
from public import attach_spend_proofs, body_core, fields, hx, load_wire, need


def main():
    need(not Path('/home/luke').exists() and not Path('/var/run/docker.sock').exists()
         and not Path('/private').exists() and not Path('/mpc').exists(),
         'public-assembler-private-surfaces-absent')
    packet = parse_json(sys.stdin.buffer.read())
    need(type(packet) is dict and packet.get('schema') == 'kpx8-public-assembly-ipc/v1',
         'public-assembly-ipc-schema')
    operation = packet.get('operation')
    if operation == 'build':
        fields(packet, ('schema', 'operation', 'history', 'inputs', 'rows_hex', 'delta_hex32',
                        'session_sha256', 'roster', 'fee_sompi'), 'exact-public-build-IPC')
        need(type(packet['inputs']) is list and len(packet['inputs']) == 3, 'three-public-input-skeletons')
        for row in packet['inputs']:
            fields(row, ('nf_hex32', 'cv_hex64'), 'no-public-input-CM-or-position')
        inputs = [(hx(row['nf_hex32'], 32), hx(row['cv_hex64'], 64)) for row in packet['inputs']]
        body = body_core(packet['history'], inputs, [hx(row, 520) for row in packet['rows_hex']],
            hx(packet['delta_hex32'], 32), packet['session_sha256'], packet['roster'], packet['fee_sompi'])
        parsed = load_wire().parse_body(body)
        outputs = {'BODY.bin': body, 'OLD-STATE.bin': parsed.old_state.raw, 'NEW-STATE.bin': parsed.new_state.raw}
    else:
        need(operation == 'finalize', 'closed-public-assembler-operation')
        fields(packet, ('schema', 'operation', 'projection_hex10973', 'spend_proofs_hex128'),
               'exact-public-finalize-IPC')
        projection = attach_spend_proofs(hx(packet['projection_hex10973'], 10973),
            [hx(row, 128) for row in packet['spend_proofs_hex128']])
        outputs = {'BODY.bin': projection[193:], 'PROJECTION.bin': projection}
    for name, raw in outputs.items():
        with (Path('/out') / name).open('xb') as stream:
            stream.write(raw)
    with (Path('/out') / 'OBSERVER.json').open('xb') as stream:
        stream.write(canonical_json({'schema': 'kpx8-public-assembler-boundary/v1', 'operation': operation,
            'public_stdin_only': True, 'private_owner_directories_visible': False,
            'docker_socket_visible': False, 'private_invocation_handles_received': False,
            'financial_proofs_verified': False, 'accepted_chain_authority': False}))


if __name__ == '__main__':
    main()
