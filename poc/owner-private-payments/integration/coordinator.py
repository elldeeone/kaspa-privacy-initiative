#!/usr/bin/env python3
"""Untrusted public-only body assembler; fixed stdin protocol, no command API."""
import json
from pathlib import Path
import sys

from public import attach_spend_proofs, body_core, hx, need, project, wire


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate-public-json-key')
        result[key] = value
    return result


def main():
    need(not Path('/home/luke').exists() and not Path('/var/run/docker.sock').exists()
         and not Path('/input').exists(), 'coordinator-private-surfaces-absent')
    packet = json.loads(sys.stdin.buffer.read(), object_pairs_hook=pairs,
                        parse_constant=lambda _: need(False, 'nonfinite-public-json'))
    need(type(packet) is dict and packet.get('schema') == 'kpx7-public-assembly-ipc/v1', 'public-assembly-ipc')
    operation = packet.get('operation')
    files = {}
    if operation == 'build':
        need(set(packet) == {'schema', 'operation', 'genesis', 'inputs', 'rows_hex', 'delta_hex32',
             'session_sha256', 'roster', 'point_hex36', 'fee_sompi'}, 'exact-build-ipc')
        need(type(packet['inputs']) is list and len(packet['inputs']) == 3 and
             all(type(row) is dict and set(row) == {'nf_hex32', 'cv_hex64'} for row in packet['inputs']),
             'exact-public-input-skeletons')
        inputs = [(hx(row['nf_hex32'], 32), hx(row['cv_hex64'], 64)) for row in packet['inputs']]
        body = body_core(packet['genesis'], inputs, [hx(row, 520) for row in packet['rows_hex']],
                         hx(packet['delta_hex32'], 32), packet['session_sha256'], packet['roster'],
                         hx(packet['point_hex36'], 36), packet['fee_sompi'])
        parsed = wire.parse_body(body)
        files = {'BODY.bin': body, 'OLD-STATE.bin': parsed.old_state.raw, 'NEW-STATE.bin': parsed.new_state.raw}
    elif operation == 'project':
        need(set(packet) == {'schema', 'operation', 'body_hex10780', 'input_spk_hex37',
             'output_spk_hex37'}, 'exact-projection-ipc')
        projection = project(hx(packet['body_hex10780'], 10780), hx(packet['input_spk_hex37'], 37),
                             hx(packet['output_spk_hex37'], 37))
        files = {'PROJECTION.bin': projection, 'EFFECTS.bin': wire.effects_digest(projection)}
    elif operation == 'finalize':
        need(set(packet) == {'schema', 'operation', 'projection_hex10973', 'spend_proofs_hex128'},
             'exact-final-proof-ipc')
        projection = attach_spend_proofs(hx(packet['projection_hex10973'], 10973),
                           [hx(proof, 128) for proof in packet['spend_proofs_hex128']])
        files = {'PROJECTION.bin': projection, 'BODY.bin': projection[193:]}
    else:
        need(False, 'unsupported-public-assembly-operation')
    for name, raw in files.items():
        with (Path('/out') / name).open('xb') as stream:
            stream.write(raw)
    with (Path('/out') / 'OBSERVER.json').open('xb') as stream:
        stream.write(canonical({'schema': 'kpx7-public-assembler-boundary/v1', 'operation': operation,
             'public_stdin_only': True, 'private_owner_directories_visible': False,
             'docker_socket_visible': False, 'private_invocation_handles_received': False,
             'financial_proofs_verified': False, 'accepted_chain_authority': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.stderr.write('KPX7_PUBLIC_ASSEMBLER_INCOMPLETE\n')
        raise SystemExit(1)
