#!/usr/bin/env python3
"""Public-synthetic DO_NOT_FUND private-relation canaries; no native/prover API.

All nominal secrets below are deterministic public fixtures. They must never
be used for a funded instance or mixed with the private main lifecycle notes.
No witness hash is emitted. The files initially stay outside Git for review.
"""
import argparse
import json
from pathlib import Path

from primitives import (ZERO, Snapshot, amount, dummy_nf, fixed, h, insert_nf,
                        need, note_cm, real_nf, singleton, u32, u64)

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / 'research/next-session/compact-batch/PUBLIC-INSTANCE-01.json'
DOMAIN = bytes.fromhex('35ee940cae12aec848a773738de04feaef80c17798a686f1d5aa808179584fd6')
SCHEMA = 'kpx4-private-batch-action-witness/v1'
G = bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
TWO_G = bytes.fromhex('c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
TAG = b'PUBLIC_SYNTHETIC_CANARY_DO_NOT_FUND/KPX4/v1\0'


def sample(label, suffix):
    return h(TAG, DOMAIN, label.encode(), b'/', suffix.encode())


def note(label, value):
    amount(value)
    s, k = sample(label, 'owner-secret'), sample(label, 'nf-secret')
    incoming, rho = sample(label, 'incoming'), sample(label, 'rho')
    owner = h(b'KPX1OWN\0', DOMAIN, s, incoming)
    key = h(b'KPX1KEY\0', DOMAIN, k)
    return owner + incoming + u64(value) + rho + key + G, s, k


def box(label, slot):
    """Opaque public data only; these canaries make NO delivery/native claim."""
    return b''.join(sample(label, f'cipher/{slot}/{i}') for i in range(9))[:264]


def fixture(label, mode):
    need(mode in (0, 2, 32), 'canary-mode')
    values = [60_000_000, 70_000_000] if mode == 2 else [1_000_000_000] * 32 if mode == 32 else []
    fee = 1000
    incoming = sum(values) + fee if mode else 1_000_000_000
    payout = 0 if mode else incoming - fee
    source, s, k = note(label + '/input', incoming)
    before = singleton(DOMAIN, source, box(label + '/initial', 0))
    cm_tree, _ = before.roots()
    nf0 = real_nf(DOMAIN, k, note_cm(DOMAIN, source), 0)
    dk, ds = sample(label, 'dummy-key'), sample(label, 'dummy-seed')
    nf1 = dummy_nf(DOMAIN, dk, ds, 1)
    after, first = insert_nf(before, nf0)
    after, second = insert_nf(after, nf1)
    output_notes = [note(f'{label}/output/{i}', value)[0] for i, value in enumerate(values)]
    if mode:
        ciphers = [box(label, i) for i in range(mode)]
        after, start, boundary = after.append(DOMAIN, output_notes, ciphers)
        array = h(b''.join(note_cm(DOMAIN, raw) for raw in output_notes))
        metadata = bytes([mode]) + bytes(3) + u32(start) + bytes(24)
        cipher_hash = h(b''.join(ciphers))
    else:
        output_notes = [bytes(168), bytes(168)]
        start, boundary = 0, []
        array, metadata, cipher_hash = ZERO, bytes(32), h(bytes(528))
    point = sample(label, 'FAKE_DO_NOT_FUND_PREVIOUS_TRANSACTION') + u32(0)
    reserve_after = incoming - payout - fee
    destination = b'\0\0\x20' + TWO_G + b'\xac' if payout else bytes(36)
    auth = (b'KPX4AU01' + DOMAIN + point + before.state(DOMAIN) + u64(incoming) + u64(fee)
            + nf0 + nf1 + array + metadata + cipher_hash + after.state(DOMAIN)
            + u64(reserve_after) + u64(payout) + destination)
    fixed(auth, 528)
    real = {'real': True, 'note_hex168': source.hex(), 's_hex32': s.hex(), 'k_hex32': k.hex(),
            'position': 0, 'cm_path_hex': [p.hex() for p in cm_tree.path(0)],
            'dummy_key_hex32': ZERO.hex(), 'dummy_seed_hex32': ZERO.hex()}
    dummy = {'real': False, 'note_hex168': bytes(168).hex(), 's_hex32': ZERO.hex(),
             'k_hex32': ZERO.hex(), 'position': 0, 'cm_path_hex': [ZERO.hex()] * 16,
             'dummy_key_hex32': dk.hex(), 'dummy_seed_hex32': ds.hex()}
    witness = {'schema': SCHEMA, 'auth_hex528': auth.hex(), 'inputs': [real, dummy],
               'outputs': [{'note_hex168': raw.hex()} for raw in output_notes]}
    return witness, {'classification': 'PUBLIC_SYNTHETIC_CANARY_DO_NOT_FUND',
        'role': 'wide32' if mode == 32 else 'compact2', 'mode': mode,
        'nominal_secrets_are_deterministic_public_fixtures': True,
        'input_sompi': incoming, 'output_sompi': sum(values), 'fee_sompi': fee,
        'payout_sompi': payout, 'reserve_after_sompi': reserve_after,
        'physical_CM_cursor_after': after.cm_cursor, 'delivered_record_count': len(after.deliveries),
        'NF_count_after': len(after.nullifiers), 'CM_start': start,
        'CF_or_native_or_accepted_chain_or_proof_claimed': False,
        'boundary_path_hash_count': len(boundary), 'native_NF_witness_bytes': len(first + second)}


def create(output):
    output = output.absolute()
    need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-output-outside-Git')
    need(not any(p.is_symlink() for p in (output, *output.parents)), 'output-symlink')
    need(json.loads(PUBLIC.read_bytes())['domain_hex32'] == DOMAIN.hex(), 'selected-fresh-domain')
    output.mkdir(parents=True, mode=0o700)
    cases = []
    for label, mode in [('compact-continuing', 2), ('compact-terminal', 0), ('wide32', 32)]:
        witness, summary = fixture(label, mode)
        path = output / (label + '.json')
        with path.open('x') as file:
            json.dump(witness, file, separators=(',', ':'))
            file.write('\n')
        path.chmod(0o600)
        cases.append({'filename': path.name, **summary})
    result = {'schema': 'kpx4-public-synthetic-batch-canaries/v1', 'domain_hex32': DOMAIN.hex(),
              'private_witness_or_input_hash_emitted': False, 'cases': cases}
    with (output / 'CANARIES.json').open('x') as file:
        json.dump(result, file, indent=2, sort_keys=True)
        file.write('\n')
    print(json.dumps({'public_canary_count': 3, 'setup_proof_native_or_network_calls': 0,
                      'private_witness_or_input_hash_emitted': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    create(parser.parse_args().output)
