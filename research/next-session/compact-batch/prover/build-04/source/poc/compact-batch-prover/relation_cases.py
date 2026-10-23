#!/usr/bin/env python3
"""Coherent PUBLIC_SYNTHETIC_DO_NOT_FUND direct-relation controls.

Only generates deterministic fixtures. It never invokes a prover, native VM,
setup, RPC or a private input. Raw requests remain outside Git with no hashes.
A parser failure must never be counted as an expected direct-constraint UNSAT.
The final SAT control deliberately isolates a mandatory native-only obligation.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'poc/compact-batch-lifecycle'))
from synthetic import DOMAIN, TWO_G, fixture  # noqa: E402
from primitives import MAX, h, need, note_cm, u32, u64  # noqa: E402

LABEL = 'relation-controls/PUBLIC_SYNTHETIC_DO_NOT_FUND'


def replace_auth(request, offset, value):
    auth = bytearray.fromhex(request['auth_hex528'])
    auth[offset:offset+len(value)] = value
    need(len(auth) == 528, 'auth-width')
    request['auth_hex528'] = auth.hex()


def flip_auth(request, offset):
    auth = bytearray.fromhex(request['auth_hex528'])
    auth[offset] ^= 1
    request['auth_hex528'] = auth.hex()


def note_value(request, slot, value):
    raw = bytearray.fromhex(request['outputs'][slot]['note_hex168'])
    raw[64:72] = u64(value)
    request['outputs'][slot]['note_hex168'] = raw.hex()


def coherent_list(request):
    notes = [bytes.fromhex(row['note_hex168']) for row in request['outputs']]
    replace_auth(request, 268, h(*(note_cm(DOMAIN, note) for note in notes)))


def cases():
    compact = fixture(LABEL + '/compact', 2)[0]
    terminal = fixture(LABEL + '/terminal', 0)[0]
    wide = fixture(LABEL + '/wide', 32)[0]
    rows = []

    def add(name, base, role, mutate, purpose, *, expected=False, native_only=False):
        request = copy.deepcopy(base)
        mutate(request)
        rows.append((request, {'label': name, 'role': role,
            'expected_relation_satisfied': expected,
            'required_result_kind': 'DIRECT_CONSTRAINT_SAT' if expected else 'DIRECT_CONSTRAINT_UNSAT',
            'purpose': purpose, 'requires_native_checks_to_reject': native_only}))

    def late_rho(request):
        raw = bytearray.fromhex(request['outputs'][31]['note_hex168'])
        raw[72] ^= 1
        request['outputs'][31]['note_hex168'] = raw.hex()
    add('wide-late31-CM-opening', wide, 'wide32', late_rho,
        'Last output rho changes while Auth array digest stays fixed; tests last-slot CM/list binding without changing values.')

    def duplicate(request):
        request['outputs'][31] = copy.deepcopy(request['outputs'][0])
        coherent_list(request)
    add('wide-late31-duplicate-coherent-digest', wide, 'wide32', duplicate,
        'Slots0/31 become identical with equal original values and a recomputed list digest; isolates all-slot distinctness.')

    def overflow(request):
        for i in range(32):
            note_value(request, i, MAX)
        coherent_list(request)
    add('wide-u64-overflow-coherent-digest', wide, 'wide32', overflow,
        'All32 values are individually legal and CMs remain distinct; exact sum exceeds u64 and input/reserve, with coherent digest.')

    def reorder(request):
        request['outputs'][30], request['outputs'][31] = request['outputs'][31], request['outputs'][30]
    add('wide-ordered-list-swap', wide, 'wide32', reorder,
        'Distinct equal-value outputs30/31 swap while original ordered digest remains; binds physical order.')

    def terminal_rho(request):
        raw = bytearray(168)
        raw[72] = 1
        request['outputs'][1]['note_hex168'] = raw.hex()
    add('compact-terminal-rho', terminal, 'compact2', terminal_rho,
        'Nonzero private rho under unchanged terminal zero sentinels must fail, despite no output CM being appended.')
    add('compact-terminal-cipher-not-empty-hash', terminal, 'compact2',
        lambda r: replace_auth(r, 332, h(b'')),
        'Terminal binds SHA256(528 zero bytes), never SHA256(empty).')
    add('compact-reserved-byte', compact, 'compact2', lambda r: flip_auth(r, 308),
        'Directly retained reserved-byte witness must be zero, not merely normalized by host serialization.')
    add('compact-alignment', compact, 'compact2', lambda r: replace_auth(r, 304, u32(3)),
        'Old cursor1 requires aligned start2; the in-range nonmultiple3 must fail.')
    add('compact-wrong-role-mode32', compact, 'compact2', lambda r: replace_auth(r, 300, bytes([32])),
        'Compact matrix cannot be promoted to wide by the Auth mode, preserving all other compact data.')
    add('compact-wrong-prior-CM-root', compact, 'compact2', lambda r: flip_auth(r, 116),
        'Real-note membership must authenticate the exact prior root.')
    add('compact-wrong-real-NF', compact, 'compact2', lambda r: flip_auth(r, 204),
        'The actual-slot real HMAC NF is independently constrained, not accepted from Auth.')

    def inflation(request):
        original = int.from_bytes(bytes.fromhex(request['auth_hex528'])[476:484], 'little')
        replace_auth(request, 484, u64(10_000_000))
        replace_auth(request, 476, u64(original - 10_000_000))
        replace_auth(request, 492, b'\0\0\x20' + TWO_G + b'\xac')
    add('compact-private-output-plus-payout-inflation', compact, 'compact2', inflation,
        'Public reserve/fee/payout equation remains balanced and SPK is valid; private outputs unchanged make private conservation fail.')

    def reserve(request):
        replace_auth(request, 188, u64(120_000_000))
        replace_auth(request, 476, u64(119_999_000))
    add('compact-input-sum-exceeds-reserve', compact, 'compact2', reserve,
        'Private input/output/fee equation unchanged; public reserve equation balanced but owned input sum exceeds reserve.')

    add('compact-next-CM-root-is-native-obligation', compact, 'compact2', lambda r: flip_auth(r, 404),
        'Private relation deliberately does not authenticate the continuing tree append; native public path/root checks remain mandatory.',
        expected=True, native_only=True)
    return rows


def create(output):
    output = output.absolute()
    need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-output-outside-Git')
    need(not any(p.is_symlink() for p in (output, *output.parents)), 'output-symlink')
    need(json.loads((ROOT / 'research/next-session/compact-batch/PUBLIC-INSTANCE-01.json').read_bytes())['domain_hex32'] == DOMAIN.hex(),
         'selected-domain')
    output.mkdir(mode=0o700, parents=True)
    summaries = []
    for index, (request, summary) in enumerate(cases()):
        filename = f'{index:02d}-{summary["label"]}.json'
        descriptor = os.open(output / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as file:
            json.dump(request, file, separators=(',', ':'))
            file.write('\n')
        summaries.append({'filename': filename, **summary})
    report = {'schema': 'kpx4-direct-relation-control-plan/v1',
        'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND', 'domain_hex32': DOMAIN.hex(),
        'private_witness_or_input_hash_emitted': False,
        'parser_rejection_does_not_count_as_direct_UNSAT': True,
        'CS_setup_proof_native_or_RPC_execution': False,
        'cases': summaries}
    with (output / 'CASES.json').open('x') as file:
        json.dump(report, file, indent=2, sort_keys=True)
        file.write('\n')
    print(json.dumps({'generated_direct_constraint_controls': len(summaries),
        'expected_UNSAT': sum(not row['expected_relation_satisfied'] for row in summaries),
        'expected_SAT_native_only_obligation': sum(row['expected_relation_satisfied'] for row in summaries),
        'CS_setup_proof_native_or_RPC_execution': False,
        'private_witness_or_input_hash_emitted': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    create(parser.parse_args().output)
