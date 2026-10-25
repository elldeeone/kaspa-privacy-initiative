#!/usr/bin/env python3
"""Genuine-component lifecycle using KNOWN PUBLIC seeds and supplied heads.

No actual private seed, network, node acceptance, outer proof, native Full or
testnet confirmation claim is made. Each stage persists complete public history
so failures are retained and independent native tests can inspect the frames.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
import time

BASE = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(BASE / 'wallet'))
sys.path.insert(0, str(BASE / 'recovery'))
import history
import payment
from native_fees import NativeFees
from support import Assets, DOMAIN, digest, encoded, need, read, write_new

PUBLIC_SEEDS = {
    'A': hashlib.sha256(b'KPXA KNOWN PUBLIC FIXTURE SEED A NOT PRIVATE').digest(),
    'B': hashlib.sha256(b'KPXA KNOWN PUBLIC FIXTURE SEED B NOT PRIVATE').digest(),
}
DEPOSIT = 2_000_000_000


def point(label):
    return hashlib.sha256(b'KPXA SUPPLIED CONTEXT POINT ' + label.encode()).digest() + bytes(4)


def replay(value, assets, genesis_sha256):
    return history.load(encoded(value), value['head'], genesis_sha256, assets)


def add(value, raw, label, assets, *, proof=None):
    value = history.parse(encoded(value))
    body = (assets.wire.parse_projection(raw).body if proof is None
            else assets.wire.parse_exit_projection(raw).body)
    successor = point(label) if body.new_reserve else None
    transition = {'kind': 'payment' if proof is None else 'exit', 'projection_hex': raw.hex(),
                  'successor_outpoint_hex36': None if successor is None else successor.hex()}
    if proof is not None:
        transition['proof_hex128'] = proof.hex()
    value['transitions'].append(transition)
    value['head'] = {'state_hex112': body.new_state.raw.hex(), 'reserve_sompi': body.new_reserve,
                     'outpoint_hex36': None if successor is None else successor.hex()}
    return value


def refused(function, label, controls):
    try:
        function()
    except (ValueError, TypeError):
        controls.append(label)
        return
    raise AssertionError('negative-control-accepted:' + label)


def run(a):
    assets = Assets(read(a.assets, a.assets_sha256), a.assets_sha256,
                    prove_roles=('output', 'spend', 'exit'))
    fees = NativeFees(assets, read(a.native_fee_policy, a.native_fee_policy_sha256), a.native_fee_policy_sha256)
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    rows, stages, controls = [], [], []
    started = time.monotonic()

    def save(label, value):
        write_new(a.output / (label + '-HISTORY.json'), encoded(value) + b'\n')
        write_new(a.output / (label + '-CONTEXT.json'), encoded({
            'schema': 'kpxa-selected-history-context/v1', 'domain_hex32': DOMAIN.hex(),
            'genesis_sha256': genesis_sha, 'checkpoint': value['head']}) + b'\n')
        stages.append(label)
        print(encoded({'stage': label, 'supplied_context_only': True,
                       'elapsed_seconds': round(time.monotonic() - started, 3)}).decode(), flush=True)

    for label, seed in PUBLIC_SEEDS.items():
        receiver = assets.receiver(seed)
        created = payment.output(assets, receiver.invoice(0), DEPOSIT, blind=bytes(32))
        need(receiver.open(created.row[96:360]).encode() == created.receipt.encode(), 'fixture-initial-recovery')
        rows.append(created.row)
        print(encoded({'stage': 'initial-output-' + label, 'genuine_output_verified': True}).decode(), flush=True)
    state = assets.trees.PublicState([row[:32] for row in rows])
    genesis = {'state_hex112': state.state().hex(), 'reserve_sompi': DEPOSIT * len(rows),
               'outpoint_hex36': point('genesis').hex(), 'outputs_hex520': [r.hex() for r in rows],
               'deposit_sompi': DEPOSIT}
    genesis_sha = digest(encoded(genesis))
    value = {'schema': 'kpxa-local-private-history/v1', 'domain_hex32': DOMAIN.hex(),
             'genesis': genesis, 'transitions': [],
             'head': {key: genesis[key] for key in ('state_hex112', 'reserve_sompi', 'outpoint_hex36')}}
    accepted = replay(value, assets, genesis_sha)
    save('00-GENESIS', value)
    wrong = assets.receiver(hashlib.sha256(b'KPXA KNOWN WRONG PUBLIC SEED').digest())
    refused(lambda: history.claims(accepted, wrong, assets), 'wrong-seed-cannot-successfully-empty-scan', controls)

    receiver_a, receiver_b = (assets.receiver(PUBLIC_SEEDS[label]) for label in ('A', 'B'))
    invoice = receiver_b.invoice(0xfffffffffffffff0).encode()
    first_fee = fees.payment_fee(accepted)
    for bad in (True, 1.5, -1, 0, (1 << 64)):
        refused(lambda bad=bad: payment.prepare(assets, accepted, receiver_a, invoice_raw=invoice,
            invoice_sha256=digest(invoice), payment_sompi=bad, fee_sompi=first_fee),
            'strict-payment-amount-' + str(bad), controls)
    for bad in (True, 1.5, -1, 0, (1 << 64)):
        refused(lambda bad=bad: payment.prepare(assets, accepted, receiver_a, invoice_raw=invoice,
            invoice_sha256=digest(invoice), payment_sompi=500_000_000, fee_sompi=bad),
            'strict-fee-amount-' + str(bad), controls)

    first_draft = payment.prepare(assets, accepted, receiver_a, invoice_raw=invoice,
        invoice_sha256=digest(invoice), payment_sompi=500_000_000, fee_sompi=first_fee, position=0)
    first_raw = payment.authorize(assets, accepted, receiver_a, first_draft,
                                  before_proof=lambda raw: fees.require(raw, 'payment'))
    write_new(a.output / '01-PAYMENT.bin', first_raw)
    case, journal, native_quote = fees.require(first_raw, 'payment')
    write_new(a.output / '01-PAYMENT-CASE.json', encoded(case) + b'\n')
    write_new(a.output / '01-PAYMENT-JOURNAL.bin', journal)
    write_new(a.output / '01-PAYMENT-NATIVE-QUOTE.json', encoded(native_quote) + b'\n')
    print(encoded({'stage': 'FIRST_FEE_CORRECT_PAYMENT_READY',
        'projection_sha256': digest(first_raw), 'case_sha256': digest(encoded(case) + b'\n'),
        'journal_sha256': digest(journal), 'fee_sompi': first_fee}).decode(), flush=True)
    rows_first = [o.tuple_bytes for o in assets.wire.parse_projection(first_raw).body.outputs]
    received_position = 2 + rows_first.index(first_draft.payment.row)
    change_position = 2 + rows_first.index(first_draft.change.row)
    # Intent mutation fails before a new Spend proof is requested.
    changed_fee = bytearray(first_draft.projection)
    changed_fee[193 + 388:193 + 396] = (first_fee + 1).to_bytes(8, 'little')
    refused(lambda: payment.consent(assets, accepted, receiver_a, first_draft, bytes(changed_fee)),
            'substituted-fee', controls)
    changed_output = bytearray(first_draft.projection)
    changed_output[193 + 532 + 96] ^= 1
    refused(lambda: payment.consent(assets, accepted, receiver_a, first_draft, bytes(changed_output)),
            'substituted-payment-or-change-CF', controls)

    # A distinct, genuine competing wallet transition uses exactly the same
    # accepted reserve head. Both are valid separately; their serial append is
    # rejected because only one may consume that outpoint.
    competing_invoice = receiver_a.invoice(0xffffffffffffffe0).encode()
    competing_draft = payment.prepare(assets, accepted, receiver_b, invoice_raw=competing_invoice,
        invoice_sha256=digest(competing_invoice), payment_sompi=300_000_000,
        fee_sompi=fees.payment_fee(accepted), position=1)
    competing = payment.authorize(assets, accepted, receiver_b, competing_draft,
                                  before_proof=lambda raw: fees.require(raw, 'payment'))
    write_new(a.output / 'CONFLICT-PAYMENT.bin', competing)
    alternative = add(value, competing, 'alternative', assets)
    alternative_accepted = replay(alternative, assets, genesis_sha)
    value = add(value, first_raw, 'payment-1', assets)
    accepted = replay(value, assets, genesis_sha)
    refused(lambda: payment.consent(assets, accepted, receiver_b, competing_draft, competing),
            'otherwise-valid-competing-transition-is-stale', controls)
    refused(lambda: replay(add(value, competing, 'invalid-serial-conflict', assets), assets, genesis_sha),
            'two-successors-cannot-serially-consume-one-head', controls)
    refused(lambda: replay(add(value, first_raw, 'replay', assets), assets, genesis_sha),
            'exact-payment-replay', controls)
    need(any(c.position == 1 and not c.spent for c in history.claims(accepted, receiver_b, assets)),
         'losing-owner-note-remains-unspent')
    reorg_claims = history.claims(alternative_accepted, assets.receiver(PUBLIC_SEEDS['A']), assets)
    need(any(c.position == 0 and not c.spent for c in reorg_claims), 'reorg-restores-unspent-original')
    need(not any(c.receipt.commitment() == first_draft.change.row[:32] for c in reorg_claims),
         'dropped-successor-change-not-credited')
    save('01-FIRST-PAYMENT', value)
    write_new(a.output / 'REORG-ALTERNATIVE-HISTORY.json', encoded(alternative) + b'\n')

    plans = [('B', 'A', received_position, 200_000_000, '02-RECEIVED-SPEND'),
             ('A', 'B', change_position, 400_000_000, '03-CHANGE-SPEND')]
    for sender, destination, position, value_sompi, label in plans:
        accepted = replay(value, assets, genesis_sha)
        # Reconstruct a new receiver solely from the original public seed;
        # no first_draft/receipt/blind/session/roster is used for note selection.
        receiver = assets.receiver(PUBLIC_SEEDS[sender])
        peer = assets.receiver(PUBLIC_SEEDS[destination])
        invoice = peer.invoice(0xffffffffffff0000 + len(value['transitions'])).encode()
        draft = payment.prepare(assets, accepted, receiver, invoice_raw=invoice,
            invoice_sha256=digest(invoice), payment_sompi=value_sompi,
            fee_sompi=fees.payment_fee(accepted), position=position)
        raw = payment.authorize(assets, accepted, receiver, draft,
                                before_proof=lambda raw: fees.require(raw, 'payment'))
        write_new(a.output / (label + '.bin'), raw)
        value = add(value, raw, label, assets)
        replay(value, assets, genesis_sha)
        save(label, value)

    index = 0
    while value['head']['reserve_sompi']:
        accepted = replay(value, assets, genesis_sha)
        matched = False
        for owner, seed in PUBLIC_SEEDS.items():
            receiver = assets.receiver(seed)
            claims = history.claims(accepted, receiver, assets)
            available = [c for c in claims if not c.spent]
            if not available:
                continue
            claim = available[0]
            quoted_fee = fees.exit_fee(accepted, claim, payment.payout_spk(accepted, receiver, claims, claim))
            raw, proof = payment.independent_exit(assets, accepted, receiver, fee_sompi=quoted_fee,
                position=claim.position, before_proof=lambda raw: fees.require(raw, 'exit'))
            index += 1
            label = 'EXIT-' + str(index).zfill(2)
            write_new(a.output / (label + '.bin'), raw)
            write_new(a.output / (label + '-PROOF.bin'), proof)
            case, journal, native_quote = fees.require(raw, 'exit')
            write_new(a.output / (label + '-CASE.json'), encoded(case) + b'\n')
            write_new(a.output / (label + '-JOURNAL.bin'), journal)
            write_new(a.output / (label + '-NATIVE-QUOTE.json'), encoded(native_quote) + b'\n')
            value = add(value, raw, label, assets, proof=proof)
            save(label, value)
            matched = True
            break
        need(matched, 'every-reserve-sompi-has-recoverable-owner')
    accepted = replay(value, assets, genesis_sha)
    for seed in PUBLIC_SEEDS.values():
        receiver = assets.receiver(seed)
        need(all(c.spent for c in history.claims(accepted, receiver, assets)), 'terminal-original-seed-scan')
        payment.reconcile_payouts(accepted, receiver, assets)
    total_fees = sum((assets.wire.parse_projection(bytes.fromhex(t['projection_hex'])).body.fee
                if t['kind'] == 'payment' else
                assets.wire.parse_exit_projection(bytes.fromhex(t['projection_hex'])).body.fee)
               for t in value['transitions'])
    payouts = sum(assets.wire.parse_exit_projection(bytes.fromhex(t['projection_hex'])).body.payout
                  for t in value['transitions'] if t['kind'] == 'exit')
    need(total_fees + payouts == DEPOSIT * 2 and accepted.reserve == 0, 'exact-terminal-integer-accounting')
    result = {'schema': 'kpxa-public-fixture-lifecycle-result/v1', 'classification': 'KNOWN_PUBLIC_SEEDS_SUPPLIED_CONTEXT_ONLY',
        'assets_sha256': a.assets_sha256, 'known_public_seed_hex32': {k: v.hex() for k, v in PUBLIC_SEEDS.items()},
        'genuine_component_proofs_verified': True, 'payments': 3, 'independent_exits': index,
        'received_note_spent_after_original_seed_recovery': True,
        'change_note_spent_after_original_seed_recovery': True,
        'wrong_seed_rejected': True, 'conflict_and_supplied_reorg_checked': True,
        'negative_controls_rejected': controls, 'deposit_sompi': DEPOSIT * 2,
        'fees_sompi': total_fees, 'payouts_sompi': payouts, 'terminal_reserve_sompi': 0,
        'actual_native_fee_quotes_before_authorization': True,
        'native_fee_rate_sompi_per_mass': fees.value['fee_rate_sompi_per_mass'],
        'native_fee_quotes': fees.quotes,
        'outer_proof_verified': False, 'native_Full_verified': False, 'testnet_confirmed': False,
        'actual_private_seed_claim': False, 'privacy_or_cost_pass': False,
        'elapsed_seconds': round(time.monotonic() - started, 3), 'stages': stages}
    write_new(a.output / 'RESULTS.json', encoded(result) + b'\n')
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--assets', type=Path, required=True)
    p.add_argument('--assets-sha256', required=True)
    p.add_argument('--native-fee-policy', type=Path, required=True)
    p.add_argument('--native-fee-policy-sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        print(encoded(run(a)).decode())
    except Exception as error:
        # Every witness/seed is explicitly public in this fixture, yet retain
        # minimal diagnostics to keep the private worker's contract separate.
        print(encoded({'fixture_failed': True, 'error_type': type(error).__name__,
                       'error': str(error), 'supplied_context_only': True}).decode(), flush=True)
        raise
