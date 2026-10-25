#!/usr/bin/env python3
"""Matched21-KAS public-seed campaign control; no network or outer prover."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import random
import sys
import time

BASE = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(BASE / 'wallet'))
sys.path.insert(0, str(BASE / 'recovery'))
import history
import payment
from native_fees import NativeFees
from public_fixture import add, point, replay
from support import Assets, DOMAIN, digest, encoded, need, parse, read, write_new

SEEDS = [hashlib.sha256(b'KPXA MATCHED21 KNOWN PUBLIC SEED ' + bytes([i])).digest() for i in range(3)]


def run(a):
    started = time.monotonic()
    assets = Assets(read(a.assets, a.assets_sha256), a.assets_sha256, prove_roles=('output', 'spend', 'exit'))
    fees = NativeFees(assets, read(a.native_fee_policy, a.native_fee_policy_sha256), a.native_fee_policy_sha256)
    a.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    rng = random.SystemRandom()
    rows = [payment.output(assets, assets.receiver(seed).invoice(0), 2_000_000_000, blind=bytes(32)).row
            for seed in SEEDS]
    state = assets.trees.PublicState([row[:32] for row in rows])
    genesis = {'state_hex112': state.state().hex(), 'reserve_sompi': 6_000_000_000,
        'outpoint_hex36': point('matched21-genesis').hex(), 'outputs_hex520': [row.hex() for row in rows],
        'deposit_sompi': 2_000_000_000}
    genesis_sha = digest(encoded(genesis))
    value = {'schema': 'kpxa-local-private-history/v1', 'domain_hex32': DOMAIN.hex(), 'genesis': genesis,
        'transitions': [], 'head': {k: genesis[k] for k in ('state_hex112', 'reserve_sompi', 'outpoint_hex36')}}
    payment_count = exit_count = 0
    kinds = []
    for round_number, value_sompi in enumerate((500_000_000, 200_000_000)):
        order = list(range(3))
        rng.shuffle(order)
        for sender in order:
            accepted = replay(value, assets, genesis_sha)
            # Fresh Receiver reconstructs all authority from the original seed.
            receiver = assets.receiver(SEEDS[sender])
            peer = assets.receiver(SEEDS[(sender + 1) % 3])
            invoice = peer.invoice(payment.fresh_index(peer)).encode()
            kind = 'any' if round_number == 0 else ('change' if sender == 1 else 'received-preferred')
            selected = history.select(accepted, receiver, assets, kind=kind,
                minimum=value_sompi + fees.payment_fee(accepted) + assets.wire.NOTE_FLOOR)
            kinds.append(selected.kind)
            draft = payment.prepare(assets, accepted, receiver, invoice_raw=invoice, invoice_sha256=digest(invoice),
                payment_sompi=value_sompi, fee_sompi=fees.payment_fee(accepted), selection_kind=kind)
            raw = payment.authorize(assets, accepted, receiver, draft,
                                    before_proof=lambda raw: fees.require(raw, 'payment'))
            payment_count += 1
            label = 'action-' + str(payment_count).zfill(4)
            write_new(a.output / (label + '.bin'), raw)
            value = add(value, raw, label, assets)
            replay(value, assets, genesis_sha)
            print(encoded({'action': label, 'component_verified': True,
                           'elapsed_seconds': round(time.monotonic() - started, 3)}).decode(), flush=True)
    # Each owner has exactly three unspent claims, independently reconstructible
    # from seed/history. Shuffle all nine exits; there is no owner-first order.
    exit_owners = [owner for owner in range(3) for _ in range(3)]
    rng.shuffle(exit_owners)
    for owner in exit_owners:
        accepted = replay(value, assets, genesis_sha)
        receiver = assets.receiver(SEEDS[owner])
        owned = history.claims(accepted, receiver, assets)
        claim = history.select(accepted, receiver, assets)
        fee = fees.exit_fee(accepted, claim, payment.payout_spk(accepted, receiver, owned, claim))
        raw, proof = payment.independent_exit(assets, accepted, receiver, fee_sompi=fee,
            before_proof=lambda raw: fees.require(raw, 'exit'))
        exit_count += 1
        label = 'action-' + str(6 + exit_count).zfill(4)
        write_new(a.output / (label + '.bin'), raw)
        write_new(a.output / (label + '-PROOF.bin'), proof)
        value = add(value, raw, label, assets, proof=proof)
        replay(value, assets, genesis_sha)
        print(encoded({'action': label, 'component_verified': True,
                       'elapsed_seconds': round(time.monotonic() - started, 3)}).decode(), flush=True)
    accepted = replay(value, assets, genesis_sha)
    for seed in SEEDS:
        receiver = assets.receiver(seed)
        need(all(claim.spent for claim in history.claims(accepted, receiver, assets)), 'matched21-all-spent')
        payment.reconcile_payouts(accepted, receiver, assets)
    all_fees, payouts = 0, 0
    for transition in value['transitions']:
        raw = bytes.fromhex(transition['projection_hex'])
        body = (assets.wire.parse_projection(raw).body if transition['kind'] == 'payment'
                else assets.wire.parse_exit_projection(raw).body)
        all_fees += body.fee
        payouts += body.payout
    need(payment_count == 6 and exit_count == 9 and accepted.reserve == 0
         and all_fees + payouts == 6_000_000_000, 'matched21-complete-integer-accounting')
    need(kinds[:3] == ['initial'] * 3 and kinds[3:].count('received') == 2
         and kinds[3:].count('change') == 1, 'matched21-original-seed-selection-controls')
    write_new(a.output / 'HISTORY.json', encoded(value) + b'\n')
    write_new(a.output / 'CONTEXT.json', encoded({'schema': 'kpxa-selected-history-context/v1',
        'domain_hex32': DOMAIN.hex(), 'genesis_sha256': genesis_sha, 'checkpoint': value['head']}) + b'\n')
    result = {'schema': 'kpxa-matched21-public-campaign-control/v1',
        'classification': 'KNOWN_PUBLIC_SEEDS_SUPPLIED_CONTEXT_ONLY', 'payments': payment_count,
        'independent_exits': exit_count, 'useful_payment_sompi': 2_100_000_000,
        'genesis_reserve_sompi': 6_000_000_000, 'fees_sompi': all_fees, 'payouts_sompi': payouts,
        'terminal_reserve_sompi': 0, 'fresh_seed_recovery_before_round_two': True,
        'round_two_received_and_change_selection_controls': True, 'randomized_round_and_exit_order': True,
        'public_owner_schedule_or_schedule_hash_exported': False, 'actual_private_seed_claim': False,
        'outer_or_native_Full_or_testnet_confirmation': False, 'prior_frozen_two_percent_verdict_unchanged': True,
        'elapsed_seconds': round(time.monotonic() - started, 3)}
    write_new(a.output / 'RESULTS.json', encoded(result) + b'\n')
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('assets', 'native-fee-policy', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('assets-sha256', 'native-fee-policy-sha256'):
        p.add_argument('--' + name, required=True)
    print(encoded(run(p.parse_args())).decode())
