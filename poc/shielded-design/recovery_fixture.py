#!/usr/bin/env python3
"""Produce public synthetic model effects and private backups; never RPC or ZK."""
import argparse
import copy
import json
from pathlib import Path

from model import Pool, ProofOracle, Wallet, hash_id
from recovery import model_checkpoint
from recovery_format import DESCRIPTOR, SCOPE, make_backup, write_private_json


def build_fixture():
    """Execute the existing model; retain effects, not its oracle or Pool state."""
    wallets = {name: Wallet('offline-recovery-fixture-' + name) for name in ('Alice', 'Bob', 'Carol')}
    alice, bob, carol = (wallets[name] for name in ('Alice', 'Bob', 'Carol'))
    oracle = ProofOracle()
    pool = Pool(oracle)
    records = []

    def record(kind, **data):
        records.append({'seq': len(records), 'kind': kind, **copy.deepcopy(data)})

    def deposit(wallet, value, label):
        note = wallet.note(value, label)
        event = pool.funded_deposit(hash_id(['MODEL-DEPOSIT', label]), note, wallet)
        record('deposit', event={key: event[key] for key in ('id', 'amount', 'commitment', 'refund_owner')})
        return note, event

    def operation(proof, expected=True):
        outcome = pool.process(proof)
        if outcome['accepted'] != expected:
            raise RuntimeError('synthetic fixture has unexpected model outcome')
        if outcome['accepted']:
            record('operation', public=proof.public)
        else:
            record('rejection', operation_hash=hash_id(proof.public))
        return outcome

    a, ae = deposit(alice, 1_000_000_000, 'alice-deposit')
    b, be = deposit(bob, 700_000_000, 'bob-deposit')
    c, ce = deposit(carol, 300_000_000, 'carol-pending')
    operation(oracle.credit(ae, a, alice.address))
    operation(oracle.credit(be, b, bob.address))
    bad = oracle.credit(ce, c, carol.address)
    bad.token = 'MODEL-INVALID-PROOF'
    operation(bad, expected=False)
    change, received = alice.note(600_000_000, 'alice-change'), bob.note(400_000_000, 'bob-receipt')
    operation(oracle.spend(alice, [a], [(change, alice.address), (received, bob.address)],
                           list(pool.commitments)))
    pool.fund_rent(50_000_000)
    record('rent_funding', amount=50_000_000)
    bob_change = bob.note(499_999_000, 'bob-change')
    operation(oracle.spend(bob, [b], [(bob_change, bob.address)], list(pool.commitments),
                           withdrawal={'recipient': 'model-native:' + bob.owner, 'amount': 200_000_000},
                           fee=1_000))
    archive = {'schema': 'kpi-model-records/v1', 'scope': SCOPE,
               'descriptor': copy.deepcopy(DESCRIPTOR), 'records': records}
    expected = {'Alice': [a.commitment, change.commitment],
                'Bob': [b.commitment, received.commitment, bob_change.commitment], 'Carol': []}
    backups = {name: make_backup(wallet, expected[name]) for name, wallet in wallets.items()}
    backups['Carol'] = make_backup(carol, pending_notes=[{'deposit': ce['id'], 'note': copy.deepcopy(c.__dict__)}])
    return {'archive': archive, 'checkpoint': model_checkpoint(archive), 'backups': backups}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='new directory; refuses overwrite')
    args = parser.parse_args()
    args.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    fixture = build_fixture()
    for name in ('archive', 'checkpoint'):
        write_private_json(args.directory / (name + '.json'), fixture[name])
    for name, backup in fixture['backups'].items():
        write_private_json(args.directory / (name.lower() + '-backup.json'), backup)
    print(json.dumps({'scope': SCOPE, 'status': 'synthetic_fixture_written',
                      'records': len(fixture['archive']['records']), 'users': 3}))


if __name__ == '__main__':
    main()
