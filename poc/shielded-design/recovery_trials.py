#!/usr/bin/env python3
"""Fixed offline R05/R06 synthetic trials; wallet/executor roles share a harness.

No network, real proof, native payout or independent-operator claim. Each CLI
invocation reads declared files and writes a new protected stage directory.
"""
import argparse
import copy
import json
from pathlib import Path

from recovery import reconstruct_public, restore_wallet
from model import refund_request_body
from recovery_format import SCOPE, pending_note_from_backup, read_json, wallet_from_backup, write_private_json
from recovery_session import RecoverySession


def checked(condition, message):
    if not condition:
        raise RuntimeError(message)


def note_with_value(wallet, state, value):
    notes = [wallet.receive_record(output) for output in state['outputs']]
    matches = [note for note in notes if note is not None and note.value == value]
    checked(len(matches) == 1, 'fixed synthetic workload note missing or ambiguous')
    return matches[0]


def economic(export):
    state = reconstruct_public(export['archive'], export['checkpoint'])
    state.pop('checkpoint_hash')
    return state


def r05_first(archive, checkpoint, backups):
    session = RecoverySession(archive, checkpoint)
    state = reconstruct_public(archive, checkpoint)
    alice, bob = (wallet_from_backup(backups[name]) for name in ('Alice', 'Bob'))
    note = note_with_value(alice, state, 600_000_000)
    proof = session.proof_oracle.spend(alice, [note],
        [(bob.note(250_000_000, 'r05-first-pay'), bob.address),
         (alice.note(350_000_000, 'r05-first-change'), alice.address)], state['commitments'])
    outcome = session.process(proof)
    checked(outcome['accepted'], 'first R05 spend did not succeed')
    return session.export(), {'case': 'r05-first', 'outcomes': [True]}


def r05_second(archive, checkpoint, backups):
    session = RecoverySession(archive, checkpoint)
    state = reconstruct_public(archive, checkpoint)
    alice, bob, carol = (wallet_from_backup(backups[name]) for name in ('Alice', 'Bob', 'Carol'))
    # The declared base workload is nine records. Rebuild its old snapshot from
    # public history, not a producer's saved Pool or private proof registry.
    old_snapshot = [output['commitment'] for record in archive['records'][:9]
                    if record['kind'] == 'operation' for output in record['public']['outputs']]
    note = note_with_value(alice, state, 600_000_000)
    competing = session.proof_oracle.spend(alice, [note],
        [(bob.note(200_000_000, 'r05-second-pay'), bob.address),
         (alice.note(400_000_000, 'r05-second-change'), alice.address)], old_snapshot)
    session.proof_oracle.verify(competing)  # Individually valid ideal predicate.
    before = economic(session.export())
    duplicate = session.process(competing)
    checked(not duplicate['accepted'] and 'nullifier' in duplicate['reason'], 'R05 duplicate did not fail spentness')
    checked(economic(session.export()) == before, 'R05 rejection changed economic state')
    independent = note_with_value(bob, state, 400_000_000)
    later = session.proof_oracle.spend(bob, [independent],
        [(carol.note(100_000_000, 'r05-carol'), carol.address),
         (bob.note(300_000_000, 'r05-bob-change'), bob.address)], old_snapshot)
    checked(session.process(later)['accepted'], 'R05 valid continuation failed')
    export = session.export()
    balances = {name: restore_wallet(export['archive'], export['checkpoint'], backup)['spendable_sompi']
                for name, backup in backups.items()}
    checked(balances == {'Alice': 350_000_000, 'Bob': 1_049_999_000, 'Carol': 100_000_000},
            'R05 final synthetic ledger mismatch')
    return export, {'case': 'r05-second', 'outcomes': [False, True],
                    'individually_valid_duplicate': True, 'rejection_preserved_economy': True,
                    'synthetic_balances_sompi': balances}


def r06_stage(archive, checkpoint, backups, winner, first_stage):
    session = RecoverySession(archive, checkpoint)
    carol = wallet_from_backup(backups['Carol'])
    state = reconstruct_public(archive, checkpoint)
    events = [event for event in state['deposits'].values() if event['refund_owner'] == carol.owner]
    checked(len(events) == 1, 'fixed R06 pending deposit missing or ambiguous')
    event = events[0]
    note = pending_note_from_backup(backups['Carol'], event)
    recipient = 'model-native:' + carol.owner
    signature = carol.sign(refund_request_body(event['id'], event['amount'], recipient))
    credit = session.proof_oracle.credit(event, note, carol.address)
    outcomes = []
    if first_stage:
        session.fund_rent(50_000_000)
        malformed = copy.deepcopy(credit); malformed.token = 'MODEL-INVALID-INNER-PROOF'
        before = economic(session.export())
        outcomes.append(session.process(malformed)['accepted'])
        checked(not outcomes[-1] and economic(session.export()) == before, 'R06 invalid credit changed state')
        outcome = session.process(credit) if winner == 'credit' else session.request_refund(event['id'], recipient, signature)
        outcomes.append(outcome['accepted'])
        checked(outcomes[-1], 'R06 first authorized transition failed')
    else:
        before = economic(session.export())
        outcome = session.request_refund(event['id'], recipient, signature) if winner == 'credit' else session.process(credit)
        outcomes.append(outcome['accepted'])
        checked(not outcomes[-1] and economic(session.export()) == before, 'R06 competing transition changed state')
        outcome = session.process(credit) if winner == 'credit' else session.request_refund(event['id'], recipient, signature)
        outcomes.append(outcome['accepted'])
        checked(not outcomes[-1] and economic(session.export()) == before, 'R06 duplicate winner changed state')
        bob = wallet_from_backup(backups['Bob'])
        source = note_with_value(bob, state, 400_000_000)
        later = session.proof_oracle.spend(bob, [source],
            [(bob.note(400_000_000, 'r06-unrelated-' + winner), bob.address)], state['commitments'])
        outcomes.append(session.process(later)['accepted'])
        checked(outcomes[-1], 'R06 unrelated continuation failed')
    export = session.export()
    final = economic(export)
    refund_won = winner == 'refund'
    expected_private = 1_499_999_000 if refund_won else 1_799_999_000
    expected_claims = 500_000_000 if refund_won else 200_000_000
    checked(final['reserve_sompi'] == 2_000_000_000 and final['private_liability_sompi'] == expected_private,
            'R06 principal ledger mismatch')
    checked(sum(claim['amount'] for claim in final['claims'].values()) == expected_claims,
            'R06 unpaid claim mismatch')
    report = restore_wallet(export['archive'], export['checkpoint'], backups['Carol'])
    return export, {'case': 'r06-' + winner + ('-first' if first_stage else '-second'),
        'outcomes': outcomes, 'winner': winner, 'reserve_sompi': final['reserve_sompi'],
        'private_liability_sompi': final['private_liability_sompi'], 'unpaid_claims_sompi': expected_claims,
        'synthetic_carol_spendable_sompi': report['spendable_sompi'],
        'synthetic_carol_unpaid_refund_sompi': report['unpaid_refund_sompi']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', choices=('r05-first', 'r05-second', 'r06-credit-first', 'r06-credit-second',
                                         'r06-refund-first', 'r06-refund-second'))
    parser.add_argument('input_directory', type=Path)
    parser.add_argument('output_directory', type=Path)
    args = parser.parse_args()
    archive = read_json(args.input_directory / 'archive.json')
    checkpoint = read_json(args.input_directory / 'checkpoint.json')
    backups = {name: read_json(args.input_directory / (name.lower() + '-backup.json'))
               for name in ('Alice', 'Bob', 'Carol')}
    if args.case.startswith('r05'):
        function = {'r05-first': r05_first, 'r05-second': r05_second}[args.case]
        export, result = function(archive, checkpoint, backups)
    else:
        _, winner, stage = args.case.split('-')
        export, result = r06_stage(archive, checkpoint, backups, winner, stage == 'first')
    result.update(scope=SCOPE, chain_or_zk_verified=False, native_payouts=0)
    args.output_directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name in ('archive', 'checkpoint'):
        write_private_json(args.output_directory / (name + '.json'), export[name])
    for name, backup in backups.items():
        write_private_json(args.output_directory / (name.lower() + '-backup.json'), backup)
    write_private_json(args.output_directory / 'result.json', result)
    # Per-user data, even this synthetic ledger, stays in the protected result.
    print(json.dumps({key: result[key] for key in ('scope', 'case', 'outcomes', 'chain_or_zk_verified', 'native_payouts')},
                     sort_keys=True))


if __name__ == '__main__':
    main()
