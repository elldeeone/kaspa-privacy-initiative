#!/usr/bin/env python3
"""Fixed R07 offline synthetic payment effects; no native transaction or RPC.

One command per new process: prepare claims, pay one, or audit the terminal
history. Wallet/executor roles coexist in this synthetic harness.
"""
import argparse
import json
from pathlib import Path

from model import Note, refund_request_body
from recovery import restore_wallet
from recovery_format import SCOPE, read_json, wallet_from_backup, write_private_json
from recovery_session import RecoverySession
from recovery_trials import checked, economic


def prepare(session, backups):
    session.fund_rent(150_000_000)  # Three new permissions, outside user principal.
    for name, principal in (('Alice', 600_000_000), ('Bob', 899_999_000)):
        saved = session.export()
        report = restore_wallet(saved['archive'], saved['checkpoint'], backups[name])
        wallet = wallet_from_backup(backups[name])
        notes = [Note(**entry['note']) for entry in report['spendable_notes']]
        proof = session.proof_oracle.spend(wallet, notes, [], economic(saved)['commitments'],
                    withdrawal={'recipient': 'model-native:' + wallet.owner, 'amount': principal})
        checked(session.process(proof)['accepted'], 'R07 full private exit failed')
    carol = wallet_from_backup(backups['Carol'])
    state = economic(session.export())
    pending = [event for event in state['deposits'].values() if event['state'] == 'pending']
    checked(len(pending) == 1, 'R07 fixed pending deposit missing')
    event = pending[0]
    recipient = 'model-native:' + carol.owner
    signature = carol.sign(refund_request_body(event['id'], event['amount'], recipient))
    checked(session.request_refund(event['id'], recipient, signature)['accepted'], 'R07 refund claim failed')
    state = economic(session.export())
    checked(state['private_liability_sompi'] == 0 and len(state['claims']) == 4,
            'R07 prepared liability mismatch')


def reject_paid_replays(session):
    """Try spent claims with a newly computed residual, then check no mutation."""
    before = economic(session.export())
    outcomes = []
    for identity, claim in before['claims'].items():
        if claim['paid']:
            result = session.payout(identity, claim['recipient'], claim['amount'], claim['rent'],
                                    max(0, before['reserve_sompi'] - claim['amount']))
            outcomes.append(result['accepted'])
    for identity, fee in before['fees'].items():
        if fee['paid']:
            result = session.pay_fee(identity, fee['recipient'], fee['amount'],
                                     max(0, before['reserve_sompi'] - fee['amount']))
            outcomes.append(result['accepted'])
    checked(not any(outcomes) and economic(session.export()) == before, 'R07 paid replay changed state')
    return len(outcomes)


def pay_next(session, last):
    state = economic(session.export())
    claims = sorted(((identity, claim) for identity, claim in state['claims'].items() if not claim['paid']),
                    key=lambda pair: (pair[1]['amount'], pair[0]))
    fees = sorted((identity, fee) for identity, fee in state['fees'].items() if not fee['paid'])
    if fees and (last == 'user' or not claims):
        identity, fee = fees[0]
        result = session.pay_fee(identity, fee['recipient'], fee['amount'], state['reserve_sompi'] - fee['amount'])
    else:
        checked(bool(claims), 'R07 no unpaid claim remains')
        identity, claim = claims[0]
        result = session.payout(identity, claim['recipient'], claim['amount'], claim['rent'],
                                state['reserve_sompi'] - claim['amount'])
    checked(result['accepted'], 'R07 authorized next payment failed')


def summary(session, backups):
    saved = session.export()
    state = economic(saved)
    paid_claims = [claim for claim in state['claims'].values() if claim['paid']]
    paid_fees = [fee for fee in state['fees'].values() if fee['paid']]
    pending = sum(event['amount'] for event in state['deposits'].values() if event['state'] == 'pending')
    outstanding = state['private_liability_sompi'] + pending
    outstanding += sum(claim['amount'] for claim in state['claims'].values() if not claim['paid'])
    outstanding += sum(fee['amount'] for fee in state['fees'].values() if not fee['paid'])
    payments = [record for record in saved['archive']['records'] if record['kind'] in ('payout', 'fee_payment')]
    by_user = {}
    for name, backup in backups.items():
        recipient = 'model-native:' + wallet_from_backup(backup).owner
        by_user[name] = sum(claim['amount'] for claim in paid_claims if claim['recipient'] == recipient)
    return {'reserve_sompi': state['reserve_sompi'], 'outstanding_principal_sompi': outstanding,
            'paid_user_principal_sompi': sum(claim['amount'] for claim in paid_claims),
            'paid_user_principal_by_user_sompi': by_user,
            'paid_fee_sompi': sum(fee['amount'] for fee in paid_fees),
            'rent_funded_sompi': state['rent_funded_sompi'], 'rent_paid_sompi': state['rent_paid_sompi'],
            'rent_available_sompi': state['rent_available_sompi'], 'rent_reserved_sompi': state['rent_reserved_sompi'],
            'synthetic_payment_count': len(payments), 'last_payment_kind': payments[-1]['kind'] if payments else None}


def audit(session, backups, result):
    expected = {'reserve_sompi': 0, 'outstanding_principal_sompi': 0,
                'paid_user_principal_sompi': 1_999_999_000, 'paid_fee_sompi': 1_000,
                'paid_user_principal_by_user_sompi': {'Alice': 600_000_000, 'Bob': 1_099_999_000, 'Carol': 300_000_000},
                'rent_funded_sompi': 200_000_000, 'rent_paid_sompi': 200_000_000,
                'rent_available_sompi': 0, 'rent_reserved_sompi': 0, 'synthetic_payment_count': 5}
    checked(all(result[key] == value for key, value in expected.items()), 'R07 terminal ledger mismatch')
    saved = session.export()
    for backup in backups.values():
        report = restore_wallet(saved['archive'], saved['checkpoint'], backup)
        checked(all(report[key] == 0 for key in ('spendable_sompi', 'pending_deposit_sompi',
                    'unpaid_exit_sompi', 'unpaid_refund_sompi')), 'R07 terminal wallet liability remains')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'pay-next', 'audit'))
    parser.add_argument('input_directory', type=Path)
    parser.add_argument('output_directory', type=Path)
    parser.add_argument('--last', choices=('fee', 'user'), default='fee')
    args = parser.parse_args()
    session = RecoverySession(read_json(args.input_directory / 'archive.json'),
                              read_json(args.input_directory / 'checkpoint.json'))
    backups = {name: read_json(args.input_directory / (name.lower() + '-backup.json')) for name in ('Alice', 'Bob', 'Carol')}
    rejected = reject_paid_replays(session)
    if args.stage == 'prepare':
        prepare(session, backups)
    elif args.stage == 'pay-next':
        pay_next(session, args.last)
    result = summary(session, backups)
    if args.stage == 'audit':
        audit(session, backups, result)
        checked(result['last_payment_kind'] == ('fee_payment' if args.last == 'fee' else 'payout'),
                'R07 final payment kind mismatch')
    result.update(scope=SCOPE, stage=args.stage, last=args.last, rejected_paid_replays=rejected,
                  chain_or_zk_verified=False, native_payouts=0)
    args.output_directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, value in session.export().items():
        write_private_json(args.output_directory / (name + '.json'), value)
    for name, backup in backups.items():
        write_private_json(args.output_directory / (name.lower() + '-backup.json'), backup)
    write_private_json(args.output_directory / 'result.json', result)
    print(json.dumps({key: result[key] for key in ('scope', 'stage', 'chain_or_zk_verified', 'native_payouts')}, sort_keys=True))


if __name__ == '__main__':
    main()
