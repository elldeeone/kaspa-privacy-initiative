#!/usr/bin/env python3
"""Offline shutdown rehearsal. One user's backup per exit/audit process.

pay-all consumes public claim terms only. Every payment is a synthetic effect;
the independent real-proof/native shutdown gate remains not passed.
"""
import argparse
import json

from model import Note, refund_request_body
from recovery import restore_wallet
from recovery_format import (SCOPE, RecoveryError, read_json, wallet_from_backup,
                             write_private_json)
from recovery_session import RecoverySession
from recovery_payout_trials import pay_next
from recovery_trials import checked, economic


def exit_user(session, backup):
    report = restore_wallet(**session.export(), backup=backup)
    wallet = wallet_from_backup(backup)
    if report['spendable_sompi']:
        session.fund_rent(50_000_000)
        notes = [Note(**entry['note']) for entry in report['spendable_notes']]
        proof = session.proof_oracle.spend(wallet, notes, [], economic(session.export())['commitments'],
                    withdrawal={'recipient': 'model-native:' + wallet.owner, 'amount': report['spendable_sompi']})
        checked(session.process(proof)['accepted'], 'synthetic user exit failed')
    pending = [event for event in economic(session.export())['deposits'].values()
               if event['state'] == 'pending' and event['refund_owner'] == wallet.owner]
    for event in pending:
        session.fund_rent(50_000_000)
        recipient = 'model-native:' + wallet.owner
        signature = wallet.sign(refund_request_body(event['id'], event['amount'], recipient))
        checked(session.request_refund(event['id'], recipient, signature)['accepted'], 'synthetic owner refund failed')


def public_summary(session):
    state = economic(session.export())
    return {'reserve_sompi': state['reserve_sompi'],
            'paid_user_principal_sompi': sum(c['amount'] for c in state['claims'].values() if c['paid']),
            'paid_fee_sompi': sum(c['amount'] for c in state['fees'].values() if c['paid']),
            'rent_paid_sompi': state['rent_paid_sompi'],
            'native_shutdown_gate_passed': False, 'real_proof_ordered_gate_passed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('exit-user', 'pay-all', 'audit-user'))
    for name in ('archive', 'checkpoint', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--backup')
    args = parser.parse_args()
    if (args.stage == 'pay-all') == bool(args.backup):
        parser.error('exit/audit requires one backup; public payment accepts none')
    try:
        session = RecoverySession(read_json(args.archive), read_json(args.checkpoint))
        backup = read_json(args.backup) if args.backup else None
        if args.stage == 'exit-user':
            exit_user(session, backup)
        elif args.stage == 'pay-all':
            state = economic(session.export())
            checked(state['private_liability_sompi'] == 0 and not any(
                event['state'] == 'pending' for event in state['deposits'].values()), 'unprepared user liabilities')
            count = sum(not c['paid'] for c in state['claims'].values()) + sum(not f['paid'] for f in state['fees'].values())
            for _ in range(count):
                pay_next(session, last='fee')
            checked(economic(session.export())['reserve_sompi'] == 0, 'terminal reserve not zero')
        report = restore_wallet(**session.export(), backup=backup) if backup else None
        if args.stage == 'audit-user':
            checked(all(report[key] == 0 for key in ('spendable_sompi', 'pending_deposit_sompi',
                         'unpaid_exit_sompi', 'unpaid_refund_sompi')), 'unpaid user entitlement')
        from pathlib import Path
        output = Path(args.output)
        output.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name, value in session.export().items():
            write_private_json(output / (name + '.json'), value)
        if report:
            write_private_json(output / 'wallet.json', report)
        result = public_summary(session)
        result.update(scope=SCOPE, stage=args.stage, chain_or_zk_verified=False, native_payouts=0)
        write_private_json(output / 'result.json', result)
        print(json.dumps({key: result[key] for key in ('scope', 'stage', 'chain_or_zk_verified',
                          'native_payouts', 'native_shutdown_gate_passed')}, sort_keys=True))
        return 0
    except RecoveryError as error:
        print(json.dumps({'scope': SCOPE, 'status': error.status, 'code': error.code}, sort_keys=True))
        return 2
    except (OSError, RuntimeError):
        print(json.dumps({'scope': SCOPE, 'status': 'incomplete_offline_rehearsal'}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
