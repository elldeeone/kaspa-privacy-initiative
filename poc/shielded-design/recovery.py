#!/usr/bin/env python3
"""Offline accepted-MODEL-effect reconstruction. No ZK, RPC or native payout."""
import argparse
import copy
import json

from model import (NETWORK, POOL, VERSION, amount, canonical, hash_id, total,
                   refund_request_body, refund_signature_bytes)
from nacl.exceptions import CryptoError
from nacl.signing import VerifyKey
from recovery_format import (DESCRIPTOR, SCOPE, RecoveryError, digest, fields, hex32,
                             read_json, reject, wallet_from_backup, write_private_json)


def integer(value):
    try:
        return amount(value)
    except ValueError:
        reject('integer_sompi_range')


def summed(values):
    try:
        return total(values)
    except ValueError:
        reject('integer_sompi_overflow')


def model_checkpoint(archive):
    """Fixture producer only. Retain separately; this is NOT chain authentication."""
    profiles = {'kpi-model-records/v1': 'kpi-model-checkpoint/v1',
                'kpi-model-records/v2': 'kpi-model-checkpoint/v2',
                'kpi-model-records/v3': 'kpi-model-checkpoint/v3'}
    if archive.get('schema') not in profiles:
        reject('archive_version')
    return {'schema': profiles[archive['schema']], 'scope': SCOPE,
            'descriptor_hash': digest(archive['descriptor']),
            'record_count': len(archive['records']), 'archive_hash': digest(archive)}


def outputs_valid(outputs):
    if type(outputs) is not list:
        reject('output_list_required')
    for output in outputs:
        fields(output, 'commitment ciphertext')
        hex32(output['commitment'])
        ciphertext = output['ciphertext']
        if not ciphertext:
            raise RecoveryError('incomplete_data', 'delivery_missing')
        if (type(ciphertext) is not str or len(ciphertext) % 2 or
                any(c not in '0123456789abcdef' for c in ciphertext)):
            reject('ciphertext_encoding')


def reconstruct_public(archive, checkpoint):
    """Reconstruct only after comparison with the caller's trusted MODEL horizon.

    No validity flags or exported oracle registry are accepted. The checkpoint
    authenticates accepted model effects by assumption; it does not prove their
    hidden predicate or any L1 acceptance. A replacement checkpoint breaks that
    assumption. No partial state escapes on error.
    """
    fields(checkpoint, 'schema scope descriptor_hash record_count archive_hash')
    fields(archive, 'schema scope descriptor records')
    if (checkpoint['scope'] != SCOPE or archive['scope'] != SCOPE or
            (archive['schema'], checkpoint['schema']) not in (
                ('kpi-model-records/v1', 'kpi-model-checkpoint/v1'),
                ('kpi-model-records/v2', 'kpi-model-checkpoint/v2'),
                ('kpi-model-records/v3', 'kpi-model-checkpoint/v3'))):
        reject('archive_or_checkpoint_version')
    if digest(archive['descriptor']) != digest(DESCRIPTOR) or checkpoint['descriptor_hash'] != digest(DESCRIPTOR):
        reject('descriptor_mismatch')
    hex32(checkpoint['archive_hash'])
    count = integer(checkpoint['record_count'])
    records = archive['records']
    if type(records) is not list:
        reject('record_list_required')
    if len(records) < count:
        raise RecoveryError('incomplete_data', 'record_range_missing')
    if len(records) != count:
        reject('unexpected_record_count')
    # Identify absent delivery fields before a general digest error. Neither
    # result qualifies history or returns a balance.
    for record in records:
        if type(record) is dict and record.get('kind') == 'operation':
            if type(record.get('public')) is not dict or 'outputs' not in record['public']:
                raise RecoveryError('incomplete_data', 'operation_outputs_missing')
            outputs_valid(record['public']['outputs'])
    if digest(archive) != checkpoint['archive_hash']:
        reject('archive_checkpoint_mismatch')
    state = {'commitments': [], 'outputs': [], 'nullifiers': [], 'anchors': [hash_id([])],
             'deposits': {}, 'claims': {}, 'fees': {}, 'reserve_sompi': 0,
             'private_liability_sompi': 0, 'rent_available_sompi': 0,
             'rent_reserved_sompi': 0, 'rent_funded_sompi': 0, 'rent_paid_sompi': 0}
    processed, spent = set(), set()
    for index, record in enumerate(records):
        if type(record) is not dict or type(record.get('seq')) is not int or record['seq'] != index:
            reject('record_sequence')
        kind = record.get('kind')
        if kind == 'deposit':
            fields(record, 'seq kind event')
            event = record['event']
            fields(event, 'id amount commitment refund_owner')
            identity = hex32(event['id'])
            hex32(event['commitment']); hex32(event['refund_owner'])
            value = integer(event['amount'])
            if value == 0 or identity in state['deposits']:
                reject('duplicate_or_zero_deposit')
            state['reserve_sompi'] = summed([state['reserve_sompi'], value])
            state['deposits'][identity] = {**event, 'state': 'pending'}
        elif kind == 'rent_funding':
            fields(record, 'seq kind amount')
            value = integer(record['amount'])
            state['rent_available_sompi'] = summed([state['rent_available_sompi'], value])
            state['rent_funded_sompi'] = summed([state['rent_funded_sompi'], value])
        elif kind == 'rejection':
            fields(record, 'seq kind operation_hash')
            hex32(record['operation_hash'])  # Retained ordered no-op, no validity flag.
        elif kind == 'refund_request':
            if archive['schema'] not in ('kpi-model-records/v2', 'kpi-model-records/v3'):
                reject('refund_requires_archive_v2')
            fields(record, 'seq kind deposit recipient signature')
            event = state['deposits'].get(hex32(record['deposit']))
            if event is None or event['state'] != 'pending':
                reject('refund_deposit_not_pending')
            try:
                body = refund_request_body(event['id'], event['amount'], record['recipient'])
                VerifyKey(bytes.fromhex(event['refund_owner'])).verify(
                    canonical(body), refund_signature_bytes(record['signature']))
            except (ValueError, CryptoError):
                reject('refund_authorization')
            if state['rent_available_sompi'] < 50_000_000:
                reject('permission_rent_unfunded')
            identity = hash_id(body)
            if identity in state['claims']:
                reject('refund_claim_replay')
            next_rent = summed([state['rent_reserved_sompi'], 50_000_000])
            event['state'] = 'refund_pending'
            state['claims'][identity] = {'recipient': record['recipient'], 'amount': event['amount'],
                'rent': 50_000_000, 'kind': 'deposit_refund', 'deposit': event['id'], 'paid': False}
            state['rent_available_sompi'] -= 50_000_000
            state['rent_reserved_sompi'] = next_rent
        elif kind == 'payout':
            if archive['schema'] != 'kpi-model-records/v3':
                reject('payout_requires_archive_v3')
            fields(record, 'seq kind claim recipient principal rent remaining_reserve')
            claim = state['claims'].get(hex32(record['claim']))
            principal, rent, remaining = (integer(record[key]) for key in ('principal', 'rent', 'remaining_reserve'))
            if (claim is None or claim['paid'] or
                    (record['recipient'], principal, rent, remaining) !=
                    (claim['recipient'], claim['amount'], claim['rent'], state['reserve_sompi'] - claim['amount'])):
                reject('payout_claim_or_terms')
            summed([principal, rent])  # One model output; reject overflow before consuming its claim.
            next_paid_rent = summed([state['rent_paid_sompi'], rent])
            claim['paid'] = True
            if claim.get('kind') == 'deposit_refund':
                state['deposits'][claim['deposit']]['state'] = 'refunded'
            state['reserve_sompi'] = remaining
            state['rent_reserved_sompi'] -= rent
            state['rent_paid_sompi'] = next_paid_rent
        elif kind == 'fee_payment':
            if archive['schema'] != 'kpi-model-records/v3':
                reject('fee_payment_requires_archive_v3')
            fields(record, 'seq kind claim recipient amount remaining_reserve')
            fee = state['fees'].get(hex32(record['claim']))
            value, remaining = integer(record['amount']), integer(record['remaining_reserve'])
            if (fee is None or fee['paid'] or (record['recipient'], value, remaining) !=
                    (fee['recipient'], fee['amount'], state['reserve_sompi'] - fee['amount'])):
                reject('fee_claim_or_terms')
            fee['paid'] = True
            state['reserve_sompi'] = remaining
        elif kind == 'operation':
            fields(record, 'seq kind public')
            p = record['public']
            if p.get('kind') == 'credit':
                fields(p, 'kind network pool version deposit outputs')
            elif p.get('kind') == 'spend':
                fields(p, 'kind network pool version anchor nullifiers outputs withdrawal fee fee_recipient')
            else:
                reject('operation_kind')
            if type(p['version']) is not int or (p['network'], p['pool'], p['version']) != (NETWORK, POOL, VERSION):
                reject('operation_domain')
            identity = hash_id(p)
            if identity in processed:
                reject('operation_replay')
            new = [o['commitment'] for o in p['outputs']]
            if len(set(new)) != len(new) or set(new).intersection(state['commitments']):
                reject('duplicate_commitment')
            if p['kind'] == 'credit':
                event = state['deposits'].get(hex32(p['deposit']))
                if event is None or event['state'] != 'pending' or new != [event['commitment']]:
                    reject('deposit_credit_binding')
                event['state'] = 'credited'
                state['private_liability_sompi'] = summed([state['private_liability_sompi'], event['amount']])
            else:
                if p['anchor'] not in state['anchors']:
                    reject('unknown_membership_anchor')
                nullifiers = p['nullifiers']
                if type(nullifiers) is not list or not nullifiers:
                    reject('nullifier_list_required')
                for nullifier in nullifiers:
                    hex32(nullifier)
                if len(set(nullifiers)) != len(nullifiers) or spent.intersection(nullifiers):
                    reject('nullifier_already_spent')
                fields(p['withdrawal'], 'recipient amount')
                value, fee = integer(p['withdrawal']['amount']), integer(p['fee'])
                debit = summed([value, fee])
                if debit > state['private_liability_sompi']:
                    reject('liability_underflow')
                if type(p['withdrawal']['recipient']) is not str or (value and not p['withdrawal']['recipient']):
                    reject('exit_recipient')
                if type(p['fee_recipient']) is not str or (fee and not p['fee_recipient']):
                    reject('fee_recipient')
                if value:
                    if state['rent_available_sompi'] < 50_000_000:
                        reject('permission_rent_unfunded')
                    state['rent_available_sompi'] -= 50_000_000
                    state['rent_reserved_sompi'] = summed([state['rent_reserved_sompi'], 50_000_000])
                    state['claims'][identity] = {**p['withdrawal'], 'rent': 50_000_000, 'paid': False}
                if fee:
                    state['fees'][identity] = {'amount': fee, 'recipient': p['fee_recipient'], 'paid': False}
                state['private_liability_sompi'] -= debit
                spent.update(nullifiers)
            state['commitments'].extend(new)
            state['outputs'].extend(copy.deepcopy(p['outputs']))
            anchor = hash_id(state['commitments'])
            if anchor not in state['anchors']:
                state['anchors'].append(anchor)
            processed.add(identity)
        else:
            reject('record_kind')
        pending = summed(d['amount'] for d in state['deposits'].values() if d['state'] == 'pending')
        claims = summed(c['amount'] for c in state['claims'].values() if not c['paid'])
        fees = summed(f['amount'] for f in state['fees'].values() if not f['paid'])
        if state['reserve_sompi'] != summed([state['private_liability_sompi'], pending, claims, fees]):
            reject('principal_accounting')
        if state['rent_reserved_sompi'] != summed(c['rent'] for c in state['claims'].values() if not c['paid']):
            reject('claim_rent_accounting')
        if state['rent_funded_sompi'] != summed([state['rent_available_sompi'], state['rent_reserved_sompi'], state['rent_paid_sompi']]):
            reject('rent_accounting')
    state['nullifiers'] = sorted(spent)
    state['checkpoint_hash'] = digest(checkpoint)
    return state


def restore_wallet(archive, checkpoint, backup):
    """Private wallet report. Caller must protect it like the backup."""
    wallet = wallet_from_backup(backup)
    state = reconstruct_public(archive, checkpoint)
    notes = []
    for output in state['outputs']:
        try:
            note = wallet.receive_record(output)
        except ValueError:
            reject('invalid_recipient_delivery')
        if note is not None:
            notes.append(note)
    found = {note.commitment for note in notes}
    if set(backup['expected_receipts']) - found:
        raise RecoveryError('incomplete_wallet_data', 'expected_receipt_not_recoverable')
    positions = {commitment: n for n, commitment in enumerate(state['commitments'])}
    spendable, spent_count = [], 0
    for note in notes:
        nullifier = wallet.nullifier(note)
        if nullifier in state['nullifiers']:
            spent_count += 1
        else:
            spendable.append({'commitment': note.commitment, 'note': note.__dict__,
                              'position': positions[note.commitment], 'anchor': state['anchors'][-1]})
    return {'scope': SCOPE, 'status': 'complete_at_model_checkpoint',
            'checkpoint_hash': state['checkpoint_hash'], 'chain_or_zk_verified': False,
            'unknown_sender_delivery_guaranteed': False,
            'accepted_note_count': len(notes), 'spent_note_count': spent_count,
            'spendable_sompi': summed(n['note']['value'] for n in spendable),
            'spendable_notes': spendable,
            'pending_deposit_sompi': summed(d['amount'] for d in state['deposits'].values()
                                          if d['state'] == 'pending' and d['refund_owner'] == wallet.owner),
            'unpaid_exit_sompi': summed(c['amount'] for c in state['claims'].values()
                                      if not c['paid'] and c['recipient'] == 'model-native:' + wallet.owner and c.get('kind') != 'deposit_refund'),
            'unpaid_refund_sompi': summed(c['amount'] for c in state['claims'].values()
                                        if not c['paid'] and c['recipient'] == 'model-native:' + wallet.owner and c.get('kind') == 'deposit_refund')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'checkpoint', 'backup', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        report = restore_wallet(read_json(args.archive), read_json(args.checkpoint), read_json(args.backup))
        write_private_json(args.output, report)
        summary = {key: report[key] for key in ('scope', 'status', 'checkpoint_hash', 'chain_or_zk_verified')}
        print(json.dumps(summary, sort_keys=True))
        return 0
    except RecoveryError as error:
        print(json.dumps({'scope': SCOPE, 'status': error.status, 'code': error.code,
                          'chain_or_zk_verified': False}, sort_keys=True))
        return 2
    except OSError:
        print(json.dumps({'scope': SCOPE, 'status': 'io_error', 'code': 'file_access_or_output_exists',
                          'chain_or_zk_verified': False}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
