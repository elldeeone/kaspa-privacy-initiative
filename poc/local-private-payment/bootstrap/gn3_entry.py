"""Public GN3 assembly, exact ordinary entry quotation and three-export combine."""
import copy
from pathlib import Path

from gn3_common import (GENESIS, MAX, amount, checked, digest, encoded, fields, hx,
                        need, outside, uint, uuid_text, write_new)
from gn3 import (MAGIC, approval_digest, encode_payload, p2sh, record,
                 validate_genesis, fee_allocation)


APPROVAL_NAMES = {'schema', 'financial_profile_sha256', 'trial_id', 'input_index',
    'signature_script_hex66', 'unsigned_case_approval_sha256',
    'own_initial_public_record_sha256', 'own_receipt_rederived', 'quote'}
QUOTE_NAMES = {'fee_rate_sompi_per_mass', 'mining_mass', 'storage_mass',
    'total_entry_fee_sompi', 'owner_entry_fee_sompi'}



def _source(value):
    fields(value, {'outpoint', 'entry'}, 'three-owner-source-fields')
    fields(value['outpoint'], {'transactionId', 'index'}, 'source-outpoint-fields')
    hx(value['outpoint']['transactionId'], 32)
    uint(value['outpoint']['index'], 32)
    entry = value['entry']
    fields(entry, {'amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'}, 'source-entry-fields')
    amount(entry['amount'], True)
    uint(entry['blockDaaScore'])
    hx(entry['scriptPublicKey'], 36)
    need(entry['isCoinbase'] is False and entry['covenantId'] is None, 'ordinary-source-context')
    return copy.deepcopy(value)


def prepare_genesis(selection, trial_id, records, sources, runtime, output, fee_rate=100):
    """No keys; owners approve independently after this proposed quote exists."""
    uuid_text(trial_id)
    uint(fee_rate)
    need(fee_rate > 0, 'positive-reference-fee-rate')
    need(type(records) in (list, tuple) and len(records) == 3
         and type(sources) is list and len(sources) == 3, 'three-initial-contributions')
    sources = [_source(v) for v in sources]
    payload = encode_payload(selection, trial_id, records)
    notes=[2_000_000_000]*3
    reserve = sum(notes)
    amount(reserve, True)
    # State and redeem derivation are reused from the exact public parser,
    # without inventing a second tree or commitment implementation.
    from gn3 import decode_payload
    _, snapshot, _ = decode_payload(payload, selection, trial_id)
    redeem = b'\x4c\x70' + selection.state_magic + snapshot.state(selection.domain)[8:] + selection.tail
    output = outside(output)
    need(not output.exists(), 'fresh-public-entry-proposal')
    output.mkdir(parents=True, mode=0o700)
    fee, seen, ordinal = 1, set(), 0
    while True:
        need(fee not in seen, 'no-exact-entry-quote-fixed-point-for-selected-sources')
        seen.add(fee)
        allocation = fee_allocation(fee)
        changes = [sources[i]['entry']['amount'] - notes[i] - allocation[i] for i in range(3)]
        need(all(v >= 0 for v in changes), 'funding-source-below-note-and-exact-fee')
        outputs = [{'value': reserve, 'scriptPublicKey': p2sh(redeem), 'covenant': None}]
        outputs += [{'value': value, 'scriptPublicKey': sources[i]['entry']['scriptPublicKey'], 'covenant': None}
                    for i, value in enumerate(changes) if value > 0]
        case = {'transaction': {'version': 1, 'id': '00' * 32,
            'inputs': [{'previousOutpoint': r['outpoint'], 'signatureScript': '41' + '00' * 64 + '01',
                        'sequence': (1 << 64) - 1, 'computeBudget': 10} for r in sources],
            'outputs': outputs, 'lockTime': 0, 'subnetworkId': '00' * 20,
            'gas': 0, 'payload': payload.hex(), 'mass': 0}, 'entries': [r['entry'] for r in sources]}
        case, metrics = runtime.normalize(case, output / ('quote-' + str(ordinal)))
        required = fee_rate * metrics['mining_mass']
        amount(required, True)
        if required == fee:
            break
        fee, ordinal = required, ordinal + 1
    result = validate_genesis(case, selection, trial_id, required_fee=required)
    runtime.roundtrip(case)
    need(metrics['actual_fee_sompi'] == result['fee_sompi'] == required
         and case['transaction']['mass'] == metrics['storage_mass'], 'actual-entry-quote-closure')
    quote = {'schema': 'kpxa-GN3-entry-quote/v1', 'financial_profile_sha256': selection.profile_sha256,
        'trial_id': trial_id, 'fee_rate_sompi_per_mass': fee_rate,
        'unsigned_case_approval_sha256': approval_digest(case, selection, trial_id, fee_rate),
        'metrics': metrics, 'derived_entry': result}
    write_new(output / 'proposed-case.json', encoded(case) + b'\n')
    write_new(output / 'QUOTE.json', encoded(quote) + b'\n')
    return case, quote


def combine(selection, trial_id, unsigned_case, approvals, runtime, output, fee_rate=100):
    """Add exactly three selected input scripts; never accept a supplied key."""
    need(type(approvals) is list and len(approvals) == 3, 'three-owner-signature-exports')
    uint(fee_rate)
    need(fee_rate > 0, 'positive-reference-fee-rate')
    initial = validate_genesis(unsigned_case, selection, trial_id)
    output = outside(output)
    need(not output.exists(), 'fresh-combined-entry-output')
    output.mkdir(parents=True, mode=0o700)
    normalized, metrics = runtime.normalize(unsigned_case, output / 'independent-unsigned-quote')
    need(normalized == unsigned_case, 'unsigned-native-ID-and-storage-mass')
    required = fee_rate * metrics['mining_mass']
    validate_genesis(unsigned_case, selection, trial_id, required_fee=required)
    expected_digest = approval_digest(unsigned_case, selection, trial_id, fee_rate)
    case = copy.deepcopy(unsigned_case)
    indices = set()
    for approval in approvals:
        fields(approval, APPROVAL_NAMES, 'signature-only-owner-export-fields')
        index = approval['input_index']
        need(type(index) is int and index in (0, 1, 2) and index not in indices, 'distinct-owner-input-index')
        indices.add(index)
        need(approval['schema'] == 'kpxa-GN3-owner-approval/v1'
             and approval['financial_profile_sha256'] == selection.profile_sha256
             and approval['trial_id'] == trial_id
             and approval['unsigned_case_approval_sha256'] == expected_digest
             and approval['own_receipt_rederived'] is True, 'exact-owner-entry-approval-context')
        row = hx(unsigned_case['transaction']['payload'])[88 + index * 520:88 + (index + 1) * 520]
        need(approval['own_initial_public_record_sha256'] == digest(row), 'approved-public-initial-record')
        fields(approval['quote'], QUOTE_NAMES, 'owner-quote-receipt-fields')
        for number in approval['quote'].values():
            uint(number)
        need(approval['quote'] == {'fee_rate_sompi_per_mass': fee_rate,
            'mining_mass': metrics['mining_mass'], 'storage_mass': metrics['storage_mass'],
            'total_entry_fee_sompi': required,
            'owner_entry_fee_sompi': initial['contributions'][index]['entry_fee_sompi']},
            'matching-independent-owner-entry-quotes')
        sig = hx(approval['signature_script_hex66'], 66)
        need(sig[:1] == b'\x41' and sig[-1:] == b'\x01', 'ordinary-ALL-script')
        case['transaction']['inputs'][index]['signatureScript'] = sig.hex()
    validate_genesis(case, selection, trial_id, required_fee=required, signed=True)
    runtime.roundtrip(case)
    signed_normalized, signed_metrics = runtime.normalize(case, output / 'signed-normalized')
    need(signed_normalized == case and signed_metrics == metrics, 'signed-body-exact-quote-and-ID')
    report, checked_metrics = runtime.validate(case, output / 'ordinary-native-Full')
    need(checked_metrics == metrics, 'Full-and-quoted-entry-metrics')
    result = {'schema': 'kpxa-GN3-final-local-entry/v1',
        'classification': 'STRICT_ENTRY_AND_NATIVE_INPUTS_VALID_NOT_ACCEPTED_OR_CURRENT',
        'financial_profile_sha256': selection.profile_sha256, 'trial_id': trial_id,
        'founding_outpoint': {'transactionId': case['transaction']['id'], 'index': 0},
        'unsigned_case_approval_sha256': expected_digest, 'metrics': metrics,
        'derived_entry': initial, 'three_complete_ordinary_ALL_signatures': True,
        'accepted_chain_backing_or_currentness': False, 'broadcast_performed': False}
    write_new(output / 'selected-case.json', encoded(case) + b'\n')
    write_new(output / 'RESULTS.json', encoded(result) + b'\n')
    return case, result
