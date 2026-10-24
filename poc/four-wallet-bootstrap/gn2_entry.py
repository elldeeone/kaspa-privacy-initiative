"""Public GN2 assembly, exact ordinary entry quotation and two-export combine."""
import copy
from pathlib import Path

from gn2_common import (GENESIS, MAX, amount, checked, digest, encoded, fields, hx,
                        need, outside, uint, uuid_text, write_new)
from gn2 import (MAGIC, approval_digest, encode_payload, p2sh, record,
                 validate_genesis)
from gn2_selection import entry_selection

INIT_NAMES = {'schema', 'network_id', 'genesis_hash_hex', 'financial_profile_id',
    'profile_identity_sha256', 'domain_hex32', 'trial_id', 'role',
    'invoices_hex208', 'funding', 'initial_record_hex496'}
APPROVAL_NAMES = {'schema', 'financial_profile_sha256', 'trial_id', 'input_index',
    'signature_script_hex66', 'unsigned_case_approval_sha256',
    'own_initial_public_record_sha256', 'own_receipt_rederived', 'quote'}
QUOTE_NAMES = {'fee_rate_sompi_per_mass', 'mining_mass', 'storage_mass',
    'total_entry_fee_sompi', 'owner_entry_fee_sompi'}


def initial_record(value, profile, trial_id, expected_role):
    fields(value, INIT_NAMES, 'immutable-owner-public-record-fields')
    need(value['schema'] == 'kpx6-owner-initial-public/v1'
         and value['network_id'] == 'testnet-10' and value['genesis_hash_hex'] == GENESIS
         and value['financial_profile_id'] == profile.financial_profile_id
         and value['domain_hex32'] == profile.domain.hex()
         and value['trial_id'] == uuid_text(trial_id) and value['role'] == expected_role,
         'own-initial-public-context')
    hx(value['profile_identity_sha256'], 32)
    fields(value['invoices_hex208'], {'0', '1'}, 'owner-public-invoices')
    for invoice in value['invoices_hex208'].values():
        hx(invoice, 208)
    fields(value['funding'], {'xonly_hex32', 'address', 'script_public_key'}, 'ordinary-funding-public-fields')
    key = hx(value['funding']['xonly_hex32'], 32)
    need(type(value['funding']['address']) is str and value['funding']['address'].startswith('kaspatest:')
         and value['funding']['script_public_key'] == '000020' + key.hex() + 'ac',
         'ordinary-funding-public-key-script')
    row = hx(value['initial_record_hex496'], 496)
    need(record(row[:168], row[200:464], profile.domain) == row, 'own-initial-note-record')
    return row


def _source(value):
    fields(value, {'outpoint', 'entry'}, 'two-owner-source-fields')
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


def prepare_genesis(profile, trial_id, owners, sources, runtime, output, fee_rate=100):
    """No keys; owners approve independently after this proposed quote exists."""
    uuid_text(trial_id)
    uint(fee_rate)
    need(fee_rate > 0, 'positive-reference-fee-rate')
    need(type(owners) is list and len(owners) == 2 and type(sources) is list and len(sources) == 2,
         'two-initial-contributions')
    records = [initial_record(v, profile, trial_id, role) for v, role in zip(owners, ('A', 'C'))]
    sources = [_source(v) for v in sources]
    for i in range(2):
        need(sources[i]['entry']['scriptPublicKey'] == owners[i]['funding']['script_public_key'],
             'source-owned-by-selected-initial-contributor')
    selection = entry_selection(profile)
    payload = encode_payload(selection, trial_id, records)
    notes = [int.from_bytes(row[64:72], 'little') for row in records]
    reserve = sum(notes)
    amount(reserve, True)
    # State and redeem derivation are reused from the exact public parser,
    # without inventing a second tree or commitment implementation.
    from gn2 import decode_payload
    _, snapshot, _ = decode_payload(payload, selection, trial_id)
    redeem = b'\x4c\x70' + snapshot.state(profile.domain) + selection.tail
    output = outside(output)
    need(not output.exists(), 'fresh-public-entry-proposal')
    output.mkdir(parents=True, mode=0o700)
    fee, seen, ordinal = 1, set(), 0
    while True:
        need(fee not in seen, 'no-exact-entry-quote-fixed-point-for-selected-sources')
        seen.add(fee)
        allocation = [fee // 2, fee - fee // 2]
        changes = [sources[i]['entry']['amount'] - notes[i] - allocation[i] for i in range(2)]
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
    quote = {'schema': 'kpx6-GN2-entry-quote/v1', 'financial_profile_sha256': profile.profile_sha256,
        'trial_id': trial_id, 'fee_rate_sompi_per_mass': fee_rate,
        'unsigned_case_approval_sha256': approval_digest(case, selection, trial_id, fee_rate),
        'metrics': metrics, 'derived_entry': result}
    write_new(output / 'proposed-case.json', encoded(case) + b'\n')
    write_new(output / 'QUOTE.json', encoded(quote) + b'\n')
    return case, quote


def combine(profile, trial_id, unsigned_case, approvals, runtime, output, fee_rate=100):
    """Add exactly two selected input scripts; never accept a supplied key."""
    need(type(approvals) is list and len(approvals) == 2, 'two-owner-signature-exports')
    uint(fee_rate)
    need(fee_rate > 0, 'positive-reference-fee-rate')
    selection = entry_selection(profile)
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
        need(type(index) is int and index in (0, 1) and index not in indices, 'distinct-owner-input-index')
        indices.add(index)
        need(approval['schema'] == 'kpx6-GN2-owner-approval/v1'
             and approval['financial_profile_sha256'] == profile.profile_sha256
             and approval['trial_id'] == trial_id
             and approval['unsigned_case_approval_sha256'] == expected_digest
             and approval['own_receipt_rederived'] is True, 'exact-owner-entry-approval-context')
        row = hx(unsigned_case['transaction']['payload'])[88 + index * 496:88 + (index + 1) * 496]
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
    result = {'schema': 'kpx6-GN2-final-local-entry/v1',
        'classification': 'STRICT_ENTRY_AND_NATIVE_INPUTS_VALID_NOT_ACCEPTED_OR_CURRENT',
        'financial_profile_sha256': profile.profile_sha256, 'trial_id': trial_id,
        'founding_outpoint': {'transactionId': case['transaction']['id'], 'index': 0},
        'unsigned_case_approval_sha256': expected_digest, 'metrics': metrics,
        'derived_entry': initial, 'two_complete_ordinary_ALL_signatures': True,
        'accepted_chain_backing_or_currentness': False, 'broadcast_performed': False}
    write_new(output / 'selected-case.json', encoded(case) + b'\n')
    write_new(output / 'RESULTS.json', encoded(result) + b'\n')
    return case, result
