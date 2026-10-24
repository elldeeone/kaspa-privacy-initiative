"""ADR59 public two-P0 host oracle and acyclic journal/body codecs.

The caller supplies an independently installed child profile, actual starting
head and trusted wrapper emitter. No transcript selects code/VKs/currentness.
This checks inner G16/public semantics; outer receipt/native execution is a
separate gate. Child contexts are virtual and never asserted accepted UTXOs.
"""
from dataclasses import dataclass

from policy import Head, Policy, auth_fields, inspect, state
from wire import h, hexbytes, need, p2sh, storage_mass, transaction_id, uint, validate_case

PAYLOAD_MAGIC = b'KPX5VP01'
JOURNAL_MAGIC = b'KPX5VS01'
BODY_MAGIC = b'KPX5FB01'
VERSION = 1
COUNT = 2
CHILD_PAYLOAD_BYTES = 3920
RECORD_BYTES = 4048
PAYLOAD_BYTES = 8108
JOURNAL_BYTES = 424


def le(value, bits):
    return uint(value, bits).to_bytes(bits // 8, 'little')


def point_bytes(point):
    need(type(point) is dict and set(point) == {'transactionId', 'index'}, 'actual_point_fields')
    return hexbytes(point['transactionId'], 32) + le(point['index'], 32)


def push(raw):
    need(type(raw) is bytes and len(raw) < 65536, 'push_width')
    return ((bytes([len(raw)]) if len(raw) <= 75 else b'\x4c' + bytes([len(raw)])
             if len(raw) <= 255 else b'\x4d' + le(len(raw), 16)) + raw)


def encode_payload(records):
    need(type(records) in (tuple, list) and len(records) == COUNT
         and all(type(record) is bytes and len(record) == RECORD_BYTES for record in records),
         'exact_two_public_child_records')
    return PAYLOAD_MAGIC + le(VERSION, 16) + le(COUNT, 16) + b''.join(records)


def decode_payload(payload):
    need(type(payload) is bytes and len(payload) == PAYLOAD_BYTES
         and payload[:12] == PAYLOAD_MAGIC + le(VERSION, 16) + le(COUNT, 16),
         'canonical_virtual_payload8108')
    return tuple(payload[12 + RECORD_BYTES * i:12 + RECORD_BYTES * (i + 1)] for i in range(COUNT))


def financial_projection(case):
    """Exact KPX5FB01 codec, independently reconstructible by native opcodes.

    No signature/proof, derived ID, storage mass or compute budget is encoded.
    The included payload has records only, never this journal/hash/outer proof.
    Header rules and profile pricing are checked separately by the consumer.
    """
    body, entry = validate_case(case)
    need(len(body['outputs']) == 1, 'aggregate_exactly_one_native_output')
    inp, out = body['inputs'][0], body['outputs'][0]
    in_spk, out_spk, payload = (hexbytes(entry['scriptPublicKey']),
                              hexbytes(out['scriptPublicKey']), hexbytes(body['payload']))
    return (BODY_MAGIC + le(body['version'], 16) + le(len(body['inputs']), 16)
        + point_bytes(inp['previousOutpoint']) + le(inp['sequence'], 64) + le(entry['amount'], 64)
        + le(len(in_spk), 16) + in_spk + le(len(body['outputs']), 16) + le(out['value'], 64)
        + le(len(out_spk), 16) + out_spk + b'\0' + le(body['lockTime'], 64)
        + hexbytes(body['subnetworkId'], 20) + le(body['gas'], 64) + le(len(payload), 32) + payload)


def encode_journal(wrapper_domain, child_domain, point, prior_state, reserve,
                   next_state, remaining, fee, records, projection):
    need(type(wrapper_domain) is bytes and len(wrapper_domain) == 32
         and type(child_domain) is bytes and len(child_domain) == 32, 'installed_journal_domains')
    state(prior_state, child_domain)
    state(next_state, child_domain)
    encode_payload(records)
    need(type(projection) is bytes and projection.startswith(BODY_MAGIC), 'financial_projection_codec')
    need(type(fee) is int and fee > 0 and reserve == remaining + fee,
         'journal_exact_reserve_fee_equation')
    raw = (JOURNAL_MAGIC + le(VERSION, 16) + wrapper_domain + child_domain + le(COUNT, 16)
        + point_bytes(point) + prior_state + le(reserve, 64) + next_state + le(remaining, 64)
        + le(fee, 64) + h(b''.join(records)) + h(projection))
    need(len(raw) == JOURNAL_BYTES, 'journal424_width')
    return raw


def decode_journal(raw):
    need(type(raw) is bytes and len(raw) == JOURNAL_BYTES and raw[:10] == JOURNAL_MAGIC + le(VERSION, 16)
         and raw[74:76] == le(COUNT, 16), 'canonical_journal424')
    child_domain = raw[42:74]
    state(raw[112:224], child_domain)
    state(raw[232:344], child_domain)
    reserve, remaining, fee = [int.from_bytes(raw[a:a + 8], 'little') for a in (224, 344, 352)]
    need(fee > 0 and reserve == remaining + fee, 'journal_exact_reserve_fee_equation')
    return {'wrapper_domain': raw[10:42], 'child_domain': child_domain,
            'point': {'transactionId': raw[76:108].hex(), 'index': int.from_bytes(raw[108:112], 'little')},
            'prior_state': raw[112:224], 'reserve': reserve, 'next_state': raw[232:344],
            'remaining': remaining, 'fee': fee, 'records_sha256': raw[360:392],
            'financial_projection_sha256': raw[392:424]}


@dataclass(frozen=True)
class InstalledProfile:
    wrapper_domain: bytes
    child: Policy
    # Trusted installed callable, not request-selected source or adjacent hash.
    wrapper_emit: object
    aggregate_budget: int = 1600

    def __post_init__(self):
        need(type(self.wrapper_domain) is bytes and len(self.wrapper_domain) == 32
             and type(self.child) is Policy and callable(self.wrapper_emit), 'installed_wrapper_profile')
        uint(self.aggregate_budget, 16)


def child_case(profile, record):
    need(type(record) is bytes and len(record) == RECORD_BYTES, 'child_record4048')
    payload, proof = record[:CHILD_PAYLOAD_BYTES], record[CHILD_PAYLOAD_BYTES:]
    auth = payload[:528]
    fields = auth_fields(auth, 'compact2', profile.child.domain, profile.child.allow_no_append_exit)
    need(fields['mode'] == 2 and fields['payout'] == 0, 'scheduled_compact_mode2_P0_only')
    redeem = profile.child.redeem(auth[76:188])
    point = {'transactionId': auth[40:72].hex(), 'index': int.from_bytes(auth[72:76], 'little')}
    body = {'version': 1, 'id': '00' * 32,
        'inputs': [{'previousOutpoint': point, 'signatureScript':
            (push(bytes(65)) + push(proof) + push(redeem)).hex(),
            'sequence': (1 << 64) - 1, 'computeBudget': 1600}],
        'outputs': [{'value': fields['remaining'], 'scriptPublicKey':
            p2sh(profile.child.redeem(auth[364:476])), 'covenant': None}],
        'lockTime': 0, 'gas': 0, 'subnetworkId': '00' * 20, 'payload': payload.hex(), 'mass': 0}
    entry = {'amount': fields['reserve'], 'scriptPublicKey': p2sh(redeem),
             'blockDaaScore': 0, 'isCoinbase': False, 'covenantId': None}
    body['mass'] = storage_mass(body, entry)
    body['id'] = transaction_id(body, entry)
    return {'transaction': body, 'entries': [entry]}


def outer_case(profile, head, records, outer_proof=bytes(128)):
    """Construct a candidate; construction is never acceptance or currentness."""
    payload = encode_payload(records)
    need(type(outer_proof) is bytes and len(outer_proof) == 128, 'outer_proof128')
    final = records[-1][:528]
    fields = auth_fields(final, 'compact2', profile.child.domain, profile.child.allow_no_append_exit)
    need(fields['mode'] == 2 and fields['payout'] == 0, 'scheduled_compact_mode2_P0_only')
    current, successor = profile.wrapper_emit(head.state), profile.wrapper_emit(final[364:476])
    body = {'version': 1, 'id': '00' * 32,
        'inputs': [{'previousOutpoint': head.point(), 'signatureScript':
            (push(bytes(65)) + push(outer_proof) + push(current)).hex(),
            'sequence': (1 << 64) - 1, 'computeBudget': profile.aggregate_budget}],
        'outputs': [{'value': fields['remaining'], 'scriptPublicKey': p2sh(successor), 'covenant': None}],
        'lockTime': 0, 'gas': 0, 'subnetworkId': '00' * 20, 'payload': payload.hex(), 'mass': 0}
    entry = {'amount': head.reserve, 'scriptPublicKey': p2sh(current),
             'blockDaaScore': 0, 'isCoinbase': False, 'covenantId': None}
    body['mass'] = storage_mass(body, entry)
    body['id'] = transaction_id(body, entry)
    return {'transaction': body, 'entries': [entry]}


def check_outer(profile, case, head, verifier, require_live=False):
    need(not require_live and head.scope == 'EXTERNALLY_SELECTED_SYNTHETIC_HEAD',
         'accepted_current_wrapper_head_authority_unavailable')
    body, entry = validate_case(case)
    need(body['id'] == transaction_id(body, entry), 'canonical_outer_v1_ID')
    need(body['lockTime'] == body['gas'] == 0 and body['subnetworkId'] == '00' * 20
         and body['inputs'][0]['sequence'] == (1 << 64) - 1, 'outer_native_fixed_header')
    need(len(body['outputs']) == 1 and body['inputs'][0]['previousOutpoint'] == head.point(),
         'outer_actual_point_and_single_output')
    need(entry['amount'] == head.reserve and entry['scriptPublicKey'] == p2sh(profile.wrapper_emit(head.state)),
         'actual_wrapper_context_not_virtual_child_context')
    records = decode_payload(hexbytes(body['payload']))
    current, outcomes, seen, fee = head, [], set(), 0
    for ordinal, record in enumerate(records):
        case_i = child_case(profile, record)
        result = inspect(profile.child, case_i, current, 'compact2', verifier)
        need(result['accepted'], 'child_' + str(ordinal) + '_proof_public_or_profile_invalid')
        nfs = (record[204:236], record[236:268])
        need(not any(nf in seen for nf in nfs), 'cross_child_duplicate_NF')
        seen.update(nfs)
        fee += result['effects']['fee_sompi']
        current = result['successor']
        need(current is not None, 'P0_child_requires_continuation')
        outcomes.append({'sequence': ordinal, 'cryptographic': result['cryptographic'],
                         'virtual_body_id': case_i['transaction']['id'], 'effects': result['effects']})
    need(head.reserve == current.reserve + fee and fee > 0, 'sum_exact_child_fees')
    expected = [{'value': current.reserve, 'scriptPublicKey': p2sh(profile.wrapper_emit(current.state)),
                 'covenant': None}]
    need(body['outputs'] == expected and entry['amount'] - body['outputs'][0]['value'] == fee,
         'outer_exact_native_reserve_fee_and_successor')
    redeem = profile.wrapper_emit(head.state)
    frame = hexbytes(body['inputs'][0]['signatureScript'])
    need(len(frame) == 199 + len(redeem) and frame[:68] == push(bytes(65)) + b'\x4c\x80'
         and frame[196:199] == b'\x4d' + le(len(redeem), 16) and frame[199:] == redeem,
         'outer_canonical_frame_and_selected_wrapper')
    need(body['inputs'][0]['computeBudget'] == profile.aggregate_budget
         and body['mass'] == storage_mass(body, entry) and entry['blockDaaScore'] == 0,
         'outer_selected_budget_storage_synthetic_profile')
    projection = financial_projection(case)
    journal = encode_journal(profile.wrapper_domain, profile.child.domain, head.point(), head.state,
        head.reserve, current.state, current.reserve, fee, records, projection)
    return {'schema': 'kpx5-virtual-P0-host-oracle/v1', 'inner_proofs_and_public_semantics_valid': True,
        'journal_hex424': journal.hex(), 'journal_sha256': h(journal).hex(),
        'financial_projection_sha256': h(projection).hex(), 'payload_sha256': h(hexbytes(body['payload'])).hex(),
        'outer_body_id': body['id'], 'initial_reserve_sompi': head.reserve,
        'final_reserve_sompi': current.reserve, 'actual_outer_fee_sompi': fee, 'children': outcomes,
        'actual_outer_proof_native_VM_acceptance_chain_or_privacy_qualified': False}
