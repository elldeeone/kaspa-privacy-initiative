"""Raw actual-W public replay and sparse receipt reconstruction; never L1 current.

Only constructed S0 is externally selected. Every later CM/CF/NF/head is derived
from exact native cases, not a supplied post-state, label, map or success report.
"""
import copy
from pathlib import Path

from reuse import core, public
import selected as s

HISTORY_SCHEMA = 'kpx5-owner-public-history/v1'
SCOPE = 'CONSTRUCTED_START_AND_SUPPLIED_NATIVE_CASES_NOT_ACCEPTED_OR_CURRENT'


def snapshot_record(snapshot):
    return {'cm_cursor': snapshot.cm_cursor,
        'deliveries': [{'position': row.position, 'cm_hex32': row.cm.hex(),
                        'cipher_hex264': row.ciphertext.hex()} for row in snapshot.deliveries],
        'nullifiers': [{'value_hex32': row.value.hex(), 'next_value_hex32': row.next_value.hex(),
                        'next_index': row.next_index} for row in snapshot.nullifiers]}


def snapshot_input(value):
    c = core(); p = c.primitives; hx = public().wire.hexbytes
    p.need(type(value) is dict and set(value) == {'cm_cursor', 'deliveries', 'nullifiers'}
           and type(value['deliveries']) is list and type(value['nullifiers']) is list, 'strict-initial-public-snapshot')
    deliveries, nfs = [], []
    for row in value['deliveries']:
        p.need(type(row) is dict and set(row) == {'position', 'cm_hex32', 'cipher_hex264'}, 'strict-positioned-CF-record')
        deliveries.append(p.Delivery(row['position'], hx(row['cm_hex32'], 32), hx(row['cipher_hex264'], 264)))
    for row in value['nullifiers']:
        p.need(type(row) is dict and set(row) == {'value_hex32', 'next_value_hex32', 'next_index'},
               'strict-physical-NF-table-record')
        nfs.append(p.NFEntry(hx(row['value_hex32'], 32), hx(row['next_value_hex32'], 32), row['next_index']))
    return p.Snapshot(value['cm_cursor'], tuple(deliveries), tuple(nfs)).verify()


def initial(raw):
    c = core(); p = c.primitives; pub = public()
    p.need(p.h(raw).hex() == s.PRESTATE_SHA, 'externally-selected-initial-public-state-pin')
    value = p.parse(raw)
    fields = {'schema', 'classification', 'child_profile_sha256', 'domain_hex32', 'wrapper_domain_hex32',
        'previous_point', 'previous_point_kind', 'reserve_sompi', 'state_hex112', 'snapshot',
        'accepted_chain_backing_currentness_or_GN_claimed', 'proof_native_PK_or_main_inputs_read'}
    p.need(type(value) is dict and set(value) == fields
           and value['schema'] == 'kpx5-public-constructed-two-owner-prestate/v1'
           and value['classification'] == 'PUBLIC_SYNTHETIC_DO_NOT_FUND_CONSTRUCTED_PRESTATE'
           and value['child_profile_sha256'] == s.PROFILE_SHA and value['domain_hex32'] == s.DOMAIN.hex()
           and value['wrapper_domain_hex32'] == s.WRAPPER_DOMAIN.hex()
           and value['previous_point_kind'] == 'CONSTRUCTED_WRAPPER_HEAD_NOT_ACCEPTED'
           and value['accepted_chain_backing_currentness_or_GN_claimed'] is False
           and value['proof_native_PK_or_main_inputs_read'] is False, 'selected-constructed-prestate-scope')
    snapshot = snapshot_input(value['snapshot'])
    p.need(snapshot.state(s.DOMAIN) == pub.wire.hexbytes(value['state_hex112'], 112), 'initial-state-roots')
    p.amount(value['reserve_sompi']); c.actions.point_bytes(value['previous_point'])
    return snapshot, value['previous_point'], value['reserve_sompi']


def advance(snapshot, reserve, previous, payload):
    c = core(); p = c.primitives; pub = public()
    p.need(type(payload) is bytes and len(payload) in (2848, 3920), 'compact-public-payload-width')
    auth = payload[:528]
    f = pub.policy.auth_fields(auth, 'compact2', s.DOMAIN, allow_no_append_exit=True)
    p.need(auth[40:76] == c.actions.point_bytes(previous) and auth[76:188] == snapshot.state(s.DOMAIN)
           and f['reserve'] == reserve, 'exact-current-point-state-reserve')
    after, w0 = p.insert_nf(snapshot, f['nfs'][0])
    after, w1 = p.insert_nf(after, f['nfs'][1])
    p.need(payload[528:2848] == w0 + w1, 'exact-two-sequential-current-NF-paths')
    if f['mode'] == 2:
        cms = [payload[2848:2880], payload[2880:2912]]
        ciphers = [payload[2912:3176], payload[3176:3440]]
        after, start, path = after.append_commitments(cms, ciphers)
        p.need(start == f['start'] and payload[3440:] == b''.join(path), 'physical-CM-placement-and-boundary')
    else:
        p.need(f['payout'] > 0, 'noappend-requires-positive-payout')
    pub.policy.append_public(f['old'], f['new'], auth, payload, f['mode'], f['start'])
    p.need(after.state(s.DOMAIN) == auth[364:476], 'derived-next-sparse-state')
    return after, f


def child_case(runtime, record, ordinal, output):
    c = core(); p = c.primitives; pub = public()
    p.need(type(record) is bytes and len(record) == 4048, 'selected-child-record-width')
    auth, payload, proof = record[:528], record[:3920], record[3920:]
    f = pub.policy.auth_fields(auth, 'compact2', s.DOMAIN, allow_no_append_exit=True)
    p.need(f['mode'] == 2 and f['payout'] == 0, 'scheduled-mode2-P0-only')
    previous = {'transactionId': auth[40:72].hex(), 'index': int.from_bytes(auth[72:76], 'little')}
    before = b'\x4c\x70' + auth[76:188] + runtime.profile['tail']
    after = b'\x4c\x70' + auth[364:476] + runtime.profile['tail']
    frame = c.native_runtime.push(bytes(65)) + c.native_runtime.push(proof) + c.native_runtime.push(before)
    body = c.native_runtime.tx(previous, [(f['remaining'], c.native_runtime.p2sh(after))], payload, frame, 1600)
    contexts = [c.native_runtime.context(f['reserve'], before)]
    normalized, _ = runtime.normalize(body, contexts, output / ('virtual-ID-' + str(ordinal)))
    p.need(runtime.verify('compact2', auth, proof)['verified'] is True, 'genuine-new-capacity-child-proof-required')
    return normalized, f


def replay(raw_prestate, raw_history, expected_history_sha256, runtime, output):
    c = core(); p = c.primitives; pub = public()
    snapshot, point, reserve = initial(raw_prestate)
    anchor = copy.deepcopy(point)
    p.need(p.h(raw_history).hex() == expected_history_sha256, 'externally-selected-local-history-pin')
    data = p.parse(raw_history)
    p.need(type(data) is dict and set(data) == {'schema', 'classification', 'prestate_sha256', 'records'}
           and data['schema'] == HISTORY_SCHEMA and data['classification'] == SCOPE
           and data['prestate_sha256'] == s.PRESTATE_SHA and type(data['records']) is list and data['records'],
           'complete-new-profile-raw-native-history-required')
    output = Path(output);output.mkdir(parents=True, mode=0o700)
    payouts, operations = [], []
    for index, case in enumerate(data['records']):
        p.need(point is not None and reserve > 0, 'no-body-after-terminal')
        body, entry = pub.wire.validate_case(case)
        payload = pub.wire.hexbytes(body['payload'])
        before_state, before_reserve, before_point = snapshot.state(s.DOMAIN), reserve, point
        redeem = runtime.emit(before_state)
        frame = pub.wire.hexbytes(body['inputs'][0]['signatureScript'])
        p.need(body['inputs'][0]['previousOutpoint'] == point
               and entry['amount'] == reserve and entry['scriptPublicKey'] == c.native_runtime.p2sh(redeem)
               and frame[:68] == c.native_runtime.push(bytes(65)) + b'\x4c\x80'
               and frame[196:199] == b'\x4d' + len(redeem).to_bytes(2, 'little')
               and frame[199:] == redeem and len(frame) == 199 + len(redeem), 'actual-W-current-head-and-context')
        p.need(body['version'] == 1 and body['lockTime'] == body['gas'] == 0
               and body['subnetworkId'] == '00' * 20 and body['inputs'][0]['sequence'] == (1 << 64) - 1
               and body['inputs'][0]['computeBudget'] in ((s.AGGREGATE_BUDGET,)
                   if payload.startswith(b'KPX5VP01') else s.DIRECT_ACCEPTED_BUDGETS)
               and entry['blockDaaScore'] == 0
               and entry['isCoinbase'] is False and entry['covenantId'] is None, 'selected-synthetic-native-header')
        normalized, contexts, metrics = runtime.normalize_case(case, output / ('normalize-' + str(index)))
        p.need(normalized == case, 'exact-canonical-actual-native-ID-and-storage')
        runtime.sdk(body, contexts)
        report, checked = runtime.validate(body, contexts, output / ('Full-' + str(index)))
        p.need(metrics == checked, 'official-public-replay-mass-conformance')
        if payload.startswith(b'KPX5VP01'):
            records = pub.virtual.decode_payload(payload)
            current, fee = point, 0
            for ordinal, record in enumerate(records):
                virtual, f = child_case(runtime, record, ordinal, output / ('W-' + str(index)))
                snapshot, derived = advance(snapshot, reserve, current, record[:3920])
                p.need(derived == f, 'selected-child-effect-conformance')
                reserve, fee = f['remaining'], fee + f['fee']
                current = {'transactionId': virtual['id'], 'index': 0}
            p.need(body['outputs'] == [{'value': reserve,
                   'scriptPublicKey': c.native_runtime.p2sh(runtime.emit(snapshot.state(s.DOMAIN))), 'covenant': None}]
                   and before_reserve == reserve + fee and metrics['actual_fee_sompi'] == fee,
                   'actual-W-exact-final-reserve-and-summed-fees')
            projection = pub.virtual.financial_projection(case)
            pub.virtual.encode_journal(s.WRAPPER_DOMAIN, s.DOMAIN, before_point, before_state,
                before_reserve, snapshot.state(s.DOMAIN), reserve, fee, records, projection)
            kind = 'ACTUAL_W_WITH_TWO_VIRTUAL_CHILDREN'
        else:
            p.need(index > 0 and payload.startswith(b'KPX4AU01'), 'first-required-actual-W-or-supported-private-body')
            snapshot, f = advance(snapshot, reserve, point, payload)
            p.need(runtime.verify('compact2', payload[:528], frame[68:196])['verified'] is True,
                   'genuine-new-capacity-private-proof-required')
            reserve, fee = f['remaining'], f['fee']
            expected = []
            if reserve:
                expected.append({'value': reserve, 'scriptPublicKey':
                    c.native_runtime.p2sh(runtime.emit(snapshot.state(s.DOMAIN))), 'covenant': None})
            if f['payout']:
                expected.append({'value': f['payout'], 'scriptPublicKey': payload[492:528].hex(), 'covenant': None})
            p.need(body['outputs'] == expected and metrics['actual_fee_sompi'] == fee, 'exact-private-W-native-effects')
            if f['payout']:
                payouts.append({'transaction_id': body['id'], 'outpoint': {'transactionId': body['id'],
                    'index': 1 if reserve else 0}, 'amount_sompi': f['payout'],
                    'script_public_key': payload[492:528].hex(), 'auth_hex528': payload[:528].hex()})
            kind = 'ACTUAL_W_PRIVATE_DIRECT'
        point = {'transactionId': body['id'], 'index': 0} if reserve else None
        operations.append({'transaction_id': body['id'], 'kind': kind, 'fee_sompi': fee,
                           'fresh_native_Full_all_engines': report['all_input_engines_accepted'] is True})
    return {'snapshot': snapshot, 'reserve': reserve, 'point': point, 'anchor_point': anchor,
            'payouts': payouts, 'operations': operations, 'provided_public_prefix_validated': True,
            'accepted_chain_backing_verified': False, 'currentness_verified': False, 'spend_authorized': False}
