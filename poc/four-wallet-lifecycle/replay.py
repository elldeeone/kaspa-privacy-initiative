"""Strict new-profile public W semantics, separate from chain acceptance.

The chain adapter authenticates GN2, accepted-prefix coverage and fresh UTXOs.
This module derives each public effect with selected software. It opens no
backup/PK/network and grants no live spend authority.
"""
import copy
from pathlib import Path

from compat import core, public
from paths import outside


def snapshot_record(snapshot):
    return {'cm_cursor': snapshot.cm_cursor,
        'deliveries': [{'position': row.position, 'cm_hex32': row.cm.hex(),
                        'cipher_hex264': row.ciphertext.hex()} for row in snapshot.deliveries],
        'nullifiers': [{'value_hex32': row.value.hex(), 'next_value_hex32': row.next_value.hex(),
                        'next_index': row.next_index} for row in snapshot.nullifiers]}


def snapshot_input(value):
    c = core(); p = c.primitives; hx = public().wire.hexbytes
    p.need(type(value) is dict and set(value) == {'cm_cursor', 'deliveries', 'nullifiers'}
           and type(value['deliveries']) is list and type(value['nullifiers']) is list,
           'strict-public-snapshot-record')
    deliveries, nullifiers = [], []
    for row in value['deliveries']:
        p.need(type(row) is dict and set(row) == {'position', 'cm_hex32', 'cipher_hex264'},
               'strict-positioned-public-delivery')
        deliveries.append(p.Delivery(row['position'], hx(row['cm_hex32'], 32),
                                     hx(row['cipher_hex264'], 264)))
    for row in value['nullifiers']:
        p.need(type(row) is dict and set(row) == {'value_hex32', 'next_value_hex32', 'next_index'},
               'strict-physical-spentness-table')
        nullifiers.append(p.NFEntry(hx(row['value_hex32'], 32),
                                   hx(row['next_value_hex32'], 32), row['next_index']))
    return p.Snapshot(value['cm_cursor'], tuple(deliveries), tuple(nullifiers)).verify()


def advance(snapshot, reserve, previous, payload, domain):
    c = core(); p = c.primitives; pub = public()
    p.need(type(payload) is bytes and len(payload) in (2848, 3920), 'compact-public-payload-width')
    auth = payload[:528]
    f = pub.policy.auth_fields(auth, 'compact2', domain, allow_no_append_exit=True)
    p.need(auth[40:76] == c.actions.point_bytes(previous)
           and auth[76:188] == snapshot.state(domain) and f['reserve'] == reserve,
           'exact-current-physical-point-state-reserve')
    after, first = p.insert_nf(snapshot, f['nfs'][0])
    after, second = p.insert_nf(after, f['nfs'][1])
    p.need(payload[528:2848] == first + second, 'exact-sequential-current-NF-updates')
    if f['mode'] == 2:
        cms = [payload[2848:2880], payload[2880:2912]]
        ciphers = [payload[2912:3176], payload[3176:3440]]
        after, start, boundary = after.append_commitments(cms, ciphers)
        p.need(start == f['start'] and payload[3440:] == b''.join(boundary),
               'exact-physical-CM-placement-and-empty-boundary')
    else:
        p.need(f['payout'] > 0, 'noappend-requires-positive-native-payout')
    pub.policy.append_public(f['old'], f['new'], auth, payload, f['mode'], f['start'])
    p.need(after.state(domain) == auth[364:476], 'independently-derived-next-state')
    return after, f


def child_case(runtime, record, ordinal, output):
    """Canonical virtual child, never an accepted native source UTXO."""
    c = core(); p = c.primitives; pub = public(); installed = runtime.profile
    p.need(type(record) is bytes and len(record) == 4048, 'exact-child-record-width')
    auth, payload, proof = record[:528], record[:3920], record[3920:]
    f = pub.policy.auth_fields(auth, 'compact2', installed.domain, allow_no_append_exit=True)
    p.need(f['mode'] == 2 and f['payout'] == 0, 'two-scheduled-P0-children-only')
    previous = {'transactionId': auth[40:72].hex(), 'index': int.from_bytes(auth[72:76], 'little')}
    before = b'\x4c\x70' + auth[76:188] + installed.child_template_tail
    after = b'\x4c\x70' + auth[364:476] + installed.child_template_tail
    frame = c.native_runtime.push(bytes(65)) + c.native_runtime.push(proof) + c.native_runtime.push(before)
    body = c.native_runtime.tx(previous, [(f['remaining'], c.native_runtime.p2sh(after))],
                               payload, frame, installed.aggregate_budget)
    # Zero DAA belongs only to this explicitly virtual context.
    contexts = [c.native_runtime.context(f['reserve'], before, daa=0)]
    normalized, _ = runtime.normalize(body, contexts, output / ('virtual-ID-' + str(ordinal)))
    p.need(runtime.verify('compact2', auth, proof)['verified'] is True,
           'selected-current-VK-genuine-child-proof')
    return normalized, f


def replay_cases(initial_snapshot_record, initial_point, initial_reserve, cases, runtime, output):
    """Supplied public-prefix validation; accepted/currentness is caller-owned.

    Initial data must be reconstructed by strict GN2. An empty W prefix is
    legitimate immediately after funding. Direct private fallback can be the
    first W spend; a missing coordinator cannot force cooperative settlement.
    """
    c = core(); p = c.primitives; pub = public(); installed = runtime.profile
    p.fixed(installed.domain); p.fixed(installed.wrapper_domain)
    snapshot = snapshot_input(initial_snapshot_record)
    c.actions.point_bytes(initial_point); p.amount(initial_reserve)
    p.need(initial_reserve >= p.NOTE_FLOOR, 'positive-GN2-reserve-required')
    p.need(type(cases) is list, 'finite-public-W-prefix-list')
    point, anchor = copy.deepcopy(initial_point), copy.deepcopy(initial_point)
    reserve = initial_reserve
    output = outside(output)
    p.need(not output.exists(), 'fresh-public-replay-output')
    output.mkdir(parents=True, mode=0o700)
    payouts, operations = [], []
    for index, case in enumerate(cases):
        p.need(point is not None and reserve > 0, 'no-body-after-terminal-reserve')
        body, entry = pub.wire.validate_case(case)
        payload = pub.wire.hexbytes(body['payload'])
        before_state, before_reserve, before_point = snapshot.state(installed.domain), reserve, point
        redeem = runtime.emit(before_state)
        frame = pub.wire.hexbytes(body['inputs'][0]['signatureScript'])
        p.need(body['inputs'][0]['previousOutpoint'] == point
               and entry['amount'] == reserve
               and entry['scriptPublicKey'] == c.native_runtime.p2sh(redeem)
               and frame[:68] == c.native_runtime.push(bytes(65)) + b'\x4c\x80'
               and frame[196:199] == b'\x4d' + len(redeem).to_bytes(2, 'little')
               and frame[199:] == redeem and len(frame) == 199 + len(redeem),
               'actual-W-current-point-context-and-immutable-program')
        budget = body['inputs'][0]['computeBudget']
        p.need(body['version'] == 1 and body['lockTime'] == body['gas'] == 0
               and body['subnetworkId'] == '00' * 20
               and body['inputs'][0]['sequence'] == (1 << 64) - 1
               and type(budget) is int and 0 <= budget < 1 << 16
               and entry['isCoinbase'] is False and entry['covenantId'] is None,
               'canonical-actual-native-header-and-context')
        normalized, contexts, metrics = runtime.normalize_case(case, output / ('normalize-' + str(index)))
        p.need(normalized == case, 'canonical-official-native-ID-and-mass')
        runtime.sdk(body, contexts)
        report, checked = runtime.validate(body, contexts, output / ('Full-' + str(index)))
        p.need(metrics == checked, 'official-public-replay-mass-conformance')
        if payload.startswith(b'KPX5VP01'):
            records = pub.virtual.decode_payload(payload)
            current, fee = point, 0
            for ordinal, record in enumerate(records):
                virtual, f = child_case(runtime, record, ordinal, output / ('W-' + str(index)))
                snapshot, derived = advance(snapshot, reserve, current, record[:3920], installed.domain)
                p.need(derived == f, 'exact-public-child-effect-conformance')
                reserve, fee = f['remaining'], fee + f['fee']; p.amount(fee)
                current = {'transactionId': virtual['id'], 'index': 0}
            expected = [{'value': reserve, 'scriptPublicKey':
                         c.native_runtime.p2sh(runtime.emit(snapshot.state(installed.domain))), 'covenant': None}]
            p.need(body['outputs'] == expected and before_reserve == reserve + fee
                   and metrics['actual_fee_sompi'] == fee,
                   'actual-W-exact-reserve-and-summed-authorized-fees')
            projection = pub.virtual.financial_projection(case)
            pub.virtual.encode_journal(installed.wrapper_domain, installed.domain, before_point,
                before_state, before_reserve, snapshot.state(installed.domain), reserve,
                fee, records, projection)
            kind = 'ACTUAL_W_TWO_VIRTUAL_CHILDREN'
        else:
            p.need(payload.startswith(b'KPX4AU01'), 'supported-private-actual-W-payload')
            snapshot, f = advance(snapshot, reserve, point, payload, installed.domain)
            p.need(runtime.verify('compact2', payload[:528], frame[68:196])['verified'] is True,
                   'selected-current-VK-genuine-private-proof')
            reserve, fee = f['remaining'], f['fee']
            expected = []
            if reserve:
                expected.append({'value': reserve, 'scriptPublicKey':
                    c.native_runtime.p2sh(runtime.emit(snapshot.state(installed.domain))), 'covenant': None})
            if f['payout']:
                expected.append({'value': f['payout'], 'scriptPublicKey': payload[492:528].hex(), 'covenant': None})
            p.need(body['outputs'] == expected and metrics['actual_fee_sompi'] == fee,
                   'exact-private-W-payout-and-remaining-reserve')
            if f['payout']:
                payouts.append({'transaction_id': body['id'],
                    'outpoint': {'transactionId': body['id'], 'index': 1 if reserve else 0},
                    'amount_sompi': f['payout'], 'script_public_key': payload[492:528].hex(),
                    'auth_hex528': payload[:528].hex()})
            kind = 'ACTUAL_W_PRIVATE_DIRECT'
        point = {'transactionId': body['id'], 'index': 0} if reserve else None
        operations.append({'transaction_id': body['id'], 'kind': kind, 'fee_sompi': fee,
            'fresh_native_Full_all_engines': report['all_input_engines_accepted'] is True})
    return {'snapshot': snapshot, 'reserve': reserve, 'point': point, 'anchor_point': anchor,
        'payouts': payouts, 'operations': operations, 'provided_public_prefix_validated': True,
        'accepted_chain_backing_verified': False, 'currentness_verified': False, 'spend_authorized': False}
