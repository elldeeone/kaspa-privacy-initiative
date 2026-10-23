"""Strict public sparse prefix replay; never asserts accepted/current chain state.

The descriptor pin comes from independent client installation/selection, not
from the capsule being checked. Locally supplied contexts remain explicitly
synthetic. Currentness/accepted-chain authority is a separate external operation.
"""
from pathlib import Path

from actions import point_bytes
from native_runtime import DOMAIN, GENESIS, ROOT, encoded, p2sh
from primitives import (MAX, NOTE_FLOOR, PAYOUT_FLOOR, ZERO, fixed, h, insert_nf,
                        need, parse, singleton, u32)

FIELDS = {'schema', 'network_id', 'genesis_hash_hex', 'domain_hex32', 'founding_outpoint',
          'birth_start_hash', 'initial_redeem_hex', 'compact_vk_hex328', 'wide_vk_hex328',
          'immutable_policy_sha256', 'compact_public_params_manifest_sha256',
          'wide_public_params_manifest_sha256'}


def hexbytes(value, width=None):
    need(type(value) is str and len(value) % 2 == 0
         and all(c in '0123456789abcdef' for c in value), 'canonical-public-hex')
    raw = bytes.fromhex(value)
    return raw if width is None else fixed(raw, width)


def descriptor(raw, expected_sha256):
    import hashlib
    data = parse(raw)
    need(type(data) is dict and set(data) == FIELDS, 'strict-descriptor-fields')
    need(hashlib.sha256(encoded(data)).hexdigest() == expected_sha256, 'externally-selected-descriptor-pin')
    need(data['schema'] == 'kpx4-compact-batch-descriptor/v1' and data['network_id'] == 'testnet-10'
         and data['genesis_hash_hex'] == GENESIS and data['domain_hex32'] == DOMAIN.hex(),
         'selected-descriptor-instance')
    point_bytes(data['founding_outpoint'])
    hexbytes(data['birth_start_hash'], 32)
    for key in ('immutable_policy_sha256', 'compact_public_params_manifest_sha256',
                'wide_public_params_manifest_sha256'):
        hexbytes(data[key], 32)
    compact, wide = hexbytes(data['compact_vk_hex328'], 328), hexbytes(data['wide_vk_hex328'], 328)
    need(compact != wide, 'distinct-role-VKs')
    redeem = hexbytes(data['initial_redeem_hex'])
    need(redeem[:2] == b'\x4c\x70' and h(redeem[114:]).hex() == data['immutable_policy_sha256'],
         'descriptor-policy-layout-and-hash')
    return data, compact, wide


def contexts(record):
    need(type(record) is dict and set(record) == {'transaction', 'entries'}
         and type(record['entries']) is list and len(record['entries']) == 1, 'strict-history-record')
    row = record['entries'][0]
    need(set(row) == {'amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'}
         and type(row['amount']) is int and 0 < row['amount'] <= MAX
         and type(row['blockDaaScore']) is int and 0 <= row['blockDaaScore'] < 1 << 64
         and row['isCoinbase'] is False and row['covenantId'] is None, 'strict-native-context')
    hexbytes(row['scriptPublicKey'])
    return [{'amount_sompi': str(row['amount']), 'script_public_key': row['scriptPublicKey'],
             'block_daa_score': str(row['blockDaaScore']), 'is_coinbase': False, 'covenant_id': None}]


def common(body):
    need(type(body) is dict and body['version'] == 1 and len(body['inputs']) == 1
         and body['inputs'][0]['sequence'] == (1 << 64) - 1
         and body['lockTime'] == 0 and body['gas'] == 0 and body['subnetworkId'] == '00' * 20,
         'native-body-metadata')
    for row in body['outputs']:
        need(type(row['value']) is int and 0 < row['value'] <= MAX and row['covenant'] is None,
             'native-output-amount-or-covenant')


def validate_genesis(body, entry, selected, runtime, compact, wide):
    """Ordinary input Full is insufficient: prove strict singleton bootstrap."""
    common(body)
    payload = hexbytes(body['payload'], 536)
    need(payload[:40] == b'KPX2GN01' + DOMAIN, 'GN-magic-domain')
    note, cm, cipher, cipher_hash = payload[40:208], payload[208:240], payload[240:504], payload[504:536]
    value = int.from_bytes(note[64:72], 'little')
    need(NOTE_FLOOR <= value <= MAX and h(b'KPX1NOT\0', DOMAIN, note) == cm
         and h(cipher) == cipher_hash, 'GN-value-CM-cipher')
    snapshot = singleton(DOMAIN, note, cipher)
    redeem = runtime.emit(snapshot.state(DOMAIN), compact, wide)
    need(selected['initial_redeem_hex'] == redeem.hex()
         and selected['founding_outpoint'] == {'transactionId': body['id'], 'index': 0}
         and body['inputs'][0]['computeBudget'] == 10
         and len(body['outputs']) in (1, 2)
         and body['outputs'][0] == {'value': value, 'scriptPublicKey': p2sh(redeem), 'covenant': None},
         'strict-singleton-initial-policy-reserve-outpoint')
    script = hexbytes(entry['script_public_key'], 36)
    need(script[:3] == b'\0\0\x20' and script[-1:] == b'\xac', 'ordinary-GN-source-P2PK')
    if len(body['outputs']) == 2:
        need(body['outputs'][1]['scriptPublicKey'] == entry['script_public_key'], 'ordinary-GN-change-only')
    need(int(entry['amount_sompi']) > sum(row['value'] for row in body['outputs']), 'GN-positive-explicit-fee')
    return snapshot, value, redeem


def advance(snapshot, reserve, previous, redeem, body, entry, runtime, compact, wide):
    common(body)
    payload = hexbytes(body['payload'])
    need(len(payload) >= 2848, 'private-minimum-frame')
    auth = payload[:528]
    need(auth[:40] == b'KPX4AU01' + DOMAIN and auth[40:76] == point_bytes(previous)
         and auth[76:188] == snapshot.state(DOMAIN)
         and int.from_bytes(auth[188:196], 'little') == reserve
         and body['inputs'][0]['previousOutpoint'] == previous
         and body['inputs'][0]['computeBudget'] == 1600
         and int(entry['amount_sompi']) == reserve and entry['script_public_key'] == p2sh(redeem),
         'exact-current-previous-state-reserve-input')
    frame = hexbytes(body['inputs'][0]['signatureScript'])
    need(frame[:66] == b'\x41' + bytes(65) and frame[66:68] == b'\x4c\x80'
         and frame[196:199] == b'\x4d' + len(redeem).to_bytes(2, 'little')
         and frame[199:] == redeem and len(frame) == 199 + len(redeem), 'exact-current-program-frame')
    nfs = [auth[204:236], auth[236:268]]
    after, witness0 = insert_nf(snapshot, nfs[0])
    after, witness1 = insert_nf(after, nfs[1])
    need(payload[528:2848] == witness0 + witness1, 'native-sequential-NF-witnesses')
    mode = auth[300]
    fee, remaining, payout = (int.from_bytes(auth[a:a + 8], 'little') for a in (196, 476, 484))
    need(0 < fee <= MAX and 0 <= payout <= MAX and remaining == reserve - fee - payout
         and (remaining == 0 or NOTE_FLOOR <= remaining <= MAX)
         and (payout == 0 or payout >= PAYOUT_FLOOR), 'exact-reserve-conservation')
    if remaining == 0:
        need(mode == 0 and payout > 0 and len(payload) == 2848 and auth[268:332] == bytes(64)
             and auth[332:364] == h(bytes(528)), 'canonical-terminal-omission')
    else:
        need(mode in (2, 32) and (mode != 32 or payout == 0)
             and len(payload) == {2: 3920, 32: 12672}[mode], 'selected-continuing-mode-frame')
        at = 2848
        cms = [payload[at + 32 * i:at + 32 * (i + 1)] for i in range(mode)]
        at += 32 * mode
        ciphers = [payload[at + 264 * i:at + 264 * (i + 1)] for i in range(mode)]
        at += 264 * mode
        after, start, path = after.append_commitments(cms, ciphers)
        need(auth[268:300] == h(b''.join(cms))
             and auth[300:332] == bytes([mode]) + bytes(3) + u32(start) + bytes(24)
             and auth[332:364] == h(b''.join(ciphers)) and payload[at:] == b''.join(path),
             'exact-ordered-list-cipher-range-and-boundary')
    need(auth[364:476] == after.state(DOMAIN), 'derived-next-state-roots-and-counts')
    outputs = []
    next_redeem = None
    if remaining:
        next_redeem = runtime.emit(after.state(DOMAIN), compact, wide)
        outputs.append({'value': remaining, 'scriptPublicKey': p2sh(next_redeem), 'covenant': None})
    if payout:
        destination = auth[492:528]
        need(destination[:3] == b'\0\0\x20' and destination[-1:] == b'\xac', 'canonical-payout-SPK')
        outputs.append({'value': payout, 'scriptPublicKey': destination.hex(), 'covenant': None})
    else:
        need(auth[492:528] == bytes(36), 'P0-zero-payout-SPK')
    need(body['outputs'] == outputs, 'exact-reserve-and-authorized-native-outputs')
    return after, remaining, next_redeem


def replay(raw_history, selected, expected_descriptor_sha256, runtime, output):
    """Every provided body receives real native Full; currentness remains false."""
    data = parse(raw_history)
    need(type(data) is dict and set(data) == {'schema', 'classification', 'descriptor_sha256', 'records'}
         and data['schema'] == 'kpx4-compact-batch-history/v1'
         and data['classification'] == 'SYNTHETIC_NATIVE_VALID_CONTEXTS_NOT_ACCEPTED'
         and data['descriptor_sha256'] == expected_descriptor_sha256
         and type(data['records']) is list and data['records'], 'strict-local-history-source-scope')
    output = Path(output)
    need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-public-replay-output')
    output.mkdir(parents=True, mode=0o700)
    compact, wide = hexbytes(selected['compact_vk_hex328'], 328), hexbytes(selected['wide_vk_hex328'], 328)
    snapshot, reserve, redeem, previous = None, None, None, None
    native_reports = []
    for ordinal, record in enumerate(data['records']):
        entries = contexts(record)
        body = record['transaction']
        runtime.sdk(body, entries)
        report, metrics = runtime.validate(body, entries, output / f'body-{ordinal:04d}')
        need(body['mass'] == metrics['storage_mass'] and metrics['actual_fee_sompi'] > 0,
             'exact-current-official-storage-mass-and-fee')
        if ordinal == 0:
            snapshot, reserve, redeem = validate_genesis(body, entries[0], selected, runtime, compact, wide)
        else:
            need(reserve > 0 and redeem is not None, 'no-action-after-terminal-prefix')
            expected = data['records'][ordinal - 1]['transaction']['outputs'][0]
            need(entries[0]['amount_sompi'] == str(expected['value'])
                 and entries[0]['script_public_key'] == expected['scriptPublicKey'], 'prior-output-context-link')
            snapshot, reserve, redeem = advance(snapshot, reserve, previous, redeem, body, entries[0],
                                                runtime, compact, wide)
        previous = {'transactionId': body['id'], 'index': 0} if reserve else None
        native_reports.append({'transaction_id': body['id'], 'native_Full_all_engines': True,
                               'fee_sompi': metrics['actual_fee_sompi']})
    return {'snapshot': snapshot, 'reserve_sompi': reserve, 'current_outpoint': previous,
            'current_redeem': redeem, 'last_body': data['records'][-1]['transaction'],
            'native_reports': native_reports, 'currentness_verified': False,
            'accepted_chain_backing_verified': False, 'provided_prefix_validated': True,
            'classification': 'SUPPLIED_SYNTHETIC_CONTEXTS_ONLY'}
