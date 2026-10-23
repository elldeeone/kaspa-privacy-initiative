#!/usr/bin/env python3
"""C-only exact disclosure screen. No RPC, private witness, actor or invoice input."""
import argparse
import hashlib
import hmac
import json
from pathlib import Path

MAX = 2_870_000_000_000_000_000
MIN_NOTE = 60_000_000


class Invalid(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def hx(value, length=None):
    require(type(value) is str, 'hex type')
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise Invalid('hex encoding') from None
    require(raw.hex() == value and (length is None or len(raw) == length), 'canonical hex width')
    return raw


def amount(value):
    require(type(value) in (str, int) and type(value) is not bool, 'integer sompi')
    if type(value) is str:
        require(value == str(int(value)) and value.isdigit(), 'canonical integer')
    value = int(value)
    require(0 <= value <= MAX, 'sompi range')
    return value


def u32(raw):
    require(len(raw) == 4, 'u32 width')
    return int.from_bytes(raw, 'little')


def u64(raw):
    require(len(raw) == 8, 'u64 width')
    return amount(int.from_bytes(raw, 'little'))


def cm(domain, note):
    require(len(note) == 168, 'Note168 width')
    return hashlib.sha256(b'KPX1NOT\0' + domain + note).digest()


def merge_intervals(intervals):
    result = []
    for low, high in sorted(intervals):
        if result and low <= result[-1][1] + 1:
            result[-1][1] = max(high, result[-1][1])
        else:
            result.append([low, high])
    return result


def necessary_slot_bounds(known_values, fee):
    """Arithmetic outer relaxation, NOT alternate cryptographic witness existence."""
    require(1 <= len(known_values) <= 2, 'bounded pilot note set')
    totals = []
    intervals = []
    for mask in range(1, 1 << len(known_values)):
        total = sum(value for i, value in enumerate(known_values) if mask & (1 << i)) - fee
        if total < MIN_NOTE:
            continue
        totals.append(total)
        # One padded zero output or two positive outputs, fixed two-slot shape.
        intervals.extend([(0, 0), (total, total)])
        if total >= 2 * MIN_NOTE:
            intervals.append((MIN_NOTE, total - MIN_NOTE))
    return {'possible_input_subset_output_totals_sompi': sorted(set(totals)),
            'necessary_slot_value_intervals_sompi': merge_intervals(intervals),
            'classification': 'ARITHMETIC_OUTER_RELAXATION_NOT_PROOF_WITNESS_ALTERNATIVES',
            'probabilities_assigned': False}


def analyze(dataset):
    require(set(dataset) == {'schema', 'observer', 'classification', 'transactions'}, 'C input fields')
    require(dataset['schema'] == 'kpx2-public-chain-observer/v1'
            and dataset['observer'] == 'C'
            and dataset['classification'] in ('ACTUAL_TN10_KNOWN_PILOT_NOT_BLIND_QUALIFICATION',
                                               'SYNTHETIC_SHAPE_ONLY_NOT_NATIVE_ACCEPTED'),
            'C input schema')
    rows = dataset['transactions']
    require(type(rows) is list and len(rows) == 6, 'finite known pilot')
    domains = []
    for row in rows:
        require(set(row) == {'ordinal', 'body', 'accepted_input_contexts', 'accepting_header'},
                'actor/semantic metadata not accepted')
        body = row['body']
        require(set(body) == {'version', 'id', 'inputs', 'outputs', 'lockTime', 'subnetworkId',
                              'gas', 'payload', 'storageMass'}, 'canonical body fields')
        payload = hx(body['payload'])
        if payload[:8] in (b'KPX2AD01', b'KPX2AU01'):
            domains.append(payload[8:40])
    require(domains and all(d == domains[0] and len(d) == 32 for d in domains), 'common domain')
    domain = domains[0]
    known_notes = {}
    output_positions = {}
    private_outputs = []
    public_openings = []
    revealed = []
    payment_horizon = None
    outputs_by_point = {}
    seen_ids = set()
    for ordinal, row in enumerate(rows):
        require(row['ordinal'] == ordinal, 'public chain order')
        body = row['body']
        require(body['version'] == 1 and body['id'] not in seen_ids, 'version/id')
        hx(body['id'], 32)
        seen_ids.add(body['id'])
        payload = hx(body['payload'])
        require(len(row['accepted_input_contexts']) == len(body['inputs']), 'input context count')
        for inp, supplied in zip(body['inputs'], row['accepted_input_contexts']):
            point = inp['previousOutpoint']
            require(supplied['outpoint'] == point and supplied['is_coinbase'] is False
                    and supplied['covenant_id'] is None, 'accepted supplied context')
            amount(supplied['amount_sompi'])
            require(hx(supplied['script_public_key'])[:2] == b'\0\0', 'SPK version')
            previous = outputs_by_point.get((point['transactionId'], point['index']))
            if previous:
                require(amount(previous['value']) == amount(supplied['amount_sompi'])
                        and previous['scriptPublicKey'] == supplied['script_public_key'], 'public prior output link')
        for index, output in enumerate(body['outputs']):
            amount(output['value'])
            require(hx(output['scriptPublicKey'])[:2] == b'\0\0' and output['covenant'] is None,
                    'public native output')
            outputs_by_point[(body['id'], index)] = output
        if payload[:8] == b'KPX2GN01':
            require(len(payload) == 536 and payload[8:40] == domain, 'founding payload width/domain')
            note = payload[40:208]
            require(cm(domain, note) == payload[208:240], 'founding CM')
            require(hashlib.sha256(payload[240:504]).digest() == payload[504:536], 'founding ciphertext binding')
            known_notes[0] = note
            public_openings.append({'position': 0, 'commitment': cm(domain, note).hex(),
                                    'native_pk': note[136:168].hex()})
        elif payload[:8] == b'KPX2AD01':
            require(len(payload) == 1344 and payload[8:40] == domain, 'admit width/domain')
            note = payload[40:208]
            require(cm(domain, note) == payload[208:240], 'admit CM')
            require(hashlib.sha256(payload[240:504]).digest() == payload[504:536], 'admit ciphertext binding')
            state = payload[1048:1160]
            require(state[:8] == b'KPX2ST01' and state[8:40] == domain, 'admit state')
            position = u32(state[72:76]) - 1
            known_notes[position] = note
            public_openings.append({'position': position, 'commitment': cm(domain, note).hex(),
                                    'native_pk': note[136:168].hex()})
        elif payload[:8] == b'KPX2AU01':
            require(len(payload) == 4356 and payload[8:40] == domain, 'private width/domain')
            require(payload[76:84] == b'KPX2ST01' and payload[84:116] == domain, 'private prior state')
            start = u32(payload[148:152])
            require(start == len(known_notes) == 2, 'known pilot previous public CM count')
            fee = u64(payload[196:204])
            require(hashlib.sha256(payload[484:1012]).digest() == payload[332:364], 'private ciphertext binding')
            payment_horizon = necessary_slot_bounds([u64(n[64:72]) for n in known_notes.values()], fee)
            for slot in range(2):
                commitment = payload[268 + 32 * slot:300 + 32 * slot]
                target = {'creation_txid': body['id'], 'slot': slot, 'position': start + slot,
                          'commitment': commitment.hex()}
                private_outputs.append(target)
                output_positions[start + slot] = target
        elif payload[:8] == b'KPX2RV01':
            require(len(payload) == 2029 and payload[8] == 1, 'reveal width/mode')
            note = payload[9:113] + payload[181:213] + payload[145:177]
            commitment = cm(domain, note)
            key = payload[113:145]
            require(hashlib.sha256(b'KPX1KEY\0' + domain + key).digest() == payload[181:213], 'revealing K')
            require(commitment == payload[213:245], 'revealing CM')
            position = u32(payload[177:181])
            nf = hmac.digest(key, b'KPX1NF\0\0' + domain + commitment + payload[177:181], 'sha256')
            require(nf == payload[1917:1949], 'original positioned NF')
            value, fee, payout = (u64(payload[a:a + 8]) for a in (73, 2013, 2021))
            require(value >= MIN_NOTE and value == fee + payout, 'revealing exact amount')
            script = (b'\0\0\x20' + payload[145:177] + b'\xac').hex()
            matches = [(i, o) for i, o in enumerate(body['outputs']) if o['scriptPublicKey'] == script]
            require(len(matches) == 1 and amount(matches[0][1]['value']) == payout, 'exact native payout')
            target = output_positions.get(position)
            if target:
                require(target['commitment'] == commitment.hex(), 'positioned historical CM match')
                revealed.append(dict(target, reveal_txid=body['id'],
                    exact_historical_note_value_sompi=value, native_fee_sompi=fee,
                    native_payout_sompi=payout, payout_output_index=matches[0][0],
                    payout_script_public_key=script,
                    forced_relation='PRIVATE_OUTPUT_CM_EQUALS_PUBLIC_REVEAL_CM_AND_POSITION'))
    require(len(private_outputs) == 2 and len(revealed) == 2, 'known pilot target coverage')
    return {'classification': ('ACTUAL_CHAIN_DESCRIPTIVE_CANARY_NOT_32_ROLE_QUALIFICATION'
        if dataset['classification'] == 'ACTUAL_TN10_KNOWN_PILOT_NOT_BLIND_QUALIFICATION'
        else 'SYNTHETIC_SHAPE_CONTROL_NOT_NATIVE_ACCEPTED'),
        'observer': 'C', 'transactions_read': len(rows), 'private_output_targets': private_outputs,
        'payment_horizon': payment_horizon, 'after_complete_cashout': {
            'exact_private_output_note_values': len(revealed), 'forced_note_to_payout_links': len(revealed),
            'targets': revealed},
        'note_native_pk_equality_matches_to_ingress': [
            {'ingress_position': opening['position'], 'reveal_creation_position': target['position']}
            for opening in public_openings for target in revealed
            if (b'\0\0\x20' + hx(opening['native_pk'], 32) + b'\xac').hex() == target['payout_script_public_key']],
        'human_identities_inferred': False, 'invoice_directory_supplied': False,
        'proof_or_signature_reverified_here': False,
        'statistical_qualification': False,
        'preserved_prior_amount_floor': {'successes': 21103, 'denominator': 100025,
                                         'adopted_gate_percent': 20, 'status': 'FAIL_UNCHANGED'},
        'limitations': ['Accepted-chain premise is source-pinned trusted-node evidence.',
            'Arithmetic bounds omit hidden hash/PRF witness relations and are only an outer relaxation.',
            'A note value is a payment amount only under the separately declared direct-note pilot semantics.',
            'Output-to-payout script linkage is not a human-identity inference.',
            'No C+P/C+P+A/I or representative population qualification.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise Invalid('fresh output required')
    result = analyze(json.loads(args.input.read_bytes()))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
