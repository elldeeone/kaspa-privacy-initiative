#!/usr/bin/env python3
"""Public malformed-body/native codec controls; all proof bytes are invalid.

This does not execute the native VM and cannot establish financial acceptance.
The artificial roots and CVs are for exact frame/effect-boundary testing only.
"""
import argparse
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

SOURCE = Path(__file__).resolve().parent.parent / 'native_case.py'
spec = importlib.util.spec_from_file_location('_kpx7_native_case_controls', SOURCE)
c = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = c
spec.loader.exec_module(c)
w = c._wire


def h(value):
    return hashlib.sha256(value).digest()


def state(n, m, label):
    return b'KPX7ST01' + w.DOMAIN + h(label + b'cm') + n.to_bytes(4, 'little') + h(label + b'nf') + m.to_bytes(4, 'little')


def body_fixture():
    old, new = state(3, 1, b'old'), state(9, 4, b'new')
    raw = bytearray(b'KPX7PB01' + struct.pack('<4H', 1, 3, 6, 0) + w.DOMAIN
                    + h(b'public session') + h(b'public roster') + h(b'public point') + bytes(4)
                    + old + (2_000_000_000).to_bytes(8, 'little') + new
                    + (1_990_000_000).to_bytes(8, 'little') + (10_000_000).to_bytes(8, 'little')
                    + bytes(8) + bytes(32))
    for i in range(3):
        raw.extend(h(b'public NF' + bytes([i])) + bytes([i + 1]) * 64)
    for i in range(6):
        cf = bytes([i + 11]) * 264
        raw.extend(h(b'public CM' + bytes([i])) + bytes([i + 21]) * 64 + cf + h(cf) + bytes(128))
    raw.extend(bytes(3480 + 3072 + 384))
    assert len(raw) == w.BODY_LEN
    return bytes(raw)


def run(codec):
    image, component = bytes([71]) * 32, bytes([81]) * 32
    case, projection, journal, report = c.make_case(codec, body_fixture(), image, component, 3000)
    assert len(projection) == 10973 and len(journal) == 104
    assert report['native_VM_executed'] is False and report['component_G16_or_outer_receipt_verified'] is False
    assert c.project(codec, case, image, component)[1:3] == (projection, journal)
    updated, same, same_journal, _ = c.replace_outer_proof(codec, case, bytes([7]) * 128, image, component)
    assert same == projection and same_journal == journal
    assert updated['transaction']['id'] == case['transaction']['id']
    mutations = []
    def mutate(label, f):
        modified = deepcopy(case)
        f(modified)
        mutations.append((label, modified))
    def payload_byte(value, offset, byte):
        raw = bytearray.fromhex(value['transaction']['payload']);raw[offset] = byte
        value['transaction']['payload'] = raw.hex()
    mutate('version', lambda x: x['transaction'].__setitem__('version', 2))
    mutate('locktime', lambda x: x['transaction'].__setitem__('lockTime', 1))
    mutate('gas', lambda x: x['transaction'].__setitem__('gas', 1))
    mutate('subnetwork', lambda x: x['transaction'].__setitem__('subnetworkId', bytes([1]).hex() + bytes(19).hex()))
    mutate('sequence', lambda x: x['transaction']['inputs'][0].__setitem__('sequence', 0))
    mutate('budget-out-of-u16', lambda x: x['transaction']['inputs'][0].__setitem__('computeBudget', 65536))
    mutate('input-count', lambda x: x['transaction']['inputs'].append(deepcopy(x['transaction']['inputs'][0])))
    mutate('extra-native-payout', lambda x: x['transaction']['outputs'].append(deepcopy(x['transaction']['outputs'][0])))
    mutate('output-amount', lambda x: x['transaction']['outputs'][0].__setitem__('value', 1_989_999_999))
    mutate('entry-amount', lambda x: x['entries'][0].__setitem__('amount', 2_000_000_001))
    mutate('coinbase', lambda x: x['entries'][0].__setitem__('isCoinbase', True))
    mutate('declared-payout', lambda x: payload_byte(x, 396, 1))
    mutate('declared-fee', lambda x: payload_byte(x, 388, 1))
    mutate('prior-state', lambda x: payload_byte(x, 148 + 40, 1))
    mutate('successor-state', lambda x: payload_byte(x, 268 + 40, 1))
    mutate('body-point', lambda x: payload_byte(x, 112, 1))
    mutate('native-point', lambda x: x['transaction']['inputs'][0]['previousOutpoint'].__setitem__('index', 1))
    mutate('old-body-tag', lambda x: payload_byte(x, 3, ord('5')))
    mutate('storage-mass', lambda x: x['transaction'].__setitem__('mass', x['transaction']['mass'] + 1))
    mutate('cached-id', lambda x: x['transaction'].__setitem__('id', bytes(32).hex()))
    def change_spk(x, entry=False):
        row = x['entries'][0] if entry else x['transaction']['outputs'][0]
        raw = bytearray.fromhex(row['scriptPublicKey']);raw[4] ^= 1;row['scriptPublicKey'] = raw.hex()
    mutate('successor-SPK', change_spk)
    mutate('current-SPK', lambda x: change_spk(x, True))
    def change_frame(x, extra=False):
        raw = bytearray.fromhex(x['transaction']['inputs'][0]['signatureScript'])
        if extra: raw.append(0)
        else: raw[0] = 0x4d
        x['transaction']['inputs'][0]['signatureScript'] = raw.hex()
    mutate('proof-push-frame', change_frame)
    mutate('extra-witness', lambda x: change_frame(x, True))
    for label, modified in mutations:
        try: c.project(codec, modified, image, component)
        except ValueError: pass
        else: raise AssertionError('native codec accepted mutation: ' + label)
    for changed_image, changed_component in [(bytes([72])*32, component), (image, bytes([82])*32)]:
        try: c.project(codec, case, changed_image, changed_component)
        except ValueError: pass
        else: raise AssertionError('native codec accepted changed selected parameters')
    try: w.validate_public(projection)
    except w.WireError: pass
    else: raise AssertionError('fixture artificial roots must not validate as a state transition')
    return {'schema': 'kpx7-native-codec-controls/v1',
            'scope': 'UNFUNDED_PUBLIC_FRAME_AND_EFFECTS_CONTROLS_INVALID_COMPONENT_AND_OUTER_PROOFS',
            'canonical_emission_projection_and_mass': True, 'outer_witness_projection_invariance': True,
            'malformed_mutations_rejected': len(mutations), 'changed_parameter_cases_rejected': 2,
            'artificial_state_root_rejected_by_shared_public_transition_check': True,
            'redeem_bytes': len(bytes.fromhex(case['transaction']['inputs'][0]['signatureScript'])) - 133,
            'projection_bytes': len(projection), 'journal_bytes': len(journal),
            'metrics': report['metrics'], 'native_VM_executed': False,
            'genuine_G16_verified': False, 'native_acceptance_or_backing_claimed': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser();p.add_argument('--codec', required=True);p.add_argument('--codec-sha', required=True)
    args = p.parse_args()
    print(json.dumps(run(c.NativeCodec(Path(args.codec), args.codec_sha)), sort_keys=True))
