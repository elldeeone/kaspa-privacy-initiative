#!/usr/bin/env python3
"""Deterministic PUBLIC_SYNTHETIC_DO_NOT_FUND capacity witnesses.

Constructed states exercise actual native/relation boundaries; they are not a
replayed history or accepted backing. No private main material is opened. Every
nominal input secret is a public deterministic fixture and may never be funded.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'poc/compact-batch-lifecycle'))
from actions import Candidate
from primitives import (CM_MAX, NF_MAX, Delivery, NFEntry, Snapshot, ZERO,
                        dummy_nf, fixed, h, insert_nf, need, note_cm, real_nf, u32, u64)
from native_runtime import Runtime, public_case, save

ORIGINAL_DOMAIN = bytes.fromhex('35ee940cae12aec848a773738de04feaef80c17798a686f1d5aa808179584fd6')
PUBLIC = ROOT / 'research/next-session/independent-payments/exits/PUBLIC-INSTANCE.json'
PHASE = ROOT / 'research/next-session/compact-batch'
G = bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
TWO_G = bytes.fromhex('c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
VALUE = 1_000_000_000
FEE = 20_000_000
TAG = b'PUBLIC_SYNTHETIC_DO_NOT_FUND/CAPACITY-EXIT/v1\0'


def sample(domain, label):
    return h(TAG, domain, label.encode())


def note(domain, position, value=VALUE):
    label = str(position) + '/'
    s, k = sample(domain, label + 'owner'), sample(domain, label + 'nullifier')
    incoming, rho = sample(domain, label + 'incoming'), sample(domain, label + 'rho')
    raw = h(b'KPX1OWN\0', domain, s, incoming) + incoming + u64(value) + rho
    raw += h(b'KPX1KEY\0', domain, k) + G
    return raw, s, k


def construct(domain, unspent=2, cm_max=CM_MAX):
    """Full CM tree prefix and real spent-note NFs, constructed not replayed.

    Prior NF indices follow real+dummy insertion order. Linked-list successors
    sort little-endian NF values; table allocation indices are never sorted or
    renumbered. All prior spent notes have corresponding public fixture CMs.
    """
    need(type(unspent) is int and 1 <= unspent <= cm_max, 'positive-unspent-count')
    deliveries, nf_values = [], [ZERO]
    for position in range(cm_max):
        raw, _, key = note(domain, position)
        cm = note_cm(domain, raw)
        deliveries.append(Delivery(position, cm, bytes(264)))
        if position < cm_max - unspent:
            nf_values += [real_nf(domain, key, cm, position),
                          dummy_nf(domain, sample(domain, str(position) + '/dummy-key'),
                                   sample(domain, str(position) + '/dummy-seed'), 1)]
    need(len(nf_values) == len(set(nf_values)), 'public-fixture-no-NF-collision')
    ordered = sorted(range(len(nf_values)), key=lambda i: int.from_bytes(nf_values[i], 'little'))
    rows = [None] * len(nf_values)
    for ordinal, index in enumerate(ordered):
        following = ordered[ordinal + 1] if ordinal + 1 < len(ordered) else 0
        rows[index] = NFEntry(nf_values[index], nf_values[following], following)
    return Snapshot(cm_max, tuple(deliveries), tuple(rows)).verify()


def cashout(domain, before, position, reserve, previous, fee=FEE):
    raw, s, k = note(domain, position)
    cm, _ = before.roots()
    nf0 = real_nf(domain, k, note_cm(domain, raw), position)
    dk = sample(domain, str(position) + '/dummy-key')
    ds = sample(domain, str(position) + '/dummy-seed')
    nf1 = dummy_nf(domain, dk, ds, 1)
    after, first = insert_nf(before, nf0)
    after, second = insert_nf(after, nf1)
    value = int.from_bytes(raw[64:72], 'little')
    payout, remaining = value - fee, reserve - value
    need(payout >= 10_000_000 and remaining >= 0, 'funded-private-conservation')
    destination = b'\0\0\x20' + TWO_G + b'\xac'
    auth = (b'KPX4AU01' + domain + bytes.fromhex(previous['transactionId']) + u32(previous['index'])
            + before.state(domain) + u64(reserve) + u64(fee) + nf0 + nf1 + ZERO + bytes(32)
            + h(bytes(528)) + after.state(domain) + u64(remaining) + u64(payout) + destination)
    fixed(auth, 528)
    inputs = ({'real': True, 'note_hex168': raw.hex(), 's_hex32': s.hex(), 'k_hex32': k.hex(),
               'position': position, 'cm_path_hex': [p.hex() for p in cm.path(position)],
               'dummy_key_hex32': ZERO.hex(), 'dummy_seed_hex32': ZERO.hex()},
              {'real': False, 'note_hex168': bytes(168).hex(), 's_hex32': ZERO.hex(),
               'k_hex32': ZERO.hex(), 'position': 0, 'cm_path_hex': [ZERO.hex()] * 16,
               'dummy_key_hex32': dk.hex(), 'dummy_seed_hex32': ds.hex()})
    return Candidate('compact2', 0, auth, inputs, (bytes(168), bytes(168)), bytes(528), b'',
                     first + second, b'', after, fee, payout, remaining)



def append_fixture(domain, width):
    need(width in (2, 32), 'compact-or-wide-append')
    values = [80_000_000, 70_000_000] if width == 2 else [VALUE]*32
    value = sum(values) + FEE
    source, s, k = note(domain, 1_000_000 + width, value)
    before = Snapshot(1, (Delivery(0, note_cm(domain, source), bytes(264)),),
                      (NFEntry(ZERO, ZERO, 0),)).verify()
    cm, _ = before.roots()
    nf0 = real_nf(domain, k, note_cm(domain, source), 0)
    dk, ds = sample(domain, 'append-dummy-key/'+str(width)), sample(domain, 'append-dummy-seed/'+str(width))
    nf1 = dummy_nf(domain, dk, ds, 1)
    after, first = insert_nf(before, nf0)
    after, second = insert_nf(after, nf1)
    notes = tuple(note(domain, 2_000_000 + width*100 + slot, amount)[0]
                  for slot, amount in enumerate(values))
    ciphertexts = tuple(sample(domain, 'cipher/'+str(width)+'/'+str(i))*8+bytes(8) for i in range(width))
    after, start, path = after.append(domain, notes, ciphertexts)
    commitments = b''.join(note_cm(domain, raw) for raw in notes)
    metadata = bytes([width]) + bytes(3) + u32(start) + bytes(24)
    previous = {'transactionId': sample(domain, 'FAKE-APPEND-PREVIOUS/'+str(width)).hex(), 'index': 0}
    auth = (b'KPX4AU01' + domain + bytes.fromhex(previous['transactionId']) + u32(0)
            + before.state(domain) + u64(value) + u64(FEE) + nf0 + nf1 + h(commitments)
            + metadata + h(b''.join(ciphertexts)) + after.state(domain) + u64(sum(values))
            + u64(0) + bytes(36))
    inputs = ({'real': True, 'note_hex168': source.hex(), 's_hex32': s.hex(), 'k_hex32': k.hex(),
               'position': 0, 'cm_path_hex': [p.hex() for p in cm.path(0)],
               'dummy_key_hex32': ZERO.hex(), 'dummy_seed_hex32': ZERO.hex()},
              {'real': False, 'note_hex168': bytes(168).hex(), 's_hex32': ZERO.hex(),
               'k_hex32': ZERO.hex(), 'position': 0, 'cm_path_hex': [ZERO.hex()]*16,
               'dummy_key_hex32': dk.hex(), 'dummy_seed_hex32': ds.hex()})
    role = 'compact2' if width == 2 else 'wide32'
    return before, Candidate(role, width, auth, inputs, notes, b''.join(ciphertexts), commitments,
                              first+second, b''.join(path), after, FEE, 0, sum(values))


def generate(output):
    output = fresh(output)
    domain = bytes.fromhex(json.loads(PUBLIC.read_bytes())['domain_hex32'])
    previous = {'transactionId': sample(domain, 'FAKE-CAPACITY-PREVIOUS').hex(), 'index':0}
    rows = []
    for unspent, label in ((2, 'capacity-noappend-continuing'), (1, 'capacity-noappend-terminal')):
        before = construct(domain, unspent)
        chosen = cashout(domain, before, CM_MAX-unspent, VALUE*unspent, previous)
        save(output / (label+'.json'), chosen.private_witness())
        rows.append({'label':label, 'role':'compact2', **summary(domain, before, chosen)})
    for width, label in ((2, 'compact-append'), (32, 'wide32-append')):
        before, chosen = append_fixture(domain, width)
        save(output / (label+'.json'), chosen.private_witness())
        rows.append({'label':label, 'role':chosen.role, **summary(domain, before, chosen)})
    save(output / 'FIXTURES.json', {'schema':'kpx-capacity-public-fixtures/v1',
        'classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND', 'cases':rows,
        'raw_requests_or_nominal_secrets_hashed':False, 'new_setup_proof_native_or_network_calls':0})
    print(json.dumps({'cases':len(rows),'setup_proof_native_or_network_calls':0}))


def summary(domain, before, candidate):
    return {'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND_CONSTRUCTED_PRESTATE',
        'domain_hex32': domain.hex(), 'prestate_CM_cursor': before.cm_cursor,
        'prestate_NF_count': len(before.nullifiers), 'poststate_CM_cursor': candidate.after.cm_cursor,
        'poststate_NF_count': len(candidate.after.nullifiers), 'mode': candidate.mode,
        'reserve_before_sompi': int.from_bytes(candidate.auth[188:196], 'little'),
        'reserve_after_sompi': candidate.reserve_after, 'fee_sompi': candidate.fee,
        'payout_sompi': candidate.payout, 'payload_bytes': len(candidate.payload()),
        'native_or_proof_or_accepted_history_claimed': False}


def fresh(path):
    path = path.absolute()
    need(not path.is_relative_to(ROOT) and not path.exists(), 'fresh-output-outside-Git')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'output-symlink')
    path.mkdir(parents=True, mode=0o700)
    return path


def validate_raw(runtime, candidate, previous, reserve, compact, wide, output, proof=bytes(128)):
    body, entries = runtime.body(candidate, previous, reserve, compact, wide, proof)
    body, metrics = runtime.normalize(body, entries, output / 'normalized')
    runtime.sdk(body, entries)
    case = output / 'case.json'
    save(case, public_case(body, entries))
    runtime.native.run(['validate-transaction', case, output / 'native'])
    report = json.loads((output / 'native/native-validation.json').read_bytes())
    engines = report['per_input_ScriptEngine']
    need(report['isolation'] == 'PASS' and len(engines) == 1, 'native-engine-coverage')
    return body, entries, metrics, report



def zero_native(output):
    from native_selected import CapacityRuntime
    output = fresh(output)
    runtime = CapacityRuntime()
    domain = runtime.domain
    # Explicit public placeholders from old domain. They only permit testing the
    # final zero-proof rejection seam; no old parameter authorizes this domain.
    compact = (PHASE / 'prover/setup-compact2-01/result/verification-key.bin').read_bytes()
    wide = (PHASE / 'prover/setup-wide32-01/result/verification-key.bin').read_bytes()
    previous = {'transactionId':sample(domain,'FAKE-CAPACITY-PREVIOUS').hex(), 'index':0}
    results=[]
    for unspent,label in ((2,'capacity-noappend-continuing'),(1,'capacity-noappend-terminal')):
        before=construct(domain,unspent)
        candidate=cashout(domain,before,CM_MAX-unspent,VALUE*unspent,previous)
        body,_,metrics,report=validate_raw(runtime,candidate,previous,VALUE*unspent,compact,wide,output/label)
        engine=report['per_input_ScriptEngine'][0]
        need(engine['accepted'] is False and engine['typed_error']=='ZkIntegrity("ARK serialization error: the input buffer contained invalid data")'
             and engine['units']>=14_750_000,'all-native-public-noappend-gates-pass-before-G16')
        results.append({**summary(domain,before,candidate),'case':label,
            'native_Full_accepted':False,'expected_final_zero_proof_G16_rejection':True,
            'engine_units':engine['units'],'engine_typed_error':engine['typed_error'],
            'transaction_id':body['id'],'metrics':metrics,'actual_native_validation_calls':1})
    for width,label in ((2,'compact-append'),(32,'wide32-append')):
        before,candidate=append_fixture(domain,width)
        point={'transactionId':candidate.auth[40:72].hex(),'index':0}
        reserve=int.from_bytes(candidate.auth[188:196],'little')
        body,_,metrics,report=validate_raw(runtime,candidate,point,reserve,compact,wide,output/label)
        engine=report['per_input_ScriptEngine'][0]
        need(engine['accepted'] is False and engine['typed_error']=='ZkIntegrity("ARK serialization error: the input buffer contained invalid data")'
             and engine['units']>=14_750_000,'ordinary-append-regression-final-G16-seam')
        results.append({**summary(domain,before,candidate),'case':label,
            'native_Full_accepted':False,'expected_final_zero_proof_G16_rejection':True,
            'engine_units':engine['units'],'engine_typed_error':engine['typed_error'],
            'transaction_id':body['id'],'metrics':metrics,'actual_native_validation_calls':1})
    result={'schema':'kpx-capacity-new-native-public-boundaries/v1',
        'classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND_ZERO_PROOFS_PLACEHOLDER_OLD_VKS',
        'cases':results,'actual_native_validation_calls':len(results),'new_proofs_or_PK_reads':0,
        'genuine_financial_positive_or_chain_or_privacy_claimed':False}
    save(output/'RESULTS.json',result)
    print(json.dumps(result,sort_keys=True))


def baseline(output):
    output = fresh(output)
    runtime = Runtime()
    compact = (PHASE / 'prover/setup-compact2-01/result/verification-key.bin').read_bytes()
    wide = (PHASE / 'prover/setup-wide32-01/result/verification-key.bin').read_bytes()
    point = {'transactionId': sample(ORIGINAL_DOMAIN, 'FAKE-PREVIOUS-DO-NOT-FUND').hex(), 'index': 0}
    results = []
    for unspent, label in ((2, 'nonterminal-noappend-blocked'), (1, 'terminal-zero-proof-G16-seam')):
        before = construct(ORIGINAL_DOMAIN, unspent)
        candidate = cashout(ORIGINAL_DOMAIN, before, CM_MAX-unspent, VALUE*unspent, point)
        body, _, metrics, report = validate_raw(runtime, candidate, point, VALUE*unspent,
                                               compact, wide, output / label)
        engine = report['per_input_ScriptEngine'][0]
        error = engine['typed_error']
        need(report['Full']['accepted'] is False and engine['accepted'] is False, 'baseline-must-reject')
        if unspent == 1:
            need(error == 'ZkIntegrity("ARK serialization error: the input buffer contained invalid data")'
                 and engine['units'] >= 14_750_000, 'terminal-reaches-final-G16-seam')
        else:
            need(not error.startswith('ZkIntegrity') and engine['units'] < 14_750_000,
                 'nonterminal-blocked-before-private-verification')
        results.append({**summary(ORIGINAL_DOMAIN, before, candidate), 'case': label,
            'transaction_id': body['id'], 'native_Full_accepted': False,
            'typed_error': report['Full']['typed_error'], 'engine_typed_error': error,
            'engine_units': engine['units'], 'actual_native_validation_calls': 1,
            'official_SDK_roundtrip': True, 'metrics': metrics,
            'expected_boundary_confirmed': True})
    report = {'schema':'kpx-capacity-original-policy-boundary/v1',
        'classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND_CONSTRUCTED_PRESTATES',
        'cases':results, 'actual_native_validation_calls':len(results), 'new_proofs_or_PK_reads':0,
        'full_history_or_chain_currentness_or_fee_or_privacy_qualification':False}
    save(output / 'RESULTS.json', report)
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['baseline', 'generate', 'zero-native'])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    {'baseline':baseline,'generate':generate,'zero-native':zero_native}[args.operation](args.output)
