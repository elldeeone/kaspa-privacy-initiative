#!/usr/bin/env python3
"""Read only exact selected PUBLIC canary proofs, bodies and parameter metadata.

No PK, private witness, backup, fixture regeneration, native VM or prover call.
Actual proof validity is joined to retained native/owner verifier outcomes;
this script does not claim a fresh independent pairing verification.
"""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
EXIT = ROOT / 'research/next-session/independent-payments/exits'
sys.path.insert(0, str(ROOT / 'poc/shared-settlement'))
import policy


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def run():
    roles = {}
    for role in ('compact2', 'wide32'):
        selected = EXIT / 'fresh-parameters-01' / role
        raw = (selected / 'public-parameters.json').read_bytes()
        manifest, report = json.loads(raw), read(selected / 'report.json')
        vk = (selected / 'verification-key.bin').read_bytes()
        assert bytes.fromhex(manifest['vk_hex328']) == vk
        assert sha(vk) == manifest['vk_sha256'] == report['vk_sha256']
        assert len(vk) == 328
        for key in ('constraint_shape', 'queries', 'pk_bytes', 'pk_sha256',
                    'domain_hex32', 'compiled_build_identity_sha256', 'output_arity',
                    'role', 'core_source_identity'):
            assert manifest[key] == report[key]
        shape, query = manifest['constraint_shape'], manifest['queries']
        assert query['a'] == query['b_g1'] == query['b_g2'] == shape['witness_variables'] + 3
        assert query['l'] == shape['witness_variables']
        assert query['h'] == shape['fft_domain_size'] - 1
        assert query['instances_including_one'] == shape['instances_including_one'] == 3
        assert manifest['domain_hex32'] == 'd55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb'
        roles[role] = {'manifest_sha256': sha(raw), 'VK_sha256': sha(vk),
                       'matrix_sha256': shape['matrix_sha256'], 'vk': vk}

    genuine = EXIT / 'genuine-capacity-01'
    results = read(genuine / 'RESULTS.json')
    cases, auths, frames = {}, {}, {}
    for name, proof_name in [('first', 'proof-first'), ('terminal', 'proof-terminal'),
                             ('current-occupied-NF', 'proof-current-occupied-NF')]:
        case = read(genuine / ('native-' + name) / 'validation-case.json')
        native = read(genuine / ('native-' + name) / 'native-validation.json')
        auth = bytes.fromhex(case['transaction']['payload'])[:528]
        frame = bytes.fromhex(case['transaction']['inputs'][0]['signatureScript'])
        selected = genuine / proof_name
        owner = read(selected / 'report.json')
        proof = (selected / 'proof128.bin').read_bytes()
        assert auth == (selected / 'authorization528.bin').read_bytes()
        assert frame[68:196] == proof
        assert sha(auth) == owner['authorization_sha256']
        assert sha(proof) == owner['proof_sha256'] and owner['genuine_Groth16_verified'] is True
        assert owner['parameter_manifest_sha256'] == roles['compact2']['manifest_sha256']
        assert (selected / 'verification-key.bin').read_bytes() == roles['compact2']['vk']
        assert native['isolation'] == 'PASS'
        assert native['Full']['accepted'] is (name != 'current-occupied-NF')
        assert native['all_input_engines_accepted'] is (name != 'current-occupied-NF')
        cases[name], auths[name], frames[name] = case, auth, frame

    first, terminal = cases['first'], cases['terminal']
    a, b = auths['first'], auths['terminal']
    assert terminal['transaction']['inputs'][0]['previousOutpoint'] == {
        'transactionId': first['transaction']['id'], 'index': 0}
    assert b[40:72].hex() == first['transaction']['id'] and int.from_bytes(b[72:76], 'little') == 0
    assert b[76:188] == a[364:476]
    assert terminal['entries'][0]['amount'] == first['transaction']['outputs'][0]['value'] == 1_000_000_000
    assert terminal['entries'][0]['scriptPublicKey'] == first['transaction']['outputs'][0]['scriptPublicKey']
    assert int.from_bytes(b[476:484], 'little') == 0
    assert len(terminal['transaction']['outputs']) == 1
    assert sum(o['value'] for o in first['transaction']['outputs'][1:] + terminal['transaction']['outputs']) == 1_960_000_000
    assert results['native_reserve_before_sompi'] == results['native_payouts_sompi'] + results['all_actual_cashout_fees_sompi'] == 2_000_000_000

    c, duplicate = auths['current-occupied-NF'], cases['current-occupied-NF']
    assert c[40:188] == b[40:188] and c[188:196] == b[188:196]
    assert c[204:236] == a[204:236]
    witness = bytes.fromhex(duplicate['transaction']['payload'])[528:1688]
    assert witness[4:36] == c[204:236]
    index, following_index = int.from_bytes(witness[:4], 'little'), int.from_bytes(witness[68:72], 'little')
    predecessor = policy.nf_leaf(witness[4:36], witness[36:68], following_index)
    assert policy.fold(predecessor, index, policy.parts(witness[72:616], 32), policy.NF_TAG) == c[152:184]

    profile_path = ROOT / 'poc/shared-settlement-proof/child-profile.json'
    profile_raw = profile_path.read_bytes()
    profile = json.loads(profile_raw)
    tail = frames['first'][313:]
    assert bytes.fromhex(profile['child_template_tail_hex']) == tail
    assert sha(tail) == '4ada93d72649bd20ec6b64c97038da08843135920aae131446c1f00dd6aea0d1'
    assert len(tail) == 23518 and tail.count(roles['compact2']['vk']) == 1
    assert bytes.fromhex(profile['child_vk_hex328']) == roles['compact2']['vk']
    assert profile['child_parameter_manifest_sha256'] == roles['compact2']['manifest_sha256']
    assert profile['child_domain_hex32'] != profile['wrapper_domain_hex32']
    assert profile['child_count'] == 2 and profile['child_mode'] == 2 and profile['child_role'] == 'compact2'
    assert profile['journal_bytes'] == 424 and profile['payload_bytes'] == 8108
    for value in roles.values():
        value.pop('vk')
    return {'schema': 'independent-capacity-public-joins/v1',
            'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND_CONSTRUCTED_PRESTATE',
            'all_expected_joins': True, 'roles': roles,
            'proof_Auth_VK_native_case_and_outcomes_joined': 3,
            'actual_successor_point_state_SPK_reserve_joined': True,
            'occupied_real_NF_equals_authenticated_current_predecessor': True,
            'child_profile_sha256': sha(profile_raw), 'child_tail_sha256': sha(tail),
            'new_PK_backup_witness_native_or_prover_reads': False,
            'accepted_history_currentness_privacy_soundness_claimed': False}


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, sort_keys=True))
