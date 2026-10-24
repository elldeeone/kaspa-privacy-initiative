#!/usr/bin/env python3
"""Finite public two-component joins. No PK, witness, backup or native VM."""
import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'poc/shared-settlement'))
sys.path.insert(0, str(ROOT / 'poc/shared-settlement-verifier'))
from capacity_g16 import verify
from policy import Head, profile
from selected import child_profile


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    folder = ROOT / 'research/next-session/independent-payments/privacy-wallet/public-components-01'
    manifest_raw = (folder / 'MANIFEST.json').read_bytes()
    assert sha(manifest_raw) == '07e32656d86f4e81a8a0dcba96d4c65765d01bc7da277d49f90ab5decb2b4ec4'
    manifest = json.loads(manifest_raw)
    seen = set()
    for row in manifest['files']:
        path = ROOT / row['path']
        assert path.is_relative_to(folder) and row['path'] not in seen
        assert not any(p.is_symlink() for p in (path,*path.parents))
        seen.add(row['path'])
        raw = path.read_bytes()
        assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
    assert len(seen) == 26
    policy, selection = child_profile(ROOT/'poc/shared-settlement-proof/child-profile.json',
        '492a0981ad04891ea68243f2c8221976f436501acf940e42211bb8773744fbdd',
        allow_no_append_exit=True)
    start = json.loads((folder/'public-prestate.json').read_bytes())
    assert start['accepted_chain_backing_currentness_or_GN_claimed'] is False
    head = Head(start['previous_point']['transactionId'],start['previous_point']['index'],
        bytes.fromhex(start['state_hex112']), start['reserve_sompi'], domain=policy.domain)
    reserve = head.reserve
    rows = []
    for i in range(2):
        owner = folder / f'owner-{i}'
        comp = json.loads((owner/'COMPONENT.json').read_bytes())
        draft = json.loads((owner/'public-case.json').read_bytes())
        case = comp['public_case']
        # The separate draft is explicitly the selected pre-ID/proof template.
        reconstructed = copy.deepcopy(case)
        reconstructed['transaction']['id'] = '00' * 32
        reconstructed['transaction']['mass'] = 0
        frame = bytearray.fromhex(reconstructed['transaction']['inputs'][0]['signatureScript'])
        frame[68:196] = bytes(128)
        reconstructed['transaction']['inputs'][0]['signatureScript'] = frame.hex()
        assert draft == reconstructed
        auth = (owner/'proof/authorization528.bin').read_bytes()
        proof = (owner/'proof/proof128.bin').read_bytes()
        vk = (owner/'proof/verification-key.bin').read_bytes()
        report = json.loads((owner/'proof/report.json').read_bytes())
        ready = json.loads((owner/'PARAMETERS-READY.json').read_bytes())
        assert auth.hex() == comp['auth_hex528'] == case['transaction']['payload'][:1056]
        assert proof.hex() == comp['proof_hex128']
        assert bytes.fromhex(case['transaction']['inputs'][0]['signatureScript'])[68:196] == proof
        assert sha(vk) == selection['child_vk_sha256']
        assert report['authorization_sha256'] == sha(auth) and report['proof_sha256'] == sha(proof)
        assert ready == {'event':'parameters-ready','role':'compact2','output_arity':2,
            'domain_hex32':policy.domain.hex(),
            'parameter_manifest_sha256':'d6f0e2bbafab39a72106ef0a0ebd6483362a858926117721a8be5aa37a459011',
            'vk_sha256':sha(vk),
            'compiled_build_identity_sha256':'fcf6e8c757613e6fea9a5dd776727f1c2456865f1185c545ac9751ef9fb26419'}
        crypto = verify('compact2', auth, proof)
        assert crypto['verified'] is True
        actual_profile = profile(case)
        previous = head
        head, effects = policy.apply(case, head, 'compact2')
        assert head is not None and effects['mode'] == 2 and effects['native_payout_sompi'] == 0
        successor = json.loads((owner/'SUCCESSOR.json').read_bytes())
        assert successor['state_hex112'] == head.state.hex() and successor['reserve_sompi'] == head.reserve
        assert successor['previous_point'] == head.point()
        rows.append({'component':i,'authorization_sha256':sha(auth),'proof_sha256':sha(proof),
            'genuine_G16_independently_verified':True,'public_transition_semantics_pass':True,
            'previous_point':previous.point(),'virtual_successor_point':head.point(),**effects})
    assert reserve - head.reserve == sum(row['fee_sompi'] for row in rows) == 18_508_000
    result = {'schema':'independent-public-two-P0-component-join/v1','manifest_sha256':sha(manifest_raw),
        'finite_public_payloads_hashed':len(seen),'child_profile':selection,'results':rows,
        'starting_reserve_sompi':reserve,'final_virtual_reserve_sompi':head.reserve,
        'total_component_fees_sompi':reserve-head.reserve,'all_public_joins_pass':True,
        'final_run_G16_verifications':2,'total_campaign_G16_verifications':3,
        'public_case_json_is_pre_ID_mass_zero_proof_template_component_embeds_actual_case':True,
        'reviewer_harness_corrections':[{'attempt':1,'G16_calls':0,'cause':'draft_is_zero_ID_proof_template_not_final_component'}, {'attempt':2,'G16_calls':1,'cause':'second_draft_also_has_uncommitted_mass_zero_before_normalization'}],'native_VM_or_proving_or_PK_backup_witness_access':False,
        'actual_wrapper_receipt_native_acceptance_chain_backing_currentness_or_privacy_claim':False,
        'source_sha256s':{p:sha((ROOT/p).read_bytes()) for p in (
            'poc/shared-settlement/policy.py','poc/shared-settlement/selected.py',
            'poc/shared-settlement/wire.py','poc/shared-settlement-verifier/capacity_g16.py')}}
    out=ROOT/'research/next-session/independent-payments/review/PRODUCER-PUBLIC-JOINS-01.json'
    assert not out.exists()
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'all_public_joins_pass':True,'independent_actual_G16_checks':2,
        'total_component_fees_sompi':reserve-head.reserve}))

if __name__ == '__main__':
    main()
