#!/usr/bin/env python3
"""Independent finite PUBLIC recovery packet/actual proof and financial joins.

No private backup/witness, operational plan, PK or new native/proving job.
The selected public G16 verifier runs once on the new known-unsafe canary proof.
"""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / 'research/next-session/independent-payments'
sys.path.insert(0, str(ROOT / 'poc/shared-settlement-verifier'))
from public_g16 import verify


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def inventory(directory, list_name, manifest_name, list_sha, manifest_sha):
    list_path, manifest_path = directory / list_name, directory / manifest_name
    raw_list, raw_manifest = list_path.read_bytes(), manifest_path.read_bytes()
    assert sha(raw_list) == list_sha and sha(raw_manifest) == manifest_sha
    names, selected = raw_list.decode().splitlines(), json.loads(raw_manifest)
    assert len(names) == len(set(names))
    rows = selected['files']
    for row in rows:
        name = row['path']; part = Path(name)
        assert not part.is_absolute() and '..' not in part.parts and part.as_posix() == name
        path = ROOT / name
        assert path.is_file() and not any(p.is_symlink() for p in (path, *path.parents))
        raw = path.read_bytes()
        assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
    assert {row['path'] for row in rows} | {
        str(list_path.relative_to(ROOT)), str(manifest_path.relative_to(ROOT))} == set(names)
    return {'paths': len(names), 'payloads': len(rows), 'bytes': sum(r['bytes'] for r in rows)}


def run():
    software = BASE / 'recovery-software'
    inventories = {
        'software': inventory(software, 'PUBLIC-FILES-SOFTWARE-02.txt', 'PUBLIC-MANIFEST-SOFTWARE-02.json',
            '0721ef28cb50e154bf5e8b01f38fd6d814188ff48991ae6225ba659a82f74c2b',
            'b0bc037eeeff6cd7032c4ae2c65088459f85a3e69390a862971e09c7c7df68e5'),
        'transport': inventory(BASE / 'recovery-transport', 'PUBLIC-FILES.txt', 'MANIFEST.json',
            '42f7ee15dcb6db50031801d6e583344ad316d34329c17cc778d2deacf915a277',
            'aca7ad4551b49566beb029523f6f611040f590598d27c19ecd3471e663f7c193')}
    public = software / 'terminal-proof-HTTPS-01/public-case'
    case = read(public / 'validation-case.json')
    body, entries = case['transaction'], case['entries']
    auth = (public / 'authorization528.bin').read_bytes()
    proof = (public / 'proof128.bin').read_bytes()
    assert bytes.fromhex(body['payload'])[:528] == auth
    assert bytes.fromhex(body['inputs'][0]['signatureScript'])[68:196] == proof
    result = verify('compact2', auth, proof)
    assert result['verified'] is True and result['rust_verifier_executed'] is True
    owner, report = read(public / 'OWNER-RESULT.json'), read(public / 'PROVER-REPORT.json')
    ready, quote = read(public / 'PARAMETERS-READY.json'), read(public / 'QUOTE-SUMMARY.json')
    native, metrics = read(public / 'native-validation.json'), read(public / 'metrics.json')
    aggregate = read(software / 'RESULTS.json')
    terminal = aggregate['public_canary_terminal']
    assert owner['authorization_sha256'] == report['authorization_sha256'] == sha(auth)
    assert owner['proof_sha256'] == report['proof_sha256'] == sha(proof)
    assert owner['quote_id'] == terminal['quote_id'] == quote['quote_id']
    assert report['parameter_manifest_sha256'] == ready['parameter_manifest_sha256'] == 'f27a806928b5c2409d4e4c5428a75deabef6ecf9601b60889667e90363f26043'
    assert report['vk_sha256'] == ready['vk_sha256'] == sha((public / 'verification-key.bin').read_bytes())
    assert report['pk_sha256'] == 'c8d72c6eae9d03ce22e350bb9d0c616fc8e1d2a8b4f2b0d748cc0336726b11a4'
    assert report['pk_bytes'] == 1_307_894_256
    assert native['Full']['accepted'] is True and native['all_input_engines_accepted'] is True
    assert native['isolation'] == 'PASS'
    assert len(body['inputs']) == len(body['outputs']) == len(entries) == 1
    assert entries[0]['amount'] == int.from_bytes(auth[188:196], 'little') == 1_000_000_000
    assert int.from_bytes(auth[476:484], 'little') == 0
    assert body['outputs'][0]['value'] == int.from_bytes(auth[484:492], 'little') == 981_281_800
    assert body['outputs'][0]['scriptPublicKey'] == auth[492:528].hex()
    assert entries[0]['amount'] - body['outputs'][0]['value'] == int.from_bytes(auth[196:204], 'little') == 18_718_200
    assert metrics == quote['metrics'] and metrics['actual_fee_sompi'] == 18_718_200
    assert next(row for row in metrics['quotes'] if row['rate'] == 100)['passes'] is True
    assert terminal['native_source_input_sompi'] == terminal['native_payout_sompi'] + terminal['complete_fee_sompi'] == 1_000_217_300
    assert terminal['complete_fee_sompi'] == terminal['entry_fee_sompi'] + terminal['exit_fee_sompi'] == 18_935_500
    assert terminal['gross_canary_is_not_ten_KAS_net_useful_payment'] is True
    unpack = aggregate['actual_HTTPS_software_restore']
    assert unpack['unpack']['archive_sha256'] == '17654e748f4c03542646af9d782279cc4e1bd040d5bc97eb0493796515632a46'
    assert unpack['unpack']['members_restored'] == 6636
    assert unpack['typed_restore']['files_verified'] == 6633
    assert unpack['exact_selected_prover_sha256'] == result['checker_elf_sha256']
    assert aggregate['limits']['accepted_chain_backing_verified'] is False
    assert aggregate['limits']['currentness_verified'] is False
    assert aggregate['limits']['spend_authorized'] is False
    for row in aggregate['resources_and_cleanup']:
        assert row['cleanup']['manager_state']['MainPID'] == '0'
        assert row['cleanup']['manager_state']['ActiveState'] == 'inactive'
        assert row['cleanup']['kernel_process_count'] is None
    return {'schema': 'independent-recovery-public-joins/v1', 'inventories': inventories,
            'actual_new_public_G16_verified': True, 'actual_native_VM_rerun': False,
            'Auth_proof_ready_quote_effects_exactly_joined': True,
            'gross_liability': 1_000_000_000, 'payout': 981_281_800,
            'entry_fee': 217_300, 'exit_fee': 18_718_200, 'complete_fee': 18_935_500,
            'actual_PK_backup_private_witness_or_operational_plan_read': False,
            'accepted_chain_privacy_new_wrapper_recovery_or_retention_claimed': False}


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, sort_keys=True))
