#!/usr/bin/env python3
"""One new-profile Original signs only its own ordinary funding input(s).

Invoked inside an admitted one-owner, network-off namespace. Reuses the stock
SDK/native quote/signing backend; never routes the new backup through a legacy
wallet seed parser or KDF. No network or broadcast operation exists here.
"""
import argparse
import copy
import hashlib
import os
from pathlib import Path
import sys
import uuid

import genesis
import private_worker as boundary
import wallet_history
import wallet_profile as wallet

HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE.parent / 'bootstrap'))
from gn3_runtime import Runtime  # Generic public SDK/Native tools, not its legacy wallet loader.

need, read, write, parse, encoded = boundary.need, boundary.read, boundary.write, boundary.parse, boundary.encoded
fields, hx = wallet_history.fields, wallet_history.hx


def decimal_boundary(value):
    need(type(value) is str and value.isascii() and value.isdecimal()
         and (value == '0' or not value.startswith('0')), 'funding-canonical-RPC-decimal-boundary')
    return genesis.uint(int(value))


def mature_sources(value, identity, trial_id, component, own_script):
    fields(value, ('schema', 'network_id', 'genesis_hash_hex', 'domain_hex32', 'profile_id_hex32',
        'pool_lineage_hex32', 'service_policy_hex32', 'trial_id', 'owner_component',
        'funding_script_public_key', 'virtual_daa_score', 'sources'))
    need(value['schema'] == 'kpb-own-mature-coinbase-observation/v1'
         and value['network_id'] == 'testnet-10' and value['genesis_hash_hex'] == identity[0].hex()
         and value['domain_hex32'] == identity[3].hex() and value['profile_id_hex32'] == identity[2].hex()
         and value['pool_lineage_hex32'] == identity[1].hex() and value['service_policy_hex32'] == identity[4].hex()
         and value['trial_id'] == trial_id and type(value['owner_component']) is int
         and value['owner_component'] == component and value['funding_script_public_key'] == own_script,
         'funding-exact-new-profile-own-mining-observation')
    current = decimal_boundary(value['virtual_daa_score'])
    need(type(value['sources']) is list and value['sources'], 'funding-positive-own-source-set')
    chosen, seen, total = copy.deepcopy(value['sources']), set(), 0
    for row in chosen:
        fields(row, ('outpoint', 'entry')); fields(row['outpoint'], ('transactionId', 'index'))
        point = row['outpoint']; hx(point['transactionId'], 32); genesis.uint(point['index'], 32)
        marker = (point['transactionId'], point['index'])
        need(marker not in seen, 'funding-distinct-own-coinbase-points'); seen.add(marker)
        entry = row['entry']; fields(entry, ('amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'))
        entry['amount'], entry['blockDaaScore'] = decimal_boundary(entry['amount']), decimal_boundary(entry['blockDaaScore'])
        genesis.amount(entry['amount'])
        need(entry['scriptPublicKey'] == own_script and entry['isCoinbase'] is True and entry['covenantId'] is None
             and current >= entry['blockDaaScore'] + 1000, 'funding-own-mature-coinbase1000')
        total += entry['amount']
    genesis.amount(total)
    return chosen, total


def selected_runtime():
    info = Path('/original/BACKUP.json').lstat()
    forbidden = ((info.st_dev, info.st_ino),)
    return Runtime(paths={'crypto': '/runtime/crypto', 'node': '/runtime/node',
        'native-validator': '/runtime/native-validator'}, sdk_dir='/runtime/sdk', forbidden=forbidden)


def own_public(config, profile):
    value = parse(read('/initial/PUBLIC.json', config['initial_public_sha256']))
    fields(value, ('schema', 'domain_hex32', 'profile_id_hex32', 'output_hex520', 'admission_sompi',
        'funding_spk_hex36', 'original_backup_schema', 'kdf_tag_ascii8', 'public_known_seed_used',
        'funding_or_native_acceptance'))
    need(value['schema'] == 'kpb-fresh-owner-initial-public/v1'
         and value['domain_hex32'] == profile.domain.hex() and value['profile_id_hex32'] == profile.profile_id.hex()
         and type(value['admission_sompi']) is int and value['admission_sompi'] == genesis.ADMISSION
         and value['original_backup_schema'] == boundary.BACKUP_SCHEMA and value['kdf_tag_ascii8'] == boundary.KDF_TAG
         and value['public_known_seed_used'] is False and value['funding_or_native_acceptance'] is False,
         'funding-explicit-new-Original-public-record')
    hx(value['output_hex520'], 520)
    script = hx(value['funding_spk_hex36'], 36)
    need(script[:3] == b'\0\0\x20' and script[-1:] == b'\xac', 'funding-own-original-P2PK')
    return value


def original_receiver(profile, authority):
    # The strict new-version loader is the sole backup read. Runtime's legacy
    # Receiver and the old sign/fund workers are never invoked.
    seed = boundary.load_backup('/original/BACKUP.json', profile)
    return wallet.Receiver(seed, profile, wallet.Crypto('/runtime/crypto'), authority)


def consolidate(config, profile, initial, authority):
    observation = parse(read('/inputs/OBSERVATION.json', config['observation_sha256']))
    chosen, total = mature_sources(observation, genesis.EXPECTED_IDENTITY, config['trial_id'],
                                   config['owner_component'], initial['funding_spk_hex36'])
    runtime = selected_runtime()
    rate = genesis.amount(config['fee_rate_sompi_per_mass'])
    fee, seen, index = 1, set(), 0
    while True:
        need(fee not in seen, 'funding-no-exact-consolidation-fee-fixed-point'); seen.add(fee)
        payout = total - fee
        need(payout >= 2_100_000_000, 'funding-ordinary-self-output-admission-headroom')
        payload = b'KPBAMF01' + profile.domain + uuid.UUID(config['trial_id']).bytes + genesis.EXPECTED_IDENTITY[1]
        case = {'transaction': {'version': 1, 'id': '00' * 32,
            'inputs': [{'previousOutpoint': row['outpoint'], 'signatureScript': '41' + '00' * 64 + '01',
                'sequence': (1 << 64) - 1, 'computeBudget': 10} for row in chosen],
            'outputs': [{'value': payout, 'scriptPublicKey': initial['funding_spk_hex36'], 'covenant': None}],
            'lockTime': 0, 'subnetworkId': '00' * 20, 'gas': 0, 'payload': payload.hex(), 'mass': 0},
            'entries': [row['entry'] for row in chosen]}
        case, metrics = runtime.normalize(case, Path('/owner') / ('quote-' + str(index)))
        required = genesis.amount(genesis.uint(metrics['mining_mass']) * rate)
        if required == fee: break
        fee, index = required, index + 1
    body, contexts = runtime.sdk_body(case)
    request = {'schema': 'kpb-offline-own-mined-consolidation/v1', 'network_id': 'testnet-10',
        'genesis_hash_hex': genesis.EXPECTED_IDENTITY[0].hex(), 'operation': 'roundtrip',
        'transaction': body, 'contexts': contexts}
    # The established consolidation helper accepts an arbitrary positive
    # number of mature coinbase inputs. GEN3's sdk.mjs deliberately requires
    # exactly three ordinary inputs and cannot sign this earlier transaction.
    helper = HERE / 'consolidation_sdk.mjs'
    reply = parse(runtime.executables['node'].run([helper, runtime.sdk_dir], request).stdout)
    need(reply['lossless_safe_roundtrip'] is True and reply['network_or_broadcast'] is False,
         'funding-official-consolidation-SDK-roundtrip')
    receiver = original_receiver(profile, authority)
    key = receiver.keys(0xffffffff)
    need(initial['funding_spk_hex36'] == (b'\0\0\x20' + key.invoice.native_pk + b'\xac').hex(),
         'funding-new-KDF-own-reserved-native-key')
    # All inputs are independently checked as this same owner's matured P2PK.
    reply = parse(runtime.executables['node'].run([helper, runtime.sdk_dir],
        {**request, 'operation': 'sign-all', 'funding_secret_hex32': key.native_secret.hex()}).stdout)
    signatures = reply['signature_scripts_hex66']
    need(reply['secret_material_emitted'] is False and reply['network_or_broadcast'] is False
         and type(signatures) is list and len(signatures) == len(chosen), 'funding-own-consolidation-signatures-only')
    for row, signature in zip(case['transaction']['inputs'], signatures):
        raw = hx(signature, 66)
        need(raw[:1] == b'\x41' and raw[-1:] == b'\x01', 'funding-own-consolidation-SIGHASH-ALL')
        row['signatureScript'] = signature
    actual, actual_metrics = runtime.normalize(case, Path('/owner/signed-normalization'))
    need(actual == case and actual_metrics == metrics, 'funding-signed-exact-consolidation-body-fee-ID')
    runtime.validate(case, Path('/owner/native-Full'))
    case_sha = hashlib.sha256(encoded(case)).hexdigest()
    write('/out/CASE.json', case, 0o400)
    return {'schema': 'kpb-own-ordinary-consolidation/v1', 'trial_id': config['trial_id'],
        'owner_component': config['owner_component'], 'observation_sha256': config['observation_sha256'],
        'case_sha256': case_sha, 'source_amount_sompi': total, 'ordinary_self_output_sompi': payout,
        'fee_sompi': fee, 'native_Full_and_all_inputs_passed': True,
        'network_or_broadcast': False, 'controller_private_Original_or_key_read': False}


def approve_genesis(config, profile, initial, authority):
    verifier = genesis.NamespaceGenesisVerifier(profile, '/runtime/prover', config['binary_sha256'],
        '/parameters/OUTPUT-MANIFEST.json', config['output_manifest_sha256'], read_public=read)
    selected = genesis.Selection.from_component(read('/component/PROFILE.json', config['component_profile_sha256']),
        config['component_profile_sha256'], read('/component/IMMUTABLE-TAIL.bin', config['tail_sha256']), verifier)
    case = parse(read('/inputs/CASE.json', config['case_sha256']))
    genesis.validate_case(case, selected, config['trial_id'])
    runtime = selected_runtime()
    actual, metrics = runtime.normalize(case, Path('/owner/public-quote'))
    need(actual == case, 'funding-exact-official-native-GEN3-ID-mass')
    rate = genesis.amount(config['fee_rate_sompi_per_mass'])
    required = genesis.amount(genesis.uint(metrics['mining_mass']) * rate)
    admission = genesis.validate_case(case, selected, config['trial_id'], quoted_fee_sompi=required)
    runtime.roundtrip(case)
    own_row = hx(initial['output_hex520'], 520)
    component = config['owner_component']
    need(hx(case['transaction']['payload'], genesis.WIDTH)[88 + 520 * component:88 + 520 * (component + 1)] == own_row,
         'funding-exact-approved-Original-initial-CM-position')
    receiver = original_receiver(profile, authority)
    receipt = receiver.open(own_row[96:360])
    need(receipt.index == 0 and receipt.value_sompi == genesis.ADMISSION and receipt.commitment() == own_row[:32],
         'funding-Original-rederives-exact-admitted-note')
    funding = receiver.keys(0xffffffff)
    script = (b'\0\0\x20' + funding.invoice.native_pk + b'\xac').hex()
    need(script == initial['funding_spk_hex36'] == case['entries'][component]['scriptPublicKey'],
         'funding-designated-own-new-KDF-GEN3-input')
    signature = runtime.signature(case, component, funding.native_secret)
    approval = hashlib.sha256(b'KPBAGR01\0' + selected.component_sha + uuid.UUID(config['trial_id']).bytes
        + rate.to_bytes(8, 'little') + encoded(case)).hexdigest()
    return {'schema': 'kpb-GEN3-owner-approval/v1', 'trial_id': config['trial_id'], 'owner_component': component,
        'component_profile_sha256': selected.component_sha.hex(), 'unsigned_case_sha256': config['case_sha256'],
        'unsigned_case_approval_sha256': approval, 'signature_script_hex66': signature.hex(),
        'own_Original_receipt_and_designated_key_rederived': True,
        'fee_rate_sompi_per_mass': rate, 'mining_mass': metrics['mining_mass'],
        'total_entry_fee_sompi': required, 'own_entry_fee_sompi': admission['owner_fee_shares_sompi'][component],
        'controller_private_Original_or_key_read': False, 'network_or_broadcast': False}


def run(operation):
    marker = parse(read('/NAMESPACE.json'))
    need(marker == {'schema': 'kpb-one-owner-namespace/v1', 'network': 'disabled',
                    'operation': operation, 'owner_slots': 1}, 'funding-one-owner-network-off-marker')
    need(not Path('/home/luke/.codex').exists() and not Path('/home/luke/.ssh').exists()
         and not Path('/var/tmp/kpi-owner-private-lifecycle-01/private').exists(), 'funding-host-private-paths-absent')
    interfaces = [line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    need(interfaces == ['lo'], 'funding-network-off-owner-namespace')
    config = parse(read('/CONFIG.json'))
    for member in config['source_members'] + config['runtime_members']:
        read(member['path'], member['sha256'])
    need(type(config['owner_component']) is int and config['owner_component'] in (0, 1, 2), 'funding-one-owner-slot')
    genesis.trial_uuid(config['trial_id'])
    profile = wallet.Profile(bytes.fromhex(config['domain_hex32']), bytes.fromhex(config['profile_id_hex32']))
    need(profile.domain == genesis.EXPECTED_IDENTITY[3] and profile.profile_id == genesis.EXPECTED_IDENTITY[2],
         'funding-explicit-new-Original-profile')
    initial = own_public(config, profile)
    modules = wallet.authenticate_js('/runtime/JS-INSTALLED-LEAF-MAP.json', config['js_leaf_map_sha256'], '/runtime/js')
    with boundary.NamespaceAuthority('/runtime/node', modules) as authority:
        result = consolidate(config, profile, initial, authority) if operation == 'consolidate' else approve_genesis(config, profile, initial, authority)
    write('/out/PUBLIC.json', result, 0o400)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('consolidate', 'approve-genesis'))
    try:
        run(parser.parse_args().operation)
    except BaseException as error:
        if Path('/out').is_dir() and not Path('/out/PUBLIC-FAILURE.json').exists():
            frame = error.__traceback__
            while frame and frame.tb_next: frame = frame.tb_next
            write('/out/PUBLIC-FAILURE.json', {'schema': 'kpb-funding-owner-failure/v1', 'category': type(error).__name__,
                'source_site': None if frame is None else {'file': Path(frame.tb_frame.f_code.co_filename).name, 'line': frame.tb_lineno}}, 0o400)
        raise


if __name__ == '__main__':
    main()
