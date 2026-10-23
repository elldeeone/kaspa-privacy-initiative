#!/usr/bin/env python3
"""Bounded public confirmation export, independent of private owner inputs/reports."""
import argparse
import json
from pathlib import Path

import funding_packet as funding
import prefix_observations as prefix

SOURCE = Path('/home/luke/projects/kpi-intensive-2026-10-22/private-service-loss-tn10-01/recovered-exits')
NETWORK = funding.ROOT / 'research/next-session/private-service-loss/network'
EXPECTED = {1: {
    'body_sha256': 'be7ed7fa0aab8ae5f73ec1b6b0d75777e3332b46ed63ea8369e3263a0cfa625c',
    'release_sha256': '184cc57a6a09bf9ce4bb11849c1752d3ecbd8aabc8979db52fc80b02a29b82ed',
    'fetch_sha256': '72174443cf578042340d279eccc31dd8049796f1f65216c2d64aae042c50edc3',
    'fetch_relative': 'live-observation-01/client-output/network-data/fetch.json',
    'predecessor': {'transactionId': '16c8a7d82f10eeac0d3da4609c518ade73f7da3294ec26e91cb1ae1b47486fd5', 'index': 0},
    'reserve_before_sompi': 120000000, 'reserve_after_sompi': 60000000,
    'payout_sompi': 41000100, 'fee_sompi': 18999900}, 2: {
    'body_sha256': '0f82842768f2e7274d33610b0210ab397231dfee9a46d7d5222868419d721e1a',
    'release_sha256': 'e854e46ce31954ea7a09ff03e60e86224ae155e48d7044b5f74671952ee0820b',
    'fetch_sha256': '7b851dfaa0ccf12b51707b789d82b06238781528b801a8bbfa95b89267f25934',
    'fetch_relative': 'live-observation-02/client-output/network-data/fetch.json',
    'predecessor': {'transactionId': '71a1536f3a4824026c0d309d2a0f46e1a14103ba99a2e8db9b6013f7ac17a9b4', 'index': 0},
    'reserve_before_sompi': 60000000, 'reserve_after_sompi': 0,
    'payout_sompi': 41042400, 'fee_sompi': 18957600}}
NATIVE_SHA = 'f6139cea85a30f092447efe199796f62c540b0399d63e949845423678d4bdc44'


def export(sequence, output):
    funding.need(sequence in EXPECTED, 'root-reviewed-actual-exit-selection-required')
    expected = EXPECTED[sequence]
    exporter = funding.base_exporter()
    source = SOURCE / f'owner-{sequence:02d}'
    names = ('transaction.json', 'supplied-context.json', 'native-validation.json',
             'local-check.json', 'release.json', 'submit-request.json', 'confirmed-observation.json')
    blobs = {name: exporter.safe_file(source, name).read_bytes() for name in names}
    data = {name: exporter.public_json(json.loads(raw)) for name, raw in blobs.items()}
    body, check, release, request, observation = [data[name] for name in
        ('transaction.json', 'local-check.json', 'release.json', 'submit-request.json', 'confirmed-observation.json')]
    funding.need(funding.sha(blobs['transaction.json']) == expected['body_sha256']
                 and funding.sha(blobs['release.json']) == expected['release_sha256']
                 and check['body_sha256'] == expected['body_sha256'] and check['transaction_id'] == body['id']
                 and check['native_binary_sha256'] == NATIVE_SHA
                 and check['native_validation_sha256'] == funding.sha(blobs['native-validation.json'])
                 and check['native_full_accepted'] is True and check['all_input_engines_accepted'] is True,
                 'exact-root-reviewed-owner-body-and-check')
    native = data['native-validation.json']
    funding.need(native['isolation'] == 'PASS'
                 and native['Full'] == {'accepted': True, 'fee_sompi': expected['fee_sompi']}
                 and native['all_input_engines_accepted'] is True
                 and len(native['per_input_ScriptEngine']) == 1
                 and native['per_input_ScriptEngine'][0]['input_index'] == 0
                 and native['per_input_ScriptEngine'][0]['accepted'] is True, 'actual-owner-native-evidence')
    stages = release['allowed_stages']
    funding.need(len(stages) == 1 and release['bodies'] == {stages[0]: {
        'body_sha256': expected['body_sha256'], 'transaction_id': body['id'],
        'local_check_sha256': funding.sha(blobs['local-check.json'])}}
        and release['native_binary_sha256'] == NATIVE_SHA
        and release['network'] == 'testnet-10'
        and release['adapter_sha256'] == '08b5870879c8e9ae83e54a5cf27f337c694a2fa87ad7f687a39d6aa70b7c1b23'
        and release['native_safe_sha256'] == 'ed36b7bb8056c2a6fa6d49140a39dce3a7cb6a9159ecf47c3a1d174b0c993e0a'
        and request['op'] == 'submit-once' and request['stage'] == stages[0]
        and request['release_sha256'] == expected['release_sha256']
        and request['rpc_url'] == release['rpc_url'] and observation['start_hash'] == request['start_hash'],
        'exact-one-stage-release-request-observation')
    fetched_raw = exporter.safe_file(NETWORK, expected['fetch_relative']).read_bytes()
    funding.need(funding.sha(fetched_raw) == expected['fetch_sha256'], 'actual-fresh-network-input-pin')
    fetched = json.loads(fetched_raw)
    predecessor = expected['predecessor']
    entries = [row['entry'] for row in fetched['current_view']['queries'] if row['outpoint'] == predecessor]
    funding.need(len(entries) == 1 and entries[0] is not None
                 and body['inputs'][0]['previousOutpoint'] == predecessor, 'fresh-network-live-head-consumed')
    entry = entries[0]
    context = {key: val for key, val in entry.items() if key != 'outpoint'}
    funding.need(data['supplied-context.json'] == [context]
                 and check['inputs'] == [dict(context, outpoint=predecessor)], 'exact-fresh-head-native-context')
    plain = prefix.checked(observation, body, context, int(entry['block_daa_score']), body['id'], exporter)
    funding.need(int(entry['amount_sompi']) == expected['reserve_before_sompi']
                 and int(entry['amount_sompi']) - sum(int(row['value']) for row in body['outputs']) == expected['fee_sompi'],
                 'actual-private-cashout-conservation')
    auth = bytes.fromhex(body['payload'])
    funding.need(len(auth) == 4400 and auth[:8] == b'KPX3AU01'
                 and auth[8:40].hex() == 'caf85e3b34cd9b426559f57bb1ab647835c5dfaf255d17bf3d1291c0f7408470'
                 and int.from_bytes(auth[188:196], 'little') == expected['reserve_before_sompi']
                 and int.from_bytes(auth[196:204], 'little') == expected['fee_sompi']
                 and int.from_bytes(auth[484:492], 'little') == expected['payout_sompi']
                 and int.from_bytes(auth[476:484], 'little') == expected['reserve_after_sompi'],
                 'public-private-cashout-effects')
    terminal = expected['reserve_after_sompi'] == 0
    payout_index = 0 if terminal else 1
    funding.need(len(body['outputs']) == (1 if terminal else 2)
                 and int(body['outputs'][payout_index]['value']) == expected['payout_sompi']
                 and body['outputs'][payout_index]['scriptPublicKey'] == auth[492:528].hex()
                 and int.from_bytes(auth[472:476], 'little') == int.from_bytes(auth[184:188], 'little') + 2,
                 'public-payout-and-two-nullifier-count')
    if terminal:
        funding.need(auth[268:332] == bytes(64) and auth[528:1056] == bytes(528)
                     and auth[3376:4400] == bytes(1024)
                     and auth[332:364] == bytes.fromhex('8889eb3cdd3d0ac94711b47ce78b430d8e23a7b31ecc994c56d0c3310c87674a')
                     and auth[116:148] == auth[404:436] and auth[148:152] == auth[436:440],
                     'terminal-public-inactive-CM-fields-and-carry')
    selected = exporter.sanitize_observation(plain, funding.sha(blobs['confirmed-observation.json']),
                                               len(blobs['confirmed-observation.json']))
    selected['post_query_related_spend_check'] = True
    authorization = {'schema': 'kpx3-public-cashout-authorization-selection/v1',
        'sequence': sequence, 'original_release_sha256': expected['release_sha256'],
        'original_request_sha256': funding.sha(blobs['submit-request.json']),
        'single_stage_authorized': True, 'selected_body': release['bodies'][stages[0]],
        'release_selection': {key: release[key] for key in ('authorization', 'profile_sha256', 'network',
            'genesis', 'rpc_url', 'adapter_sha256', 'native_safe_sha256', 'native_binary_sha256')},
        'request_selection': {key: request[key] for key in ('op', 'rpc_url', 'start_hash', 'release_sha256')},
        'owner_stage_label_and_private_filesystem_paths_omitted': True}
    summary = {'schema': 'kpx3-private-cashout-confirmed-public-closure/v1', 'sequence': sequence,
        'transaction_id': body['id'], 'body_sha256': expected['body_sha256'],
        'fresh_network_input_sha256': expected['fetch_sha256'],
        'reserve_before_sompi': expected['reserve_before_sompi'], 'reserve_after_sompi': expected['reserve_after_sompi'],
        'native_payout_sompi': expected['payout_sompi'], 'fee_sompi': expected['fee_sompi'],
        'terminal': terminal, 'public_cm_count_after': int.from_bytes(auth[436:440], 'little'),
        'public_nf_count_after': int.from_bytes(auth[472:476], 'little'),
        'confirmation_policy': observation['confirmation_policy'], 'all_outputs_unspent_at_this_observation': True,
        'current_now_or_independent_consensus_claimed': False,
        'hidden_input_note_CM_position_key_or_private_witness_exported': False,
        'private_receipt_to_owner_or_native_payout_association_exported': False,
        'operator_rehearsal_exit_read_compared_or_used': False,
        'privacy_fee_or_production_qualification_claimed': False, 'export_rpc_native_proof_signing_runs': 0,
        'original_public_input_identities': {name: {'sha256': funding.sha(raw), 'bytes': len(raw)}
            for name, raw in blobs.items()}}
    payloads = {'selected-observation.json': funding.encoded(selected),
                'authorization-selection.json': funding.encoded(authorization),
                'CONFIRMED-CASHOUT.json': funding.encoded(summary),
                'source/cashout_observations.py': Path(__file__).read_bytes(),
                'source/funding_packet.py': Path(funding.__file__).read_bytes(),
                'source/prefix_observations.py': Path(prefix.__file__).read_bytes()}
    funding.need(not output.exists() and not any(path.is_symlink() for path in (output, *output.parents)),
                 'fresh-public-cashout-output')
    output.mkdir(parents=True)
    files = []
    for name, raw in sorted(payloads.items()):
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as file:
            file.write(raw)
        files.append({'path': name, 'bytes': len(raw), 'sha256': funding.sha(raw)})
    with (output / 'MANIFEST.json').open('xb') as file:
        file.write(funding.encoded({'schema': 'kpx3-public-cashout-confirmation-manifest/v1', 'files': files,
            'sequence': sequence, 'exporter_sha256': funding.sha(Path(__file__).read_bytes()),
            'funding_extractor_sha256': funding.sha(Path(funding.__file__).read_bytes()),
            'prefix_extractor_sha256': funding.sha(Path(prefix.__file__).read_bytes())}))
    return {'manifest_sha256': funding.sha((output / 'MANIFEST.json').read_bytes()), 'payloads': len(files)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sequence', type=int)
    parser.add_argument('new_public_output', type=Path)
    args = parser.parse_args()
    print(json.dumps(export(args.sequence, args.new_public_output), sort_keys=True))
