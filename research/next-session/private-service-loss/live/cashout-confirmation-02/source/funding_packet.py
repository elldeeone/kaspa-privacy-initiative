#!/usr/bin/env python3
"""Bounded public extraction for the reviewed ordinary merge03 only.

No recursive operator-file discovery, private profile, backup, key, PK, witness,
RPC, signing or broadcast input. The original bulk observation stays outside Git.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import types

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path('/home/luke/.local/share/kpi-kpx2-recovery-trials/20261023-ordinary-merge-03')
TXID = '98580676726abeb9057de82f6a5e3c3077cd865aa8c8acad205b210d09fcdb7f'
BODY_SHA = '342fe19d541f0f13a3179cf3f0a1c69a393e46c58d7b6f5e6aac80f85c9069b6'
RELEASE_SHA = '3a19782953d767562f68f328f9c93b14e56998691dbefda754c9fd1e855c21ef'
DESTINATION = '0000205f9c87ec955e6354bf4733ea75b96baf6dcd90f8daebe2f0ef1f241ee438a933ac'
PUBLIC_FILES = ('public-merge.json', 'case.json', 'transaction.json', 'supplied-context.json',
    'local-check.json', 'native-01/native-validation.json', 'native-01/metrics.json',
    'planned-source.json', 'release.json', 'public/identity.json',
    'chain/fundingprep.submission-intent.json', 'chain/' + TXID + '.submission-intent.json',
    'chain/fundingprep.submission-result.json')


def need(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def base_exporter():
    path = ROOT / 'poc/recovery-trial/export_public.py'
    raw = path.read_bytes()
    need(sha(raw) == '229bfc2ee3dd3725afd8152977d2790acbaebd31a9e0b9a5e68e157df73402af',
         'immutable-public-extractor-source')
    need(sha((ROOT / 'poc/future-native-chain/native_safe.py').read_bytes())
         == 'c4b7c3353ba4c83b758daa24f967c922acd1abe2aad2909010924fba9fb7f736',
         'immutable-public-codec-source')
    module = types.ModuleType('_funding_public_extractor')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), vars(module))
    return module


def checked_observation(observation, body, contexts, raw_sha, raw_bytes, exporter):
    canonical = exporter.canonical_body(body)
    need(observation['transaction_id'] == TXID and observation['accepted_body'] == canonical,
         'exact-observed-body')
    sdk_raw = json.dumps(canonical, separators=(',', ':'), ensure_ascii=False).encode()
    need(observation['accepted_body_sha256'] == sha(sdk_raw), 'observed-SDK-body-hash')
    actual = observation['accepted_input_contexts']
    need(len(actual) == len(contexts) == len(body['inputs']) == 4, 'all-four-input-contexts')
    for got, expected, input_ in zip(actual, contexts, body['inputs']):
        need(set(got) == {'outpoint', 'amount_sompi', 'script_public_key',
                         'block_daa_score', 'is_coinbase', 'covenant_id'}
             and got['outpoint'] == input_['previousOutpoint'] == expected['outpoint']
             and got['script_public_key'] == expected['script_public_key']
             and int(got['amount_sompi']) == int(expected['amount_sompi'])
             and int(got['block_daa_score']) == int(expected['block_daa_score'])
             and got['is_coinbase'] is False and got['covenant_id'] is None,
             'accepted-input-context-binding')
    spent = observation['spent_inputs']
    point = lambda value: (value['transactionId'], value['index'])
    need(len(spent) == 4 and {point(x['outpoint']) for x in spent}
         == {point(x['previousOutpoint']) for x in body['inputs']}, 'all-four-spent-queries')
    scripts = {point(row['outpoint']): row['script_public_key'] for row in contexts}
    need(all(row['script_public_key'] == scripts[point(row['outpoint'])]
             for row in spent), 'spent-query-script-binding')
    outputs = observation['current_outputs']
    need(len(outputs) == 1 and outputs[0]['index'] == 0, 'sole-funding-output-query')
    current = outputs[0]
    need(current['outpoint'] == {'transactionId': TXID, 'index': 0}
         and int(current['amount_sompi']) == 228999900
         and current['script_public_key'] == DESTINATION, 'funding-query-binding')
    utxo = current['utxo']
    need(utxo is not None and utxo['outpoint'] == current['outpoint']
         and int(utxo['amount_sompi']) == 228999900
         and utxo['script_public_key'] == DESTINATION
         and utxo['is_coinbase'] is False and utxo['covenant_id'] is None,
         'funding-output-unspent-at-observation')
    return exporter.sanitize_observation(observation, raw_sha, raw_bytes)


def export(output):
    exporter = base_exporter()
    need(not any(path.is_symlink() for path in (output, *output.parents))
         and not output.exists() and output.resolve() != SOURCE.resolve()
         and SOURCE.resolve() not in output.resolve().parents,
         'fresh-public-output-outside-originals')
    blobs = {name: exporter.safe_file(SOURCE, name).read_bytes() for name in PUBLIC_FILES}
    data = {name: exporter.public_json(json.loads(raw)) for name, raw in blobs.items()}
    body, checked, release = (data[name] for name in ('transaction.json', 'local-check.json', 'release.json'))
    need(sha(blobs['transaction.json']) == BODY_SHA and body['id'] == TXID
         and sha(blobs['release.json']) == RELEASE_SHA, 'released-body-identity')
    need(checked['body_sha256'] == BODY_SHA and checked['transaction_id'] == TXID
         and checked['profile_sha256'] == sha(blobs['public/identity.json']) == release['profile_sha256'],
         'body-check-profile-binding')
    need(release['allowed_stages'] == ['fundingprep'] and release['network'] == 'testnet-10'
         and release['destination_spk'] == DESTINATION, 'ordinary-only-testnet-release')
    contexts = checked['inputs']
    case = data['case.json']
    expected_entries = [{'amount': int(row['amount_sompi']),
        'scriptPublicKey': row['script_public_key'], 'blockDaaScore': int(row['block_daa_score']),
        'isCoinbase': row['is_coinbase'], 'covenantId': row['covenant_id']} for row in contexts]
    expected_supplied = [{key: row[key] for key in ('amount_sompi', 'script_public_key',
        'block_daa_score', 'is_coinbase')} for row in contexts]
    need(set(case) == {'transaction', 'entries'} and case['transaction'] == body
         and case['entries'] == expected_entries
         and data['supplied-context.json'] == expected_supplied,
         'copied-native-case-and-supplied-context-bind-check')
    native = data['native-01/native-validation.json']
    need(native['isolation'] == 'PASS' and native['Full'] == {'accepted': True, 'fee_sompi': 498600}
         and native['all_input_engines_accepted'] is True
         and len(native['per_input_ScriptEngine']) == 4
         and all(row['accepted'] is True and row['input_index'] == index
                 for index, row in enumerate(native['per_input_ScriptEngine'])), 'native-four-engine-evidence')
    need(sum(int(row['amount_sompi']) for row in contexts) == 229498500
         and len(body['outputs']) == 1 and body['outputs'][0]['value'] == 228999900
         and body['outputs'][0]['scriptPublicKey'] == DESTINATION
         and body['payload'] == '', 'ordinary-source-reconciliation')
    intent = data['chain/fundingprep.submission-intent.json']
    need(intent == data['chain/' + TXID + '.submission-intent.json']
         and intent['transaction_id'] == TXID and intent['body_sha256'] == BODY_SHA
         and intent['release_sha256'] == RELEASE_SHA and intent['stage'] == 'fundingprep'
         and intent['profile_sha256'] == release['profile_sha256']
         and intent['rpc_url'] == release['rpc_url'],
         'both-durable-intents-bind-release')
    raw = exporter.safe_file(SOURCE, 'confirmed-observation-01.json').read_bytes()
    observation = json.loads(raw)
    need(observation['start_hash'] == intent['start_hash']
         and observation['server']['networkId'] == release['network']
         and observation['expected_genesis'] == release['genesis'],
         'actual-refreshed-observation-start')
    selected = checked_observation(observation, body, contexts, sha(raw), len(raw), exporter)
    summary = {
        'schema': 'kpx3-ordinary-funding-closure/v1', 'transaction_id': TXID,
        'classification': 'CONFIRMED_TESTNET_ORDINARY_FUNDING_SELECTED_NODE_OBSERVATION',
        'input_count': 4, 'input_sum_sompi': 229498500, 'fee_sompi': 498600,
        'funding_output_sompi': 228999900, 'funding_output_script_public_key': DESTINATION,
        'funding_output_block_daa_score': str(observation['current_outputs'][0]['utxo']['block_daa_score']),
        'all_four_inputs_queried_spent': True, 'funding_output_unspent_at_observation': True,
        'observation_is_current_now_proved': False,
        'confirmation_policy': observation['confirmation_policy'],
        'actual_start_hash_bound_by_intents_and_observation': intent['start_hash'],
        'checkpoint_refresh': 'Read-only checkpoint refreshed before intent; initial prepared requests are not represented as issued requests',
        'released_local_complete_sha256': release['local_four_body_complete_sha256'],
        'old_profile_used_only_for_ordinary_merge_never_for_a_pool': True,
        'raw_observation_sha256': sha(raw), 'raw_observation_bytes': len(raw),
        'unrelated_bulk_pages_published': False,
        'header_hash_recomputation_or_independent_consensus_claimed': False,
        'pool_lifecycle_or_cold_private_exit_qualified_here': False,
        'private_profile_backup_seed_PK_witness_or_native_secret_read': False,
        'export_rpc_native_proof_sign_or_broadcast': False}
    output.mkdir(parents=True)
    def emit(relative, raw):
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as file:
            file.write(raw)
    for name, blob in blobs.items():
        emit('originals/' + name, blob)
    emit('selected-observation.json', encoded(selected))
    emit('FUNDING-CLOSURE.json', encoded(summary))
    origins = {name: {'sha256': sha(blob), 'bytes': len(blob)} for name, blob in blobs.items()}
    origins['confirmed-observation-01.json'] = {'sha256': sha(raw), 'bytes': len(raw),
                                             'unrelated_pages_excluded': True}
    emit('ORIGINAL-IDENTITIES.json', encoded(origins))
    files = []
    for path in sorted(output.rglob('*')):
        if path.is_file():
            blob = path.read_bytes()
            files.append({'path': str(path.relative_to(output)), 'bytes': len(blob), 'sha256': sha(blob)})
    emit('MANIFEST.json', encoded({'schema': 'kpx3-funding-public-manifest/v1',
        'exporter_sha256': sha(Path(__file__).read_bytes()),
        'immutable_base_extractor_sha256': '229bfc2ee3dd3725afd8152977d2790acbaebd31a9e0b9a5e68e157df73402af',
        'files': files}))
    return {'public_payload_files': len(files), 'manifest_sha256': sha((output / 'MANIFEST.json').read_bytes()),
            'raw_global_pages_published': False, 'funding_transaction_id': TXID}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('new_public_output', type=Path)
    args = parser.parse_args()
    print(json.dumps(export(args.new_public_output), sort_keys=True))
