#!/usr/bin/env python3
"""Explicit public allowlist for the fresh KPX2 service-loss evidence packet.

No recursive discovery of operator files, private profile/backup access, network,
signing or proof API. Original bulk RPC observations stay outside Git.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('public_export_native_safe',
                                             ROOT / 'poc/future-native-chain/native_safe.py')
_native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_native)

PREFIX = ('fundingprep', 'founding', 'admit', 'private')
PREFIX_DIR = {'fundingprep': 'funding-prep', **{x: x for x in PREFIX[1:]}}
ARTIFACTS = ('transaction.json', 'supplied-context.json', 'native-validation.json',
             'metrics.json', 'local-check.json')
FORBIDDEN_KEYS = {'secrets', 'seed_hex32', 'funding_secret_hex32', 'native_secret_hex32',
                  'source_secret_hex32', 'private_key_hex32'}
OBSERVATION_FIELDS = {'transaction_id', 'accepted_body', 'accepted_body_sha256',
    'accepted_input_contexts', 'accepting_block_header', 'observed_sink', 'virtual_daa_score',
    'start_hash', 'final_cursor', 'confirmation_policy', 'current_outputs', 'spent_inputs',
    'chain_delta_removed', 'utxo_query_started_at', 'observed_at', 'network',
    'expected_genesis', 'trust', 'server'}
MERGE02_ID = '033edf4c81a8edbea99f572ed4f883558f51bab19d3b2c4ef7aa34321d673a5b'
# Individually approved by the coordinator. Never enumerate these directories.
MERGE02_PUBLIC = ('public-merge.json', 'transaction.json', 'supplied-context.json',
    'local-check.json', 'native-01/native-validation.json', 'native-01/metrics.json',
    'release.json', 'submit-request.json', 'observe-request.json', 'checkpoint.json',
    'confirmed-source.json', 'chain/fundingprep.submission-intent.json',
    'chain/' + MERGE02_ID + '.submission-intent.json', 'chain/fundingprep.submission-result.json')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_body(value):
    if 'storageMass' in value:
        value = dict(value)
        value['mass'] = value.pop('storageMass')
    return _native.body(value)


def canonical_full_record(value):
    """Adapt only public FullV2 fields through the established native converter."""
    if 'mass' in value and 'storageMass' in value:
        require(_native.u(value['mass']) == _native.u(value['storageMass']), 'full-record-mass-alias')
    inputs = []
    for item in value['inputs']:
        require(item.get('sigOpCount', 0) == 0, 'full-record-v1-sigop')
        inputs.append({key: item[key] for key in
                       ('previousOutpoint', 'signatureScript', 'sequence', 'computeBudget')})
    outputs = []
    for item in value['outputs']:
        script = item['scriptPublicKey']
        if isinstance(script, dict):
            require(type(script['version']) is int and script['version'] == 0, 'full-record-script-version')
            script = '0000' + script['script']
        outputs.append({'value': item['value'], 'scriptPublicKey': script,
                        'covenant': item.get('covenant')})
    return _native.body({'version': value['version'],
        'id': value.get('verboseData', {}).get('transactionId', value.get('id')),
        'inputs': inputs, 'outputs': outputs, 'lockTime': value['lockTime'],
        'subnetworkId': value['subnetworkId'], 'gas': value['gas'], 'payload': value['payload'],
        'mass': value['storageMass'] if 'storageMass' in value else value['mass']})


def public_json(value):
    if isinstance(value, dict):
        require(not FORBIDDEN_KEYS.intersection(value), 'private-key-field-rejected')
        for child in value.values():
            public_json(child)
    elif isinstance(value, list):
        for child in value:
            public_json(child)
    return value


def safe_file(base, relative):
    relative = Path(relative)
    require(not relative.is_absolute() and '..' not in relative.parts, 'relative-public-path')
    path = base / relative
    require(not any(x.is_symlink() for x in (path, *path.parents)), 'symlink-rejected')
    require(path.is_file(), 'required-public-artifact-absent: ' + str(relative))
    return path


def sanitize_observation(value, original_sha256, original_bytes):
    require(set(value) == OBSERVATION_FIELDS | {'pages'}, 'observation-fields')
    txid = value['transaction_id']
    require(value['accepted_body']['id'] == txid, 'observed-body-identity')
    require(value['network'] == 'testnet-10' and value['confirmation_policy']['passes'] is True,
            'confirmed-testnet-observation-required')
    require(int(value['confirmation_policy']['actual_blue_score_distance'])
            > int(value['confirmation_policy']['min_confirmation_count']) >= 20,
            'confirmation-depth')
    require(value['chain_delta_removed'] == [] and value['spent_inputs']
            and all(x['queried'] is True and x['unspent'] is False for x in value['spent_inputs']),
            'spent-input-query')
    relevant, pages = [], []
    seen = set()
    for page in value['pages']:
        response = page['response']
        groups = response['chainBlockAcceptedTransactions']
        require(response['removedChainBlockHashes'] == [], 'removed-observation-prefix')
        require(len(groups) == len(response['addedChainBlockHashes']), 'page-header-count')
        pages.append({'start_hash': page['start_hash'], 'original_page_canonical_sha256': sha(canonical(page)),
            'added_blocks': len(response['addedChainBlockHashes']),
            'removed_blocks': 0, 'accepted_transaction_records': sum(len(g['acceptedTransactions']) for g in groups)})
        for group, added_hash in zip(groups, response['addedChainBlockHashes']):
            require(group['chainBlockHeader']['hash'] == added_hash, 'page-header-identity')
            selected = [tx for tx in group['acceptedTransactions']
                        if tx.get('verboseData', {}).get('transactionId', tx.get('id')) == txid]
            if selected:
                require(all(canonical_full_record(tx) == value['accepted_body'] for tx in selected),
                        'selected-acceptance-body')
                require(group['chainBlockHeader']['hash'] == value['accepting_block_header']['hash'],
                        'selected-accepting-header')
                record = {'chainBlockHeader': group['chainBlockHeader'], 'acceptedTransactions': selected}
                digest = sha(canonical(record))
                if digest not in seen:
                    seen.add(digest)
                    relevant.append(record)
    require(relevant, 'selected-acceptance-record-required')
    output = {key: value[key] for key in OBSERVATION_FIELDS}
    output['public_extraction'] = {'original_file_sha256': original_sha256,
        'original_file_bytes': original_bytes, 'full_unrelated_pages_excluded': True,
        'original_page_summaries': pages, 'selected_acceptance_records': relevant,
        'adapter_headers_are_selected_node_assertions': True,
        'headers_independently_rehashed_by_this_extractor': False,
        'independent_fresh_fetch_header_checks_are_separate_evidence': True}
    return public_json(output)


class Packet:
    def __init__(self, trial, output):
        self.trial, self.output = trial.absolute(), output.absolute()
        require(self.output != self.trial and self.trial not in self.output.parents,
                'public-output-must-not-be-in-private-trial')
        self.files, self.originals = {}, {}

    def emit(self, relative, raw):
        path = self.output / relative
        require(not any(x.is_symlink() for x in (path, *path.parents)), 'output-symlink')
        if path.exists():
            require(path.read_bytes() == raw, 'existing-public-artifact-differs: ' + relative)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.files[relative] = sha(raw)

    def copy(self, source, destination=None):
        path = safe_file(self.trial, source)
        raw = path.read_bytes()
        public_json(json.loads(raw))
        self.emit(destination or source, raw)
        self.originals[source] = {'sha256': sha(raw), 'bytes': len(raw)}

    def ordinary_funding(self):
        parent = self.trial.parent
        approved = [('20261023-ordinary-merge-01', 'UNUSED-PUBLIC.json')]
        approved += [('20261023-ordinary-merge-02', name) for name in MERGE02_PUBLIC]
        for directory, relative in approved:
            raw = safe_file(parent / directory, relative).read_bytes()
            public_json(json.loads(raw))
            destination = 'ordinary-funding/' + directory + '/' + relative
            self.emit(destination, raw)
            self.originals[directory + '/' + relative] = {'sha256': sha(raw), 'bytes': len(raw)}
        original = safe_file(parent / '20261023-ordinary-merge-02', 'observation.json').read_bytes()
        value = sanitize_observation(json.loads(original), sha(original), len(original))
        require(value['transaction_id'] == MERGE02_ID, 'ordinary-merge-identity')
        self.emit('ordinary-funding/20261023-ordinary-merge-02/observation.json',
                  (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())
        self.originals['20261023-ordinary-merge-02/observation.json'] = {
            'sha256': sha(original), 'bytes': len(original), 'bulk_pages_not_published': True}

    def observe(self, source, destination):
        path = safe_file(self.trial, source)
        raw = path.read_bytes()
        value = sanitize_observation(json.loads(raw), sha(raw), len(raw))
        self.emit(destination, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())
        self.originals[source] = {'sha256': sha(raw), 'bytes': len(raw), 'bulk_pages_not_published': True}

    def stage(self, name, relative, *, owner=False):
        body_path = safe_file(self.trial, relative + '/transaction.json')
        body = canonical_body(json.loads(body_path.read_bytes()))
        native = json.loads(safe_file(self.trial, relative + '/native-validation.json').read_bytes())
        checked = json.loads(safe_file(self.trial, relative + '/local-check.json').read_bytes())
        require(native['Full']['accepted'] is True and native['all_input_engines_accepted'] is True,
                'native-validation-required')
        engines = native['per_input_ScriptEngine']
        require(len(engines) == len(body['inputs']) and all(x['accepted'] is True for x in engines),
                'every-native-input-engine-required')
        require(checked['transaction_id'] == body['id'] and checked['body_sha256'] == sha(body_path.read_bytes()),
                'local-check-body-hash')
        for artifact in ARTIFACTS:
            self.copy(relative + '/' + artifact, 'stages/' + name + '/' + artifact)
        if owner:
            for artifact in ('RESULTS.json', 'quote.json', 'release.json', 'CONFIRMED.json'):
                self.copy(relative + '/' + artifact, 'stages/' + name + '/' + artifact)
        else:
            self.copy(relative + '/sdk-roundtrip.json', 'stages/' + name + '/sdk-roundtrip.json')
        # Fixed names and the exact public body's ID are the entire intent allowlist.
        for artifact in (name + '.submission-intent.json', name + '.submission-result.json',
                         body['id'] + '.submission-intent.json'):
            self.copy('chain/' + artifact)
        intent = json.loads(safe_file(self.trial, 'chain/' + name + '.submission-intent.json').read_bytes())
        require(intent['transaction_id'] == body['id'] and intent['body_sha256'] == sha(body_path.read_bytes())
                and intent['stage'] == name, 'submission-intent-body')
        return body

    def finish(self, owners):
        metadata = {'schema': 'kpx2-service-loss-public-extraction/v1',
            'classification': 'SANITIZED_PUBLIC_RECORDS_NOT_AGGREGATE_LIFECYCLE_RESULTS',
            'prefix_stages': list(PREFIX), 'cold_exit_stages': [owner + '-reveal' for owner in owners],
            'source_files': self.originals,
            'bulk_unrelated_FullV2_pages_published': False,
            'private_profile_backup_fixture_witness_pk_prover_or_precomputed_exit_read': False,
            'rpc_signing_proving_or_broadcast_operation': False,
            'adapter_header_assertions_and_fresh_fetch_header_validation_are_distinct': True}
        # The originals remain local; this private index pins the exact bulk bytes
        # without copying unrelated records into the publication directory.
        local_index = self.trial / ('public-extraction-originals-' + self.output.name + '.json')
        local_raw = (json.dumps(self.originals, indent=2, sort_keys=True) + '\n').encode()
        require(not local_index.is_symlink(), 'local-original-index-symlink')
        if local_index.exists():
            require(local_index.read_bytes() == local_raw, 'local-original-index-differs')
        else:
            fd = os.open(local_index, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(local_raw)
                stream.flush()
                os.fsync(stream.fileno())
        self.emit('EXTRACTION.json', (json.dumps(metadata, indent=2, sort_keys=True) + '\n').encode())
        public_files = sorted([*self.files, 'PUBLIC-FILES.json', 'SHA256SUMS.json'])
        self.emit('PUBLIC-FILES.json', (json.dumps(public_files, indent=2) + '\n').encode())
        # SHA256SUMS cannot contain its own digest; its exact path is allowlisted.
        manifest = dict(sorted(self.files.items()))
        manifest_path = self.output / 'SHA256SUMS.json'
        require(not manifest_path.is_symlink(), 'manifest-symlink')
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        actual = sorted(str(p.relative_to(self.output)) for p in self.output.rglob('*') if p.is_file())
        require(actual == public_files, 'unexpected-public-output-file')
        require(all(sha((self.output / name).read_bytes()) == digest for name, digest in manifest.items()),
                'public-output-hash-mismatch')
        return {'files': len(actual), 'manifest_sha256': sha(manifest_path.read_bytes()),
                'manifest': str(manifest_path)}


def export(trial, output, owners, include_ordinary=False):
    require(len(set(owners)) == len(owners) and set(owners) <= {'bob', 'charlie'}, 'owner-selection')
    p = Packet(trial, output)
    if include_ordinary:
        p.ordinary_funding()
    p.copy('public/identity.json', 'public/identity.json')
    p.copy('public/recovery-descriptor.json', 'public/recovery-descriptor.json')
    p.copy('prefix-release.json')
    p.copy('prefix-chain/FOUR-CONFIRMED.json')
    for stage in PREFIX:
        body = p.stage(stage, 'actual-execution/' + PREFIX_DIR[stage])
        observation = 'prefix-chain/' + stage + '-observation.json'
        require(json.loads(safe_file(p.trial, observation).read_bytes())['accepted_body'] == body,
                'prefix-observation-body')
        p.observe(observation, 'observations/' + stage + '.json')
        p.copy('prefix-chain/' + stage + '-submission.json')
    for owner in owners:
        stage, relative = owner + '-reveal', 'recovered-exits/' + owner
        body = p.stage(stage, relative, owner=True)
        observation = relative + '/observation.json'
        require(json.loads(safe_file(p.trial, observation).read_bytes())['accepted_body'] == body,
                'cold-exit-observation-body')
        confirmed = json.loads(safe_file(p.trial, relative + '/CONFIRMED.json').read_bytes())
        require(confirmed['transaction_id'] == body['id']
                and confirmed['observation_sha256'] == sha(safe_file(p.trial, observation).read_bytes())
                and confirmed['no_operator_precomputed_exit_used'] is True,
                'cold-confirmation-identity')
        require(int(body['outputs'][confirmed['payout_output_index']]['value']) == confirmed['payout_sompi'],
                'cold-confirmation-payout')
        p.observe(observation, 'observations/' + stage + '.json')
        p.copy(relative + '/submission.json', 'stages/' + stage + '/submission.json')
    return p.finish(owners)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trial', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--owner', action='append', choices=('bob', 'charlie'), default=[])
    parser.add_argument('--include-ordinary', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(export(args.trial, args.output, args.owner, args.include_ordinary), sort_keys=True))
    except (ValueError, KeyError, OSError, TypeError) as error:
        raise SystemExit('public extraction refused: ' + str(error))
