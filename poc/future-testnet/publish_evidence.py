#!/usr/bin/env python3
"""Export only public completed-trial evidence; never traverse private inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import re


STAGES = ('fundingprep', 'founding', 'admit', 'private', 'bob-reveal', 'charlie-reveal')
GENERATED_SOURCE_PATHS = frozenset({
    'poc/future-native-union/Cargo.lock',
    'poc/future-native-union/Cargo.toml',
    'poc/future-native-union/src/lib.rs',
    'poc/future-native-union/src/main.rs',
    'poc/future-native-union/src/native.rs',
    'poc/future-native-union/src/policy.rs',
    'poc/future-private-payment/Cargo.lock',
    'poc/future-private-payment/Cargo.toml',
    'poc/future-private-payment/src/circuit.rs',
    'poc/future-private-payment/src/lib.rs',
    'poc/future-private-payment/tests/public/recipient-v1-core-hash-known-answer.json',
    'poc/future-private-payment/tests/public/recipient-v2-known-answer.json',
    'poc/future-recipient/v2/recipient.py',
    'poc/future-testnet/runner/Cargo.lock',
    'poc/future-testnet/runner/Cargo.toml',
    'poc/future-testnet/runner/src/main.rs',
})


def public_driver_member(relative):
    if relative.is_absolute() or len(relative.parts) != 2:
        return False
    directory, filename = relative.parts
    if directory in ('bodies', 'observations'):
        return filename in {stage + '.json' for stage in STAGES}
    phase = re.fullmatch(r'phase-([345])-[0-9a-f]{32}', directory)
    if phase is None:
        return False
    names = {'archive.json', 'current.json', 'charlie-recovery.json'}
    if phase.group(1) in ('3', '5'):
        names.add('bob-recovery.json')
    return filename in names


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def excerpt(value):
    if isinstance(value, dict):
        return {key: excerpt(item) for key, item in value.items() if key != 'pages'}
    if isinstance(value, list):
        return [excerpt(item) for item in value]
    return value


def publish(trial, destination):
    trial = trial.resolve(strict=True)
    if destination.exists():
        raise ValueError('fresh publication destination required')
    destination.mkdir(parents=True)
    records = []

    def put(source, relative, raw=None, transform='BYTE_IDENTICAL'):
        if (source.is_symlink() or not source.is_file()
                or trial not in source.resolve(strict=True).parents):
            raise ValueError('nonpublic artifact type')
        original = source.read_bytes()
        if original.startswith(b'\x7fELF'):
            raise ValueError('nonpublic artifact type')
        raw = original if raw is None else raw
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(raw)
        records.append({'source_relative_path': str(source.relative_to(trial)),
            'original_bytes': len(original), 'original_sha256': sha(original),
            'published_path': str(relative), 'published_bytes': len(raw),
            'published_sha256': sha(raw), 'transform': transform})

    # Explicit allowlist: no profile, backup, private witness/vector/rho, log,
    # executable or either proving-key representation can enter this loop.
    for name in ('CHAIN-COMPLETE.json', 'LOCAL-COMPLETE.json', 'chain-release.json',
                 'public/identity.json', 'public/recovery-identity.json', 'suite.json',
                 'setup/report.json', 'setup/new-key-selection.json', 'setup/verification-key.bin',
                 'actual-proof/report.json', 'actual-proof/proof128.bin', 'actual-proof/verification-key.bin',
                 'source-workspace/domain-source-manifest.json', 'MOUNTED-BRIDGE-IDENTITY.json'):
        put(trial / name, Path(name))
    chain = trial / 'chain-public'
    # This directory is written only by the public chain driver. Reject any
    # unexpected member instead of recursively copying the trial directory.
    for source in sorted(chain.rglob('*')):
        if not source.is_file():
            continue
        relative = source.relative_to(chain)
        if not public_driver_member(relative):
            raise ValueError('unexpected public-driver member')
        value = json.loads(source.read_bytes())
        selected = excerpt(value)
        raw = encoded(selected) if selected != value else None
        put(source, Path('chain-public') / relative, raw,
            'OMIT_UNRELATED_FULL_HISTORY_PAGES' if raw is not None else 'BYTE_IDENTICAL')
    # Rebind derived archive observation hashes to the excerpts, keeping the
    # original full archive and observation identities in the extraction map.
    for output in destination.glob('chain-public/phase-*/archive.json'):
        value = json.loads(output.read_bytes())
        for operation in value['operations']:
            selected = output.parent / operation['observation_path']
            operation['observation_sha256'] = sha(selected.read_bytes())
        raw = encoded(value)
        output.write_bytes(raw)
        record = next(row for row in records if row['published_path'] == str(output.relative_to(destination)))
        record.update(published_bytes=len(raw), published_sha256=sha(raw),
                      transform='REBIND_OBSERVATION_EXCERPT_FILE_HASHES')
    local = json.loads((trial / 'local-archive.json').read_bytes())
    if [operation['kind'] for operation in local['operations']] != list(STAGES):
        raise ValueError('unexpected local operation set/order')
    for operation in local['operations']:
        for filename in ('transaction.json', 'supplied-context.json', 'native-validation.json',
                         'local-check.json', 'sdk-roundtrip.json'):
            source = Path(operation['accepted_body_path']).parent / filename
            if trial not in source.resolve().parents:
                raise ValueError('local body outside selected trial')
            put(source, Path('local-native') / operation['kind'] / filename)
    for source in sorted((trial / 'chain').glob('*.json')):
        intent_names = {name + '.submission-intent.json'
                        for name in (*STAGES, *(operation['txid_raw_hex'] for operation in local['operations']))}
        result_names = {stage + '.submission-result.json' for stage in STAGES}
        if source.name not in intent_names | result_names:
            raise ValueError('unexpected submission record')
        put(source, Path('chain') / source.name)
    source_manifest = json.loads((trial / 'source-workspace/domain-source-manifest.json').read_bytes())
    if {item['path'] for item in source_manifest['files']} != GENERATED_SOURCE_PATHS:
        raise ValueError('unexpected generated source set')
    for item in source_manifest['files']:
        relative = Path(item['path'])
        if item['path'] not in GENERATED_SOURCE_PATHS:
            raise ValueError('unexpected generated source path')
        source = trial / 'source-workspace' / relative
        if sha(source.read_bytes()) != item['generated_sha256']:
            raise ValueError('generated source identity changed')
        put(source, Path('generated-source') / relative)
    manifest = {'schema': 'kpx2-confirmed-trial-public-extraction/v1',
        'classification': 'ACTUAL_TN10_TEST_KAS_ONLY_TRUSTED_NODE_ARCHIVE',
        'trial_id': json.loads((trial / 'CHAIN-COMPLETE.json').read_bytes())['trial_id'],
        'private_seeds_keys_witnesses_vectors_and_executables_excluded': True,
        'original_full_rpc_history_retained_privately': True,
        'omitted_observer_field': 'pages (unrelated FullV2 chain history only)',
        'records': records}
    (destination / 'EXTRACTION-MANIFEST.json').write_bytes(encoded(manifest))
    return {'published_files': len(records) + 1, 'published_bytes': sum(row['published_bytes'] for row in records),
            'destination': str(destination)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trial', type=Path)
    parser.add_argument('destination', type=Path)
    arguments = parser.parse_args()
    print(json.dumps(publish(arguments.trial, arguments.destination), sort_keys=True))
