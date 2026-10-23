#!/usr/bin/env python3
"""Fresh unfunded Auth528 TN10 identities. No node, setup or broadcast API."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import types
import uuid

ROOT = Path(__file__).resolve().parents[2]
ADR = ROOT / 'docs/adr/0053-private-network-recovery-and-local-owner-proving.md'
# Selected by the coordinator only after the ADR/API freeze; no runtime override.
SELECTED_ADR_SHA256 = 'dd77b305df860011ae6608e312eb09396f2c6585fa17225646bdb8f181fa9b58'
CONTRACT = ROOT / 'research/next-session/private-service-loss/CONTRACT.md'
SELECTED_CONTRACT_SHA256 = '16679d12132ca437624e0878dc5fc5140889d56e5f376d4459b362bb86b9df94'
RUNTIME_ADR = ROOT / 'docs/adr/0054-trusted-read-only-executable-releases.md'
RUNTIME_ADR_SHA256 = '2319c8d3cbd59f2b59b1087f947f796e852a43c02d13a09573ce0695aaaffff4'
# Populated only from the independently reviewed template-source selection.
# Unfunded identity creation does not depend on a prover build or template.
TEMPLATE_FREEZE = ROOT / 'research/next-session/private-service-loss/prover/TEMPLATE-SOURCE-FREEZE-01.json'
SELECTED_TEMPLATE_FREEZE_SHA256 = 'b207222c4f7dda52a88e8682fed5af8eec521ac1ac678ab1077128ffee74d3ec'
GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
DOMAIN_TAG = b'KPX3/TN10/PRIVATE-RECOVERY/v1\0'
AA_DOMAIN = 'aa39ad5d2da85dfd1695cc74ce3e0f23e713f315d6e5341bccc8a060111354c2'
OLD_DOMAIN = '9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c'
SCHEMA = 'kpx3-tn10-private-trial/v1'
CLASS = 'PRIVATE_TN10_TEST_KAS_ONLY'
PROGRAM = 'AUTH528_PRIVATE_CASHOUT/v1'
PROVER = ROOT / 'poc/private-cashout-prover'
RELEASE = Path.home() / '.local/share/kpi-private-cashout-trial-runtime/adr0054-01'
DEFAULT_BRIDGE = RELEASE / 'crypto'
NODE = Path.home() / '.local/share/kpi-private-network-runtime/adr0054-01/node'
NODE_SHA = 'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c'
DEFAULT_SDK = Path.home() / '.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/kaspa.js'
BRIDGE_SHA = '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'
RECIPIENT_SHA = '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'
ADDRESSES_SHA = '62d8a3ef6e6b8a64c0d308ac82ed4bf0b0b68b10094ab083adfc977c7b3a2666'
TRUSTED_RUNTIME_SHA = '3ce31ae0eb8f942009a4108f9a5dbb6a08df6c7f0925f06a952315091e1bbd1c'
SDK_PINS = {
    'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
    'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
    'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0',
}


def require(condition, category):
    if not condition:
        raise ValueError(category)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def parse_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def selected_adr():
    require(isinstance(SELECTED_ADR_SHA256, str) and len(SELECTED_ADR_SHA256) == 64,
            'adr0053-selection-required-before-entropy')
    require(digest(ADR.read_bytes()) == SELECTED_ADR_SHA256, 'selected-adr0053-changed')
    require(digest(CONTRACT.read_bytes()) == SELECTED_CONTRACT_SHA256,
            'selected-common-contract-changed')
    require(digest(RUNTIME_ADR.read_bytes()) == RUNTIME_ADR_SHA256,'selected-runtime-ADR0054-changed')
    return SELECTED_ADR_SHA256


def no_symlinks(path):
    require(not any(part.is_symlink() for part in (path, *path.parents)), 'symlink-path')


def outside_git(path):
    path = Path(path).expanduser().absolute()
    no_symlinks(path)
    path = Path(os.path.normpath(path))
    probe = path
    while not probe.exists():
        probe = probe.parent
    if not probe.is_dir():
        probe = probe.parent
    result = subprocess.run(['git', '-c', 'safe.directory=*', '-C', str(probe),
                             'rev-parse', '--show-toplevel'], capture_output=True)
    require(result.returncode != 0 and ROOT != path and ROOT not in path.parents,
            'private-material-inside-git')
    return path


def sync_parent(path):
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_write(path, raw):
    no_symlinks(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as file:
        os.fchmod(file.fileno(), 0o600)
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())
    sync_parent(path)


def private_dir(path):
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    sync_parent(path)


def source_provenance():
    require(type(SELECTED_TEMPLATE_FREEZE_SHA256) is str,
            'reviewed-template-source-selection-required')
    require(PROVER.is_dir(), 'new-private-prover-template-required')
    raw = TEMPLATE_FREEZE.read_bytes()
    require(digest(raw) == SELECTED_TEMPLATE_FREEZE_SHA256, 'selected-template-source-freeze')
    freeze = parse_json(raw)
    require(freeze['schema'] == 'kpx3-unselected-template-source-freeze/v1'
            and freeze['authority_adr_sha256'] == selected_adr()
            and freeze['common_contract_sha256'] == SELECTED_CONTRACT_SHA256,
            'template-source-authority')
    records = {}
    for entry in freeze['files']:
        relative = Path(entry['path'])
        require(not relative.is_absolute() and '..' not in relative.parts
                and relative.parts[:2] == ('poc', 'private-cashout-prover')
                and str(relative) not in records, 'template-source-allowlist-path')
        path = ROOT / relative
        no_symlinks(path)
        data = path.read_bytes()
        require(path.is_file() and len(data) == entry['bytes']
                and digest(data) == entry['sha256'], 'reviewed-template-source-changed')
        records[str(relative)] = entry['sha256']
    return {'base_git_head': subprocess.check_output(
                ['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
            'constructor_sha256': digest(Path(__file__).read_bytes()),
            'template_source_freeze_sha256': SELECTED_TEMPLATE_FREEZE_SHA256,
            'selected_adr_sha256': selected_adr(), 'files': records,
            'old_proving_key_or_profile_loaded': False}


def identity_provenance():
    selected_adr()
    return {'base_git_head': subprocess.check_output(
                ['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
        'constructor_sha256': digest(Path(__file__).read_bytes()),
        'selected_adr_sha256': SELECTED_ADR_SHA256,
        'selected_common_contract_sha256': SELECTED_CONTRACT_SHA256,
        'runtime_ADR0054_sha256': RUNTIME_ADR_SHA256,
        'recipient_source_sha256': RECIPIENT_SHA, 'address_adapter_sha256': ADDRESSES_SHA,
        'prover_template_not_yet_selected_or_built': True,
        'old_proving_key_or_profile_loaded': False}


def runtime(bridge, sdk):
    selected_adr()
    for path in (bridge, sdk):
        no_symlinks(path.absolute())
    bridge, sdk = bridge.resolve(strict=True), sdk.resolve(strict=True)
    require(os.access(bridge, os.X_OK) and digest(bridge.read_bytes()) == BRIDGE_SHA,
            'selected-crypto-bridge')
    pins = {name: digest((sdk.parent / name).read_bytes()) for name in SDK_PINS}
    require(pins == SDK_PINS, 'official-sdk21-identity')
    addresses = ROOT / 'poc/future-testnet/addresses.cjs'
    recipient = ROOT / 'poc/future-recipient/v2/recipient.py'
    recipient_raw = recipient.read_bytes()
    require(digest(addresses.read_bytes()) == ADDRESSES_SHA
            and digest(recipient_raw) == RECIPIENT_SHA, 'stateless-source-identity')
    # Execute the same authenticated owned source bytes, never a later reopen.
    module = types.ModuleType('_private_cashout_recipient')
    module.__file__ = str(recipient)
    sys.modules[module.__name__] = module
    exec(compile(recipient_raw, str(recipient), 'exec'), module.__dict__)
    runtime_module=trusted_runtime()
    with runtime_module.TrustedExecutable(NODE,NODE_SHA) as node_runtime:
        node=node_runtime.run(['--version'])
        require(node.returncode==0 and node.stdout.startswith('v'),'selected-node-runtime-preflight')

    class TrustedCrypto(module.Crypto):
        def __init__(self):
            self.executable = bridge
            self.runtime_handle = runtime_module.TrustedExecutable(bridge, BRIDGE_SHA)

        def close(self):
            self.runtime_handle.close()

        def call(self, op, *, secret=None, public=None, payload=None):
            request = {'op': op}
            for key, value in (('secret_hex', secret), ('public_hex', public), ('payload_hex', payload)):
                if value is not None:
                    request[key] = value.hex()
            process = self.runtime_handle.run([], input_text=json.dumps(request))
            try:
                result = parse_json(process.stdout)
            except (ValueError, KeyError, TypeError):
                raise module.Invalid('crypto-adapter') from None
            if process.returncode or 'error' in result:
                raise module.Invalid('crypto-' + str(result.get('error', 'adapter')))
            try:
                return bytes.fromhex(result['hex'])
            except (ValueError, KeyError, TypeError):
                raise module.Invalid('crypto-adapter') from None

    crypto = TrustedCrypto()
    return module, crypto, {'bridge_path': str(bridge), 'bridge_sha256': BRIDGE_SHA,
        'bridge_runtime': crypto.runtime_handle.receipt(), 'sdk_path': str(sdk),
        'sdk_file_sha256': pins}


def trusted_runtime():
    path=ROOT/'poc/private-network-recovery/trusted_runtime.py'
    raw=path.read_bytes()
    require(digest(raw)==TRUSTED_RUNTIME_SHA,'selected-ordinary-runtime-source')
    module=types.ModuleType('_private_cashout_trusted_runtime')
    module.__file__=str(path);sys.modules[module.__name__]=module
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def node_run(arguments,input_text=None):
    with trusted_runtime().TrustedExecutable(NODE,NODE_SHA) as node:
        return node.run(arguments,input_text=input_text)


def domain(nonce):
    require(type(nonce) is bytes and len(nonce) == 32, 'nonce-width')
    return digest(DOMAIN_TAG + bytes.fromhex(GENESIS) + nonce)


def new(destination, bridge=DEFAULT_BRIDGE, sdk=DEFAULT_SDK):
    started = time.monotonic()
    selected_adr()  # Must precede every entropy operation and private artifact.
    destination = outside_git(destination)
    require(not destination.exists() and destination.parent.is_dir(), 'fresh-private-destination')
    provenance = identity_provenance()
    module, crypto, rt = runtime(bridge, sdk)
    try:
        return create_identity(destination, module, crypto, rt, provenance, started)
    finally:
        crypto.close()


def create_identity(destination, module, crypto, rt, provenance, started):
    selected_adr()
    nonce = secrets.token_bytes(32)
    d = bytes.fromhex(domain(nonce))
    require(d != bytes(32) and d.hex() not in (AA_DOMAIN, OLD_DOMAIN), 'fresh-domain')
    seeds = {name: secrets.token_bytes(32) for name in ('alice', 'bob', 'charlie')}
    while True:
        funding = secrets.token_bytes(32)
        try:
            funding_pk = crypto.xonly(funding)
            break
        except module.Invalid as error:
            if str(error) != 'crypto-scalar':
                raise
    private_dir(destination)
    private_dir(destination / 'backups')
    private_dir(destination / 'public')
    for name, seed in seeds.items():
        private_write(destination / 'backups' / (name + '.json'), encoded({
            'schema': 'kpx2-tn10-seed-backup/v1', 'network_id': 'testnet-10',
            'genesis_hash_hex': GENESIS, 'domain_hex32': d.hex(), 'seed_hex32': seed.hex()}))
    invoices = {name: module.Receiver(seed, d, crypto).invoice(0).encode().hex()
                for name, seed in seeds.items()}
    process=node_run([str(ROOT/'poc/future-testnet/addresses.cjs'),rt['sdk_path']],
                     input_text=json.dumps([funding_pk.hex()]))
    require(process.returncode == 0, 'offline-funding-address')
    funding_destination = parse_json(process.stdout)[0]
    require(set(funding_destination) == {'xonly_hex32', 'address', 'spk_version', 'spk_hex'}
            and funding_destination['xonly_hex32'] == funding_pk.hex()
            and funding_destination['spk_version'] == 0
            and funding_destination['spk_hex'] == '20' + funding_pk.hex() + 'ac'
            and funding_destination['address'].startswith('kaspatest:'), 'funding-public-key-binding')
    funding_destination['canonical_spk_hex'] = '0000' + funding_destination['spk_hex']
    public = {'schema': SCHEMA, 'program_label': PROGRAM, 'classification': CLASS,
        'trial_id': str(uuid.uuid4()), 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'network_id': 'testnet-10', 'genesis_hash_hex': GENESIS, 'domain_tag_hex': DOMAIN_TAG.hex(),
        'domain_nonce_hex32': nonce.hex(), 'domain_hex32': d.hex(), 'status': 'unfunded',
        'funding_destination': funding_destination, 'source_provenance': provenance,
        'accepted_chain_backing': False, 'payout_confirmed': False}
    profile = {**public, 'secret_origin': 'OS_RANDOM_FRESH_AUTH528_TN10/v1', 'runtime': rt,
        'secrets': {**{name + '_seed_hex32': seed.hex() for name, seed in seeds.items()},
                    'funding_secret_hex32': funding.hex()}, 'private_invoices_hex208': invoices,
        'selected_setup': None, 'selected_vk': None, 'funding_utxo': None}
    private_write(destination / 'profile.json', encoded(profile))
    private_write(destination / 'public/identity.json', encoded(public))
    return {'trial_directory': str(destination), 'trial_id': public['trial_id'],
        'domain_hex32': d.hex(), 'program_label': PROGRAM, 'status': 'unfunded',
        'elapsed_seconds': round(time.monotonic() - started, 3)}


def load_profile(directory):
    selected_adr()
    directory = outside_git(directory)
    require(stat.S_IMODE(directory.stat().st_mode) == 0o700, 'trial-directory-mode')
    path = directory / 'profile.json'
    require(path.is_file() and not path.is_symlink()
            and stat.S_IMODE(path.stat().st_mode) == 0o600, 'private-profile-mode')
    value = parse_json(path.read_bytes())
    require(value['schema'] == SCHEMA and value['classification'] == CLASS
            and value['program_label'] == PROGRAM and value['network_id'] == 'testnet-10'
            and value['genesis_hash_hex'] == GENESIS
            and value['domain_tag_hex'] == DOMAIN_TAG.hex()
            and value['secret_origin'] == 'OS_RANDOM_FRESH_AUTH528_TN10/v1'
            and value['domain_hex32'] == domain(bytes.fromhex(value['domain_nonce_hex32']))
            and value['domain_hex32'] not in (AA_DOMAIN, OLD_DOMAIN)
            and value['source_provenance']['selected_adr_sha256'] == selected_adr(),
            'fresh-auth528-profile-identity')
    return directory, value


def replace_domain(raw, selected):
    text = raw.decode()
    pattern = r'(pub const DOMAIN: (?:H|\[u8; 32\]) = \[)(.*?)(\n\];)'
    matches = list(re.finditer(pattern, text, re.S))
    require(len(matches) == 1, 'one-authoritative-domain-array')
    base = bytes(int(value, 16) for value in re.findall(r'0x([0-9a-f]{2})', matches[0].group(2)))
    require(base.hex() == AA_DOMAIN and len(selected) == 32
            and selected.hex() not in (AA_DOMAIN, OLD_DOMAIN), 'exact-template-domain')
    body = '\n' + '\n'.join('    ' + ', '.join(f'0x{x:02x}' for x in row) + ','
                              for row in (selected[:16], selected[16:]))
    return re.sub(pattern, lambda match: match.group(1) + body + match.group(3), text,
                  count=1, flags=re.S).encode()


def materialize_source(directory):
    directory, profile = load_profile(directory)
    require(profile['status'] == 'unfunded', 'unfunded-source-materialization')
    target = directory / 'source-workspace'
    require(not target.exists(), 'fresh-source-workspace')
    expected = source_provenance()['files']
    raw_sources = {name: (ROOT / name).read_bytes() for name in expected}
    require(all(digest(raw_sources[name]) == sha for name, sha in expected.items()),
            'template-source-bytes-changed')
    pin_path = 'poc/private-cashout-prover/trial-selection.json'
    require(pin_path in raw_sources and parse_json(raw_sources[pin_path]) ==
            {'schema': 'kpx3-selected-private-trial-source/v1', 'selected': False},
            'exact-unselected-trial-template')
    selected = {'schema': 'kpx3-selected-private-trial-source/v1', 'selected': True,
        **{name: profile[name] for name in
           ('trial_id', 'network_id', 'genesis_hash_hex', 'domain_hex32', 'program_label')}}
    private_dir(target)
    records = []
    for name, raw in raw_sources.items():
        generated = (replace_domain(raw, bytes.fromhex(profile['domain_hex32']))
                     if name == 'poc/private-cashout-prover/src/lib.rs' else
                     encoded(selected) if name == pin_path else raw)
        path = target / name
        missing = []
        parent = path.parent
        while parent != target and not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for parent in reversed(missing):
            private_dir(parent)
        private_write(path, generated)
        records.append({'path': name, 'base_sha256': digest(raw),
            'generated_sha256': digest(generated), 'bytes': len(generated),
            'transformation': 'DOMAIN_ARRAY' if name.endswith('/src/lib.rs') else
                'PUBLIC_TRIAL_SELECTION' if name == pin_path else 'UNCHANGED'})
    manifest = {'schema': 'kpx3-fresh-private-trial-source/v1', 'classification': CLASS,
        'trial_id': profile['trial_id'], 'domain_hex32': profile['domain_hex32'],
        'selected_adr_sha256': selected_adr(), 'files': records,
        'template_source_freeze_sha256': SELECTED_TEMPLATE_FREEZE_SHA256,
        'proving_key_or_matrix_copied': False, 'build_or_setup_performed': False}
    private_write(target / 'SOURCE-MANIFEST.json', encoded(manifest))
    return {'source_manifest': str(target / 'SOURCE-MANIFEST.json'),
            'source_files': len(records), 'domain_hex32': profile['domain_hex32'],
            'build_or_setup_performed': False}


def build_setup(directory, jobs):
    directory, profile = load_profile(directory)
    require(type(jobs) is int and jobs > 0, 'positive-build-jobs')
    target = directory / 'source-workspace'
    manifest = parse_json((target / 'SOURCE-MANIFEST.json').read_bytes())
    require(manifest['trial_id'] == profile['trial_id']
            and manifest['domain_hex32'] == profile['domain_hex32']
            and manifest['selected_adr_sha256'] == selected_adr()
            and manifest['template_source_freeze_sha256'] == SELECTED_TEMPLATE_FREEZE_SHA256,
            'generated-source-identity')
    expected = source_provenance()['files']
    require({row['path'] for row in manifest['files']} == set(expected), 'generated-source-allowlist')
    pins = encoded({'schema': 'kpx3-selected-private-trial-source/v1', 'selected': True,
        **{name: profile[name] for name in
           ('trial_id', 'network_id', 'genesis_hash_hex', 'domain_hex32', 'program_label')}})
    for entry in manifest['files']:
        path = target / entry['path']
        no_symlinks(path)
        original = (ROOT / entry['path']).read_bytes()
        generated = (replace_domain(original, bytes.fromhex(profile['domain_hex32']))
            if entry['path'] == 'poc/private-cashout-prover/src/lib.rs' else
            pins if entry['path'] == 'poc/private-cashout-prover/trial-selection.json' else original)
        require(entry['base_sha256'] == expected[entry['path']]
                and path.is_file() and path.read_bytes() == generated
                and len(generated) == entry['bytes']
                and digest(generated) == entry['generated_sha256'], 'generated-source-changed')
    build = directory / 'setup-build'
    require(not build.exists(), 'fresh-source-build-directory')
    private_dir(build)
    command = ['cargo', 'build', '--release', '--locked', '--offline', '--manifest-path',
        str(target / 'poc/private-cashout-prover/Cargo.toml'), '--target-dir', str(build),
        '--jobs', str(jobs), '--bin', 'kpi-private-cashout-setup']
    with (build / 'build.log').open('xb') as log:
        os.fchmod(log.fileno(), 0o600)
        process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        log.flush()
        os.fsync(log.fileno())
    require(process.returncode == 0, 'source-matching-build-failed')
    executable = build / 'release/kpi-private-cashout-setup'
    require(executable.is_file() and executable.read_bytes()[:4] == b'\x7fELF', 'setup-executable')
    result = {'schema': 'kpx3-source-matching-setup-build/v1', 'classification': CLASS,
        'trial_id': profile['trial_id'], 'domain_hex32': profile['domain_hex32'],
        'source_manifest_sha256': digest((target / 'SOURCE-MANIFEST.json').read_bytes()),
        'executable': str(executable), 'executable_sha256': digest(executable.read_bytes()),
        'command': command, 'setup_or_proof_performed': False}
    private_write(build / 'BUILD.json', encoded(result))
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('new')
    create.add_argument('destination', type=Path)
    create.add_argument('--crypto', type=Path, default=DEFAULT_BRIDGE)
    create.add_argument('--sdk', type=Path, default=DEFAULT_SDK)
    materialize = sub.add_parser('materialize-source')
    materialize.add_argument('trial', type=Path)
    build = sub.add_parser('build-setup')
    build.add_argument('trial', type=Path)
    build.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    try:
        result = (new(args.destination, args.crypto, args.sdk) if args.command == 'new' else
                  materialize_source(args.trial) if args.command == 'materialize-source' else
                  build_setup(args.trial, args.jobs))
        print(json.dumps(result, sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        # Never include adapter input/output, private paths or an exception traceback.
        print('private cashout trial refused: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
