#!/usr/bin/env python3
"""Fresh, unfunded KPX2 TN10 identities. No RPC, funding, broadcast or key reuse."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
DOMAIN_TAG = b'KPX2/TN10/TRIAL/v1\0'
OLD_DOMAIN = '9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c'
SCHEMA = 'kpx2-tn10-private-trial/v1'
CLASS = 'PRIVATE_TN10_TEST_KAS_ONLY'
DEFAULT_BRIDGE = ROOT.parent / 'recipient-target/debug/kpi-future-recipient-crypto'
DEFAULT_SDK = Path.home() / '.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/kaspa.js'
SDK_PINS = {
    'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
    'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
    'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0',
}
DOMAIN_FILES = ('poc/future-private-payment/src/lib.rs', 'poc/future-native-union/src/policy.rs')

class Invalid(ValueError):
    pass

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()

def private_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())

def no_symlinks(path):
    for p in (path, *path.parents):
        if p.is_symlink():
            raise Invalid('symlink path rejected')

def outside_git(path):
    no_symlinks(path)
    # An ignored directory still belongs to Git and must not contain secrets.
    probe = path
    while not probe.exists():
        probe = probe.parent
    p = subprocess.run(['git', '-c', 'safe.directory=*', '-C', str(probe),
                        'rev-parse', '--show-toplevel'],
                       capture_output=True, text=True)
    if p.returncode == 0 or path == ROOT or ROOT in path.parents:
        raise Invalid('trial must be outside every Git worktree')

def private_dir(path):
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise Invalid('private directory permissions')

def source_files():
    files = []
    for package in ('future-private-payment', 'future-native-union'):
        base = ROOT / 'poc' / package
        files += [base / 'Cargo.toml', base / 'Cargo.lock']
        files += sorted((base / 'src').rglob('*.rs'))
    # These two published known-answer files are compile-time test includes.
    files += sorted((ROOT / 'poc/future-private-payment/tests/public').glob('*.json'))
    files += [ROOT / 'poc/future-recipient/v2/recipient.py']
    files += [HERE / 'runner/Cargo.toml', HERE / 'runner/Cargo.lock',
              HERE / 'runner/src/main.rs']
    return files

def source_provenance():
    head = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                          check=True, capture_output=True, text=True).stdout.strip()
    return {'base_git_head': head,
        'constructor_sha256': digest(Path(__file__).read_bytes()),
        'address_adapter_sha256': digest((HERE / 'addresses.cjs').read_bytes()),
        'files': {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in source_files()}}

def recipient_module():
    path = ROOT / 'poc/future-recipient/v2/recipient.py'
    spec = importlib.util.spec_from_file_location('kpx2_trial_recipient', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module

def runtime(bridge, sdk):
    bridge = bridge.resolve(strict=True)
    sdk = sdk.resolve(strict=True)
    if not os.access(bridge, os.X_OK):
        raise Invalid('recipient bridge not executable')
    pins = {name: digest((sdk.parent / name).read_bytes()) for name in SDK_PINS}
    if pins != SDK_PINS or digest(sdk.read_bytes()) != SDK_PINS['kaspa.js']:
        raise Invalid('official SDK 2.1.0 identity mismatch')
    return {'bridge_path': str(bridge), 'bridge_sha256': digest(bridge.read_bytes()),
            'sdk_path': str(sdk), 'sdk_file_sha256': pins}

def domain(nonce):
    return digest(DOMAIN_TAG + bytes.fromhex(GENESIS) + nonce)

def new(destination, bridge=DEFAULT_BRIDGE, sdk=DEFAULT_SDK):
    started = time.monotonic()
    destination = destination.expanduser().absolute()
    outside_git(destination)
    if destination.exists():
        raise Invalid('destination already exists; use a fresh identity')
    if not destination.parent.is_dir():
        raise Invalid('destination parent must exist')
    rt = runtime(bridge, sdk)
    recipient = recipient_module()
    crypto = recipient.Crypto(Path(rt['bridge_path']))
    nonce = secrets.token_bytes(32)
    d = bytes.fromhex(domain(nonce))
    seeds = {name: secrets.token_bytes(32) for name in ('alice', 'bob', 'charlie')}
    # The validity check is delegated to established libsecp, never modular reduction.
    while True:
        funding = secrets.token_bytes(32)
        try:
            funding_pk = crypto.xonly(funding)
            break
        except recipient.Invalid as error:
            if str(error) != 'crypto-scalar':
                raise
    private_dir(destination)
    private_dir(destination / 'backups')
    private_dir(destination / 'public')
    # Seed-only backups precede invoice derivation/publication.
    for name, seed in seeds.items():
        private_write(destination / 'backups' / (name + '.json'), encoded({
            'schema': 'kpx2-tn10-seed-backup/v1', 'network_id': 'testnet-10',
            'genesis_hash_hex': GENESIS, 'domain_hex32': d.hex(), 'seed_hex32': seed.hex()}))
    invoices = {name: recipient.Receiver(seed, d, crypto).invoice(0)
                for name, seed in seeds.items()}
    keys = [funding_pk.hex()] + [invoices[n].native_pk.hex() for n in seeds]
    proc = subprocess.run(['node', str(HERE / 'addresses.cjs'), rt['sdk_path']],
                          input=json.dumps(keys), text=True, capture_output=True)
    if proc.returncode:
        raise Invalid('offline SDK address conversion failed')
    addresses = json.loads(proc.stdout)
    identities = {'funding': addresses[0]}
    for name, addr in zip(seeds, addresses[1:]):
        identities[name] = dict(addr, invoice_index=0, invoice_hex208=invoices[name].encode().hex())
    profile = {'schema': SCHEMA, 'classification': CLASS,
        'secret_origin': 'OS_RANDOM_NEW_TN10_TRIAL/v1', 'trial_id': str(uuid.uuid4()),
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'network_id': 'testnet-10', 'genesis_hash_hex': GENESIS,
        'domain_tag_hex': DOMAIN_TAG.hex(), 'domain_nonce_hex32': nonce.hex(),
        'domain_hex32': d.hex(), 'status': 'unfunded', 'runtime': rt,
        'secrets': {**{name + '_seed_hex32': seed.hex() for name, seed in seeds.items()},
                    'funding_secret_hex32': funding.hex()},
        'identities': identities, 'source_provenance': source_provenance(),
        'selected_suite': None, 'selected_vk': None, 'funding_utxo': None,
        'accepted_chain_backing': False, 'payout_confirmed': False}
    private_write(destination / 'profile.json', encoded(profile))
    public = {k: v for k, v in profile.items() if k not in ('secrets', 'runtime')}
    public['scope'] = 'UNFUNDED_IDENTITY_ONLY_NO_BUILD_SETUP_OR_BROADCAST'
    private_write(destination / 'public/identity.json', encoded(public))
    return {'trial_directory': str(destination), 'trial_id': profile['trial_id'],
            'domain_hex32': d.hex(), 'network_id': 'testnet-10', 'status': 'unfunded',
            'elapsed_seconds': round(time.monotonic() - started, 3)}

def load_profile(trial):
    trial = trial.expanduser().absolute()
    outside_git(trial)
    if stat.S_IMODE(trial.stat().st_mode) != 0o700:
        raise Invalid('trial directory must be 0700')
    path = trial / 'profile.json'
    no_symlinks(path)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise Invalid('profile must be 0600')
    p = json.loads(path.read_bytes())
    try:
        valid = (p['schema'] == SCHEMA and p['classification'] == CLASS and
            p['secret_origin'] == 'OS_RANDOM_NEW_TN10_TRIAL/v1' and
            p['network_id'] == 'testnet-10' and p['genesis_hash_hex'] == GENESIS and
            p['domain_tag_hex'] == DOMAIN_TAG.hex() and
            re.fullmatch('[0-9a-f]{64}', p['domain_nonce_hex32']) is not None and
            p['domain_hex32'] == domain(bytes.fromhex(p['domain_nonce_hex32'])) and
            p['domain_hex32'] != OLD_DOMAIN)
    except (KeyError, ValueError, TypeError):
        valid = False
    if not valid:
        raise Invalid('wrong private TN10 identity/domain/genesis')
    return p

def replace_domain(raw, d):
    text = raw.decode()
    pattern = r'(pub const DOMAIN: (?:H|\[u8; 32\]) = \[)(.*?)(\n\];)'
    matches = list(re.finditer(pattern, text, re.S))
    if len(matches) != 1:
        raise Invalid('expected exactly one authoritative DOMAIN declaration')
    old = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-f]{2})', matches[0].group(2)))
    if old.hex() != OLD_DOMAIN:
        raise Invalid('authoritative old domain changed; no speculative substitution')
    body = '\n' + '\n'.join('    ' + ', '.join(f'0x{x:02x}' for x in row) + ','
                              for row in (d[:16], d[16:]))
    return re.sub(pattern, lambda m: m.group(1) + body + m.group(3), text, count=1,
                  flags=re.S).encode()

def materialize(trial):
    profile = load_profile(trial)
    trial = trial.expanduser().absolute()
    if profile['status'] != 'unfunded':
        raise Invalid('source materialization requires an unused unfunded identity')
    target = trial / 'source-workspace'
    if target.exists():
        raise Invalid('source workspace already exists')
    sources = profile['source_provenance']['files']
    if set(sources) != {str(p.relative_to(ROOT)) for p in source_files()}:
        raise Invalid('source allowlist changed since identity creation')
    # Validate all base bytes before creating any generated sources.
    raw_sources = {name: (ROOT / name).read_bytes() for name in sources}
    if any(digest(raw_sources[n]) != sha for n, sha in sources.items()):
        raise Invalid('authoritative source changed since identity creation')
    private_dir(target)
    records = []
    for name, raw in raw_sources.items():
        generated = replace_domain(raw, bytes.fromhex(profile['domain_hex32'])) if name in DOMAIN_FILES else raw
        path = target / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # pathlib parents honors umask; enforce private source directories too.
        for parent in path.parents:
            if parent == trial:
                break
            parent.chmod(0o700)
        private_write(path, generated)
        records.append({'path': name, 'base_sha256': digest(raw),
                        'generated_sha256': digest(generated), 'domain_replaced': name in DOMAIN_FILES})
    manifest = {'schema': 'kpx2-tn10-domain-source/v1', 'classification': CLASS,
        'trial_id': profile['trial_id'], 'domain_hex32': profile['domain_hex32'],
        'genesis_hash_hex': GENESIS, 'network_id': 'testnet-10',
        'transformation': 'Only the two exact DOMAIN byte-array declarations are replaced.',
        'base_git_head': profile['source_provenance']['base_git_head'], 'files': records,
        'build_performed': False, 'setup_performed': False, 'old_pk_or_vk_copied': False}
    private_write(target / 'domain-source-manifest.json', encoded(manifest))
    return {'source_workspace': str(target), 'manifest_sha256': digest(encoded(manifest)),
            'domain_hex32': profile['domain_hex32'], 'files': len(records),
            'matching_fresh_setup_required': True}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    n = sub.add_parser('new')
    n.add_argument('--network', required=True, choices=['testnet-10'])
    n.add_argument('--bridge', type=Path, default=DEFAULT_BRIDGE)
    n.add_argument('--sdk', type=Path, default=DEFAULT_SDK)
    n.add_argument('destination', type=Path)
    m = sub.add_parser('materialize')
    m.add_argument('trial', type=Path)
    args = parser.parse_args()
    try:
        result = new(args.destination, args.bridge, args.sdk) if args.command == 'new' else materialize(args.trial)
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        # Never echo runtime input or private JSON/secret values.
        message = str(error) if isinstance(error, Invalid) else type(error).__name__
        print('TN10 constructor: ' + message, file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
