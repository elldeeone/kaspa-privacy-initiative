#!/usr/bin/env python3
"""Materialize only the ADR0060 source identity changes from fixed Git preimages.

No build, setup, cryptographic operation, witness, PK or owner backup is read.
The generator refuses reused destinations and source drift before writing.
"""
from pathlib import Path
import hashlib
import json
import re
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PHASE = ROOT / 'research/next-session/four-wallet-testnet/profile'
BASELINE = 'b7b41ab066807d7859499b3491a663ab110fedf9'
CLASSIFICATION = 'TESTNET_REHEARSAL_ONLY_ADR0060'
PROGRAM_LABEL = 'AUTH528_PRIVATE_FOUR_WALLET_TESTNET/v1'
UNUSED_WIDE = 'UNSELECTED_WIDE_VIRTUAL_ONLY'


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def git(*args):
    return subprocess.run(['git', *args], cwd=ROOT, capture_output=True, check=True).stdout


def patch(raw, old, new, count=1):
    need(raw.count(old) == count, 'source-patch-preimage-count')
    return raw.replace(old, new)


def domain(raw, value):
    pattern = rb'pub const DOMAIN: (?:H|\[u8; 32\]) = \[[\s\S]*?\];'
    matched = list(re.finditer(pattern, raw))
    need(len(matched) == 1, 'compiled-domain-preimage')
    declaration = matched[0].group().split(b' = [', 1)[0]
    replacement = declaration + b' = [\n    ' + ', '.join(map(str, value)).encode() + b',\n];'
    return raw[:matched[0].start()] + replacement + raw[matched[0].end():]


def main():
    identity = json.loads((HERE / 'profile-identity.json').read_bytes())
    need(identity['classification'] == CLASSIFICATION
         and identity['source_baseline_commit'] == BASELINE
         and identity['network_id'] == 'testnet-10', 'selected-root-profile-identity')
    child = bytes.fromhex(identity['child_domain_hex32'])
    need(len(child) == 32 and child != bytes(32)
         and identity['wrapper_domain_hex32'] != child.hex(), 'new-profile-domains')
    profile_id = identity['financial_profile_id'].encode()
    plan = []

    def add_tree(source, target, predicate=lambda _: True):
        names = git('ls-tree', '-r', '--name-only', BASELINE, '--', source).decode().splitlines()
        need(names, 'source-tree-missing')
        for name in names:
            relative = Path(name).relative_to(source)
            if predicate(relative):
                plan.append((name, HERE / target / relative))

    add_tree('poc/private-exit-stress/prover', 'prover')
    add_tree('poc/private-exit-stress/native', 'child-native',
             lambda n: n.name in ('Cargo.toml', 'Cargo.lock') or n.parts[0] == 'src')
    for part in ('common', 'guest', 'host'):
        add_tree('poc/shared-settlement-proof/' + part, 'proof/' + part)
    add_tree('poc/shared-settlement-native', 'native',
             lambda n: n.name in ('Cargo.toml', 'Cargo.lock', 'NOTICE') or n.parts[0] == 'src')
    output = []
    maps = []
    for original, target in plan:
        raw = git('show', BASELINE + ':' + original)
        source = ROOT / original
        need(source.is_file() and not source.is_symlink() and source.read_bytes() == raw,
             'historical-source-drift')
        relative = target.relative_to(HERE).as_posix()
        result, changes = raw, []
        if relative in ('prover/src/lib.rs', 'child-native/src/policy.rs', 'native/src/policy.rs'):
            result = domain(result, child); changes.append('exact-new-compiled-child-domain')
        if relative == 'prover/src/parameters.rs':
            result = patch(result, b'AUTH528_PRIVATE_CAPACITY_EXIT/v1', PROGRAM_LABEL.encode(), count=3)
            result = patch(result, b'|| trial.trial_id.is_empty()',
                b'|| trial.trial_id != "' + profile_id + b'"')
            changes += ['exact-financial-program-label', 'exact-stable-profile-ID']
        if relative == 'prover/trial-selection.json':
            result = encoded({'schema': 'kpx4-selected-compact-batch-source/v1',
                'selected': True, 'trial_id': identity['financial_profile_id'],
                'network_id': identity['network_id'], 'genesis_hash_hex': identity['genesis_hash_hex'],
                'domain_hex32': child.hex(), 'program_label': PROGRAM_LABEL,
                'auth_magic_hex8': '4b50583441553031'})
            changes.append('public-stable-profile-selection-not-operational-trial')
        if relative.startswith('prover/pins/'):
            role = target.parent.name
            if target.name == 'verification-key.bin':
                result = bytes(328)
            elif target.name == 'parameter-selection.json':
                result = encoded({'schema': 'kpx4-public-parameter-selection/v1',
                                  'selected': False, 'role': role})
            elif target.name == 'public-parameters.json':
                result = b'{}'
            else:
                raise ValueError('unexpected-parameter-pin-file')
            changes.append('fresh-unselected-role-no-old-parameters-or-VK')
        if relative == 'proof/common/Cargo.toml':
            result = patch(result, b'../../accelerated-bn254/common', b'../../../accelerated-bn254/common')
            changes.append('same-trusted-generic-dependency-new-relative-path')
        if relative == 'proof/host/Cargo.toml':
            result = patch(result, b'../../private-note-proof', b'../../../private-note-proof')
            changes.append('same-trusted-receipt-checks-new-relative-path')
        if relative == 'proof/common/src/lib.rs':
            result = patch(result, b'PUBLIC_SYNTHETIC_DO_NOT_FUND_UNFUNDED_BENCHMARK_ONLY',
                           CLASSIFICATION.encode())
            result = patch(result, b'    owner_witness_or_funding_authority: bool,',
                b'    owner_witness_or_funding_authority: bool,\n    unused_wide_virtual_key_policy: String,')
            result = patch(result, b'&& !f.trial_id.is_empty()',
                b'&& f.trial_id == "' + profile_id + b'"')
            result = patch(result, b'&& !f.owner_witness_or_funding_authority,',
                b'&& !f.owner_witness_or_funding_authority\n'
                b'                && f.unused_wide_virtual_key_policy == "UNSELECTED_WIDE_VIRTUAL_ONLY",')
            result = patch(result, b'&& tail.windows(raw.len()).filter(|w| *w == raw).count() == 1,',
                b'&& tail.windows(raw.len()).filter(|w| *w == raw).count() == 1\n'
                b'                && tail.windows(328).filter(|w| *w == [0u8; 328]).count() == 1,')
            changes += ['exact-financial-classification-and-stable-ID',
                        'explicit-unselected-wide-virtual-only-sentinel-unique']
        if relative == 'proof/host/src/main.rs':
            result = patch(result, b'|| v["selected"] != true',
                b'|| v["selected"] != true\n'
                b'        || v["classification"] != "' + CLASSIFICATION.encode() + b'"\n'
                b'        || v["financial_profile_id"] != "' + profile_id + b'"')
            changes.append('exact-outer-financial-classification-and-stable-ID')
        if relative in ('native/src/main.rs', 'native/src/policy.rs'):
            result = patch(result, b'../../shared-settlement-proof/child-profile.json',
                           b'../../proof/child-profile.json')
            changes.append('exact-new-child-profile-include-path')
        if relative == 'native/src/policy.rs':
            result = patch(result, b'if value["selected"] != true',
                b'if value["selected"] != true\n'
                b'            || value["classification"] != "' + CLASSIFICATION.encode() + b'"\n'
                b'            || value["trial_id"] != "' + profile_id + b'"\n'
                b'            || value["owner_witness_or_funding_authority"] != false\n'
                b'            || value["unused_wide_virtual_key_policy"] != "UNSELECTED_WIDE_VIRTUAL_ONLY"')
            result = patch(result, b'if tail.is_empty() || tail.len() + 114 > u16::MAX as usize {',
                b'if tail.is_empty() || tail.len() + 114 > u16::MAX as usize\n'
                b'            || tail.windows(328).filter(|w| *w == compact_vk).count() != 1\n'
                b'            || tail.windows(328).filter(|w| *w == [0u8; 328]).count() != 1 {')
            changes += ['exact-financial-classification-and-stable-ID',
                        'unique-compact-and-disabled-wide-virtual-slots']
        need(not target.exists() and not any(p.is_symlink() for p in (target, *target.parents)),
             'fresh-generated-source-destination')
        output.append((target, result))
        maps.append({'original': original, 'original_bytes': len(raw),
            'original_sha256': sha(raw), 'copy': str(target.relative_to(ROOT)),
            'copied_bytes': len(result), 'copied_sha256': sha(result), 'changes': changes})
    metadata = {
        HERE / 'proof/child-profile.json': {
            'schema': 'kpx5-public-virtual-settlement-child-profile/v1', 'selected': False,
            'classification': CLASSIFICATION, 'trial_id': identity['financial_profile_id'],
            'wrapper_domain_hex32': identity['wrapper_domain_hex32'], 'child_domain_hex32': child.hex(),
            'child_role': 'compact2', 'child_mode': 2, 'child_count': 2,
            'child_vk_hex328': None, 'child_vk_sha256': None, 'child_template_tail_hex': None,
            'child_parameter_manifest_sha256': None, 'journal_bytes': 424, 'payload_bytes': 8108,
            'owner_witness_or_funding_authority': False, 'unused_wide_virtual_key_policy': UNUSED_WIDE},
        HERE / 'proof/outer-selection.json': {
            'schema': 'kpx5-public-virtual-settlement-outer-selection/v1', 'selected': False,
            'classification': CLASSIFICATION, 'financial_profile_id': identity['financial_profile_id'],
            'journal_bytes': 424, 'image_id_hex32': None, 'program_sha256': None,
            'funding_or_chain_currentness_authority': False},
    }
    for target, value in metadata.items():
        need(not target.exists(), 'fresh-profile-metadata')
        output.append((target, encoded(value)))
    map_path = PHASE / 'SOURCE-GENERATION-MAP-01.json'
    need(not map_path.exists(), 'fresh-source-generation-map')
    for target, result in output:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as file:
            file.write(result)
    report = {'schema': 'kpx6-financial-profile-source-generation/v1',
        'source_baseline_commit': BASELINE, 'classification': CLASSIFICATION,
        'financial_profile_id': identity['financial_profile_id'], 'files': maps,
        'new_metadata': [{'path': str(p.relative_to(ROOT)), 'bytes': p.stat().st_size,
                          'sha256': sha(p.read_bytes())} for p in metadata],
        'crypto_relation_circuit_and_request_source_unchanged': True,
        'old_files_modified': False, 'build_setup_proof_PK_owner_secret_or_network_used': False}
    map_path.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'copied_sources': len(maps), 'new_metadata': len(metadata),
                      'map_sha256': sha(map_path.read_bytes()), 'build_or_setup_run': False}))


if __name__ == '__main__':
    main()
