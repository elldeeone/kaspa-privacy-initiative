#!/usr/bin/env python3
"""Select the public virtual child after fresh compact setup; no PK or owner IO."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

import selection

HERE = Path(__file__).resolve().parent


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_public(path, expected):
    path = Path(path)
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
         'canonical-public-profile-path')
    raw = path.read_bytes()
    need(sha(raw) == expected, 'external-public-byte-pin')
    return raw


def install(manifest_path, manifest_sha256, emitter_path, emitter_sha256, report_path):
    report_path = Path(report_path)
    need('..' not in report_path.parts and not report_path.exists()
         and report_path.parent.is_dir()
         and not any(p.is_symlink() for p in (report_path, *report_path.parents)),
         'fresh-canonical-child-selection-report')
    raw = read_public(manifest_path, manifest_sha256)
    manifest = json.loads(raw.decode(), object_pairs_hook=selection.unique)
    for key, expected in (('schema', 'kpx4-public-proving-parameters/v1'),
        ('role', 'compact2'), ('output_arity', 2), ('trial_id', selection.PROFILE_ID),
        ('network_id', selection.NETWORK), ('genesis_hash_hex', selection.GENESIS),
        ('domain_hex32', selection.DOMAIN), ('program_label', 'AUTH528_PRIVATE_FOUR_WALLET_TESTNET/v1'),
        ('auth_magic_hex8', '4b50583441553031')):
        need(manifest.get(key) == expected, 'fresh-selected-compact-identity')
    vk = selection.hexbytes(manifest['vk_hex328'], 328)
    need(vk != bytes(328) and sha(vk) == manifest['vk_sha256'], 'fresh-compact-VK-pin')
    read_public(emitter_path, emitter_sha256)
    child_path = HERE / 'proof/child-profile.json'
    previous = json.loads(child_path.read_bytes(), object_pairs_hook=selection.unique)
    need(previous['selected'] is False and previous['classification'] == selection.CLASSIFICATION
         and previous['trial_id'] == selection.PROFILE_ID, 'fresh-child-profile-install-only')
    state = (b'KPX2ST01' + bytes.fromhex(selection.DOMAIN) + bytes(32)
             + (1).to_bytes(4, 'little') + bytes(32) + (1).to_bytes(4, 'little'))
    need(len(state) == 112, 'virtual-only-template-state')
    request = {'operation': 'emit', 'state_hex112': state.hex(),
               'compact_vk_hex328': vk.hex(), 'wide_vk_hex328': bytes(328).hex()}
    result = subprocess.run([str(Path(emitter_path).absolute())],
        input=json.dumps(request, sort_keys=True, separators=(',', ':')).encode(),
        capture_output=True, check=True)
    value = json.loads(result.stdout, object_pairs_hook=selection.unique)
    need(value['schema'] == 'kpx4-compact-batch-native-bytes/v1'
         and value['domain_hex32'] == selection.DOMAIN and value['state_hex112'] == state.hex()
         and value['private_witness_or_PK_or_seed_read'] is False
         and value['signing_network_or_broadcast'] is False, 'public-virtual-emitter-scope')
    program = bytes.fromhex(value['redeem_hex'])
    need(program[:114] == b'\x4c\x70' + state and len(program) == value['redeem_bytes']
         and sha(program) == value['redeem_sha256'], 'public-virtual-program-bytes')
    tail = program[114:]
    matches = lambda needle: sum(tail.startswith(needle, i)
        for i in range(max(0, len(tail) - len(needle) + 1)))
    need(matches(vk) == 1 and matches(bytes(328)) == 1, 'unique-active-and-disabled-virtual-keys')
    profile = {**previous, 'selected': True, 'child_vk_hex328': vk.hex(),
        'child_vk_sha256': manifest['vk_sha256'], 'child_template_tail_hex': tail.hex(),
        'child_parameter_manifest_sha256': manifest_sha256}
    encoded = json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()
    child_path.write_bytes(encoded)
    report = {'schema': 'kpx6-public-child-profile-selection/v1',
        'financial_profile_id': selection.PROFILE_ID, 'classification': selection.CLASSIFICATION,
        'child_profile_sha256': sha(encoded), 'parameter_manifest_sha256': manifest_sha256,
        'compact_vk_sha256': sha(vk), 'virtual_template_tail_sha256': sha(tail),
        'virtual_template_tail_bytes': len(tail), 'compact_VK_occurrences': matches(vk),
        'unused_wide_zero328_occurrences': matches(bytes(328)),
        'unused_wide_virtual_key_policy': 'UNSELECTED_WIDE_VIRTUAL_ONLY',
        'selected_child_native_executable_sha256': emitter_sha256,
        'virtual_template_never_a_GN2_funding_destination': True,
        'public_emitter_executed': True, 'native_VM_or_PK_owner_key_proof_or_network_used': False}
    Path(report_path).write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'emitter', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('manifest-sha256', 'emitter-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    print(json.dumps(install(args.manifest, args.manifest_sha256, args.emitter,
                             args.emitter_sha256, args.report), sort_keys=True))
