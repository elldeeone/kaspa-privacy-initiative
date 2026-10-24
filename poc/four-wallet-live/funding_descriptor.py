#!/usr/bin/env python3
"""Full public descriptor from selected GN2 and anchor; never signs/submits.

The existing selected GN2 parser derives actual point/state/redeem. The existing
full descriptor parser checks its shape. Native validity, source currentness
and funding authority remain separate required stages.
"""
import argparse
from pathlib import Path
import subprocess
import sys

from live_contracts import module
from outer_accepted import CLEAN, authenticate_restored, restore_software
from prepare_runtime import Exclusions, PROFILE_SHA
from public import ROOT, checked, digest, encoded, need, parse, trial, write_new

CHECKER = 'research/next-session/four-wallet-testnet/live-runner/nonbroadcast-integration-01/descriptor_check.mjs'
CHECKER_SHA = 'd22e90a94acdf1a79025ab8bf1e1c28b57d374fe39da49e2065b7b571e0827af'
GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'


def run(a):
    excluded = Exclusions(a.exclude_trial_directory)
    trial(a.trial_id); need(a.financial_sha256 == PROFILE_SHA, 'selected-financial41c')
    excluded.guard((a.financial_profile, a.inventory, a.case, a.anchor, ROOT / CHECKER))
    profile_raw = excluded.read(a.financial_profile, a.financial_sha256)
    inventory_raw = excluded.read(a.inventory, a.inventory_sha256)
    case_raw = excluded.read(a.case, a.case_sha256)
    anchor_raw = excluded.read(a.anchor, a.anchor_sha256)
    checker_raw = excluded.read(ROOT / CHECKER, CHECKER_SHA)
    output = checked(a.output)
    need(not output.exists() and not output.is_relative_to(ROOT)
         and all(not output.is_relative_to(folder) for folder in excluded.directories), 'fresh-public-descriptor-output')
    output.mkdir(parents=True, mode=0o700)
    software = restore_software(a, excluded, inventory_raw, output)
    source, assets, receipt = authenticate_restored(software, inventory_raw, a.inventory_sha256, excluded)
    profile = module(source / 'poc/four-wallet-profile/selection.py',
        '_kpx6_public_descriptor_financial').load(profile_raw, a.financial_sha256)
    sys.path.insert(0, str(source / 'poc/four-wallet-bootstrap'))
    from gn2 import EntrySelection, validate_genesis
    initial = validate_genesis(parse(case_raw), EntrySelection(PROFILE_SHA,
        profile.domain, profile.w_tail), a.trial_id, signed=True)
    anchor = parse(anchor_raw)
    need(anchor['schema'] == 'kpx5-gn2-birth-anchor/v1' and anchor['network_id'] == 'testnet-10'
         and anchor['genesis_hash_hex'] == GENESIS and anchor['financial_profile_sha256'] == PROFILE_SHA
         and anchor['birth_start_hash'] == anchor['birth_header']['hash']
         and type(anchor['min_confirmation_count']) is int and anchor['min_confirmation_count'] >= 20,
         'externally-selected-public-birth-anchor')
    descriptor = {'schema': 'kpx5-gn2-network-descriptor/v1', 'network_id': 'testnet-10',
        'genesis_hash_hex': GENESIS, 'financial_profile_sha256': PROFILE_SHA, 'trial_id': a.trial_id,
        'founding_outpoint': initial['founding_outpoint'], 'birth_start_hash': anchor['birth_start_hash'],
        'initial_redeem_hex': initial['redeem_hex'],
        'initial_redeem_sha256': digest(bytes.fromhex(initial['redeem_hex']))}
    write_new(output / 'descriptor.json', descriptor); (output / 'descriptor.json').chmod(0o400)
    write_new(output / 'financial-profile.json', profile_raw); (output / 'financial-profile.json').chmod(0o400)
    write_new(output / 'descriptor-check.mjs', checker_raw); (output / 'descriptor-check.mjs').chmod(0o400)
    node = assets / 'node'; selected_node = profile.executables['node']
    need(digest(excluded.read(node, selected_node['sha256'])) == selected_node['sha256']
         and node.stat().st_size == selected_node['bytes'], 'selected-descriptor-checker-node')
    descriptor_raw = encoded(descriptor) + b'\n'
    result = subprocess.run([str(node), str(output / 'descriptor-check.mjs'), str(software),
        str(output / 'financial-profile.json'), PROFILE_SHA,
        str(output / 'descriptor.json'), digest(descriptor_raw)], capture_output=True, env=dict(CLEAN))
    need(result.returncode == 0 and not result.stderr, 'existing-full-descriptor-parser')
    receipt = {'schema': 'kpx6-four-wallet-public-descriptor-construction/v1',
        'trial_id': a.trial_id, 'financial_profile_sha256': PROFILE_SHA,
        'case_sha256': a.case_sha256, 'anchor_sha256': a.anchor_sha256,
        'descriptor_sha256': digest(descriptor_raw), 'inventory_sha256': a.inventory_sha256,
        'selected_public_software_receipt': receipt,
        'initial_point_state_redeem_derived_by_selected_GN2_parser': True,
        'full_descriptor_shape_checked_by_selected_chain_parser': True,
        'original_eight_backup_files_and_owner_directories_excluded': True,
        'Native_Full_or_source_UTXO_or_anchor_currentness_verified': False,
        'private_backup_PK_key_witness_or_signing': False,
        'RPC_funding_submission_or_trial_readiness': False,
        'fresh_anchor_capture_and_actual_Native_preflight_required_before_funding': True}
    write_new(output / 'RESULTS.json', receipt)
    return {'status': 'PUBLIC_DESCRIPTOR_CONSTRUCTED_NOT_AUTHORIZED',
        'trial_id': a.trial_id, 'descriptor_sha256': digest(descriptor_raw)}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('financial-profile', 'software-root', 'inventory', 'case', 'anchor', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    for name in ('financial-sha256', 'inventory-sha256', 'trial-id', 'case-sha256', 'anchor-sha256'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--exclude-trial-directory', required=True, action='append', type=Path)
    return p


if __name__ == '__main__':
    p = parser()
    try:
        print(encoded(run(p.parse_args())).decode())
    except (ValueError, OSError, KeyError, TypeError):
        p.exit(2, 'public descriptor construction incomplete; no funding or submission\n')
