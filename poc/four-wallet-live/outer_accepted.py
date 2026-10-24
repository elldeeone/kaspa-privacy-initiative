#!/usr/bin/env python3
"""Accepted GN2 to public sizing or an unproved two-child body. No local source,
owner/PK/witness, signing, RPC or proving-job interface. Currentness is scoped
to the verified non-atomic node checkpoint; presubmit requery stays mandatory.
"""
import argparse
from pathlib import Path
import subprocess

from live_contracts import (HELPER, HELPER_SHA, OWN, REQUIRED, module_from_owned_bytes,
                            public_runtime, stage_sdk)
from prepare_runtime import Exclusions, KINDS, PROFILE_SHA
from public import ROOT, checked, digest, encoded, fields, need, parse, sha, trial, write_new

HOST_SHA = 'efddfb276afcdd0eec4ae8a071bbfb1e02a8f6189db4424efeccd64d6def27e1'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def accepted_fetch_shape(value, trial_id, profile_sha256):
    """Early scope refusal only. Matching JSON never establishes acceptance."""
    need(type(value) is dict and value.get('schema') == 'kpx5-gn2-network-fetch/v1'
         and value.get('status') == 'FETCHED_PENDING_REPLAY'
         and value.get('network_id') == 'testnet-10'
         and value.get('genesis_hash_hex') == 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
         and value.get('financial_profile_sha256') == profile_sha256
         and type(value.get('descriptor')) is dict
         and value['descriptor'].get('trial_id') == trial_id,
         'actual-accepted-Full-fetch-required-no-local-history')


def two_records(raw, profile_sha256):
    value = parse(raw)
    fields(value, ('schema', 'financial_profile_sha256', 'record_hex4048'), 'exact-prefix-fields')
    need(value['schema'] == 'kpx6-four-wallet-proposed-prefix/v1'
         and value['financial_profile_sha256'] == profile_sha256
         and type(value['record_hex4048']) is list and len(value['record_hex4048']) == 2,
         'exact-two-proposed-P0-records')
    result = []
    for item in value['record_hex4048']:
        need(type(item) is str and len(item) == 8096
             and all(char in '0123456789abcdef' for char in item), 'canonical-record4048')
        result.append(bytes.fromhex(item))
    return tuple(result)


def restore_software(a, excluded, raw_inventory, output):
    value = parse(raw_inventory)
    fields(value, ('schema', 'classification', 'files'), 'typed-public-inventory')
    need(value['schema'] == 'kpx4-public-software-bundle/v1'
         and value['classification'] == 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY'
         and type(value['files']) is list and value['files'], 'selected-public-software-tree')
    rows, seen = [], set()
    for row in value['files']:
        fields(row, ('kind', 'path', 'bytes', 'sha256'), 'typed-public-member')
        name = row['path']
        need(type(name) is str and name and not Path(name).is_absolute()
             and '..' not in Path(name).parts and str(Path(name)) == name
             and name not in seen and type(row['bytes']) is int and row['bytes'] >= 0,
             'finite-canonical-unique-software-member')
        need(row['kind'] in KINDS, 'typed-public-software-kind')
        sha(row['sha256']); seen.add(name); rows.append((row, checked(a.software_root) / name))
    excluded.guard(path for _, path in rows)
    need(all(path.stat().st_mode & 0o222 == 0 for _, path in rows), 'selected-members-readonly')
    destination = output / 'software'; destination.mkdir(mode=0o700)
    for row, path in rows:
        raw = excluded.read(path, row['sha256']); need(len(raw) == row['bytes'], 'exact-member-length')
        target = destination / row['path']; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw); target.chmod(0o500 if row['kind'] == 'selected-executable' else 0o400)
    write_new(destination / 'SOFTWARE-BUNDLE.json', raw_inventory)
    (destination / 'SOFTWARE-BUNDLE.json').chmod(0o400)
    return destination


def authenticate_restored(software, raw_inventory, expected_sha256, excluded):
    """The existing fixed closure/source joins with BOTH original namespaces.

    c14's authenticator protects one trial. Do not silently call it for eight:
    join running controller bytes through Exclusions, then invoke the same b3
    byte verifier only on newly owned readonly restored members.
    """
    need(digest(raw_inventory) == expected_sha256, 'external-software-inventory-pin')
    rows = {row['path']: row for row in parse(raw_inventory)['files']}
    need({'runtime-source/' + name for name in REQUIRED} <= set(rows), 'complete-fixed-source-closure')
    paths = [ROOT / 'poc/four-wallet-live' / name for name in OWN]
    excluded.guard(paths)
    for name, path in zip(OWN, paths):
        excluded.read(path, rows['runtime-source/poc/four-wallet-live/' + name]['sha256'])
    helper_raw = excluded.read(software / 'runtime-source' / HELPER, HELPER_SHA)
    helper = module_from_owned_bytes(helper_raw)
    receipt = helper.verify(software, raw_inventory, expected_sha256)
    return software / 'runtime-source', software / 'runtime', receipt


def accepted_base(a):
    excluded = Exclusions(a.exclude_trial_directory)
    trial(a.trial_id); need(a.financial_sha256 == PROFILE_SHA, 'selected-financial41c')
    names = [a.financial_profile, a.descriptor, a.fetch, a.inventory]
    if a.op == 'prepare':
        need(a.prefix is not None and a.prefix_sha256 is not None
             and a.w_codec is not None and a.r0_host is not None, 'public-outer-inputs-and-tools')
        names.extend((a.prefix, a.w_codec, a.r0_host))
    excluded.guard(names)
    raw_fetch = excluded.read(a.fetch, a.fetch_sha256)
    accepted_fetch_shape(parse(raw_fetch), a.trial_id, a.financial_sha256)
    raw_profile = excluded.read(a.financial_profile, a.financial_sha256)
    raw_descriptor = excluded.read(a.descriptor, a.descriptor_sha256)
    raw_inventory = excluded.read(a.inventory, a.inventory_sha256)
    descriptor = parse(raw_descriptor)
    need(descriptor['trial_id'] == a.trial_id
         and descriptor['financial_profile_sha256'] == a.financial_sha256, 'descriptor-trial-profile')
    output = checked(a.output)
    need(not output.exists() and not output.is_relative_to(ROOT)
         and all(not output.is_relative_to(folder) for folder in excluded.directories), 'fresh-public-output')
    output.mkdir(parents=True, mode=0o700)
    software = restore_software(a, excluded, raw_inventory, output)
    source, assets, receipt = authenticate_restored(software, raw_inventory, a.inventory_sha256, excluded)
    profile, runtime, chain = public_runtime(source, assets, raw_profile, a.financial_sha256,
                                           a.exclude_trial_directory[-1])
    paths = chain.bundle_public_files(raw_fetch, a.fetch_sha256, a.bundle_directory)
    excluded.guard(paths)
    bundle = parse(raw_fetch)
    page_rows = [*bundle['pages'], *bundle['current_view']['post_query_delta']['pages']]
    need(len(paths) == len(page_rows), 'complete-retained-page-list')
    pages = output / 'retained-public-pages'; pages.mkdir(mode=0o700)
    for row, path in zip(page_rows, paths):
        raw = excluded.read(path, row['gzip_sha256']); need(len(raw) == row['gzip_bytes'], 'exact-page-length')
        target = pages / checked(path).relative_to(checked(a.bundle_directory))
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw); target.chmod(0o400)
    base = chain.replay_bundle(raw_descriptor, a.descriptor_sha256, raw_fetch, a.fetch_sha256,
        profile, runtime, output / 'actual-accepted-base', bundle_directory=pages,
        sdk_directory=stage_sdk(software, output / 'accepted-public-SDK', a.exclude_trial_directory[-1]))
    need(base['trial_id'] == a.trial_id and base['accepted_chain_backing_verified'] is True
         and base['currentness_verified'] is True and not base['operations']
         and base['point'] == base['entry']['founding_outpoint'] and base['point'] is not None
         and base['reserve'] == base['entry']['reserve_sompi'], 'actual-current-accepted-GN2-before-W')
    from source import actual_daa
    return excluded, output, software, profile, runtime, base, actual_daa(base, runtime), receipt


def run(a):
    excluded, output, software, profile, runtime, base, daa, receipt = accepted_base(a)
    bindings = {'trial_id': a.trial_id, 'financial_profile_sha256': a.financial_sha256,
        'public_source_kind': 'accepted', 'descriptor_sha256': a.descriptor_sha256,
        'fetch_sha256': a.fetch_sha256, 'accepted_point': base['point'], 'actual_DAA': daa,
        'currentness_scope': base['currentness_scope'], 'observation_checkpoint': base['observation_checkpoint'],
        'fresh_acquisition_and_immediate_presubmit_input_requery_required': True}
    if a.op == 'quote-payment':
        from pricing import evaluate
        need(type(a.net_principal_sompi) is int and a.net_principal_sompi == 1_000_000_000,
             'selected-four-wallet-net1B')
        sizing = evaluate(runtime, base['snapshot'], base['point'], base['reserve'], daa,
            output / 'public-sizing', net_principal_sompi=a.net_principal_sompi, rate=100)
        result = {**sizing, **bindings, 'sizing_grants_spend_authority': False}
        write_new(output / 'SIZING.json', result)
        return {'status': 'ACCEPTED_BASE_PUBLIC_SIZING_ONLY', 'recipient_exit_credit_sompi':
            sizing['recipient_exit_credit_sompi'], 'trial_id': a.trial_id, 'spend_authorized': False}
    records = two_records(excluded.read(a.prefix, a.prefix_sha256), a.financial_sha256)
    from compat import core, public as selected_public
    from preparation import virtual_prefix
    c, pub = core(), selected_public(); v = pub.virtual
    after = virtual_prefix(runtime, base, records, output / 'genuine-proposed-prefix')
    state, successor = base['snapshot'].state(profile.domain), after['snapshot'].state(profile.domain)
    frame = v.push(bytes(65)) + v.push(bytes(128)) + v.push(runtime.emit(state))
    body = c.native_runtime.tx(base['point'], [(after['reserve'], c.native_runtime.p2sh(runtime.emit(successor)))],
        v.encode_payload(records), frame, profile.aggregate_budget)
    contexts = [dict(base['head_context'])]
    candidate, checked_contexts, metrics = runtime.normalize_case(
        c.native_runtime.public_case(body, contexts), output / 'outer-normalize')
    need(contexts == checked_contexts and int(contexts[0]['block_daa_score']) == daa, 'actual-accepted-context-DAA')
    runtime.sdk(candidate['transaction'], contexts)
    projection = v.financial_projection(candidate)
    journal = v.encode_journal(profile.wrapper_domain, profile.domain, base['point'], state,
        base['reserve'], successor, after['reserve'], base['reserve'] - after['reserve'], records, projection)
    need(len(projection) == 8301 and len(journal) == 424
         and metrics['actual_fee_sompi'] == base['reserve'] - after['reserve']
         and metrics['actual_fee_sompi'] == 100 * metrics['mining_mass'], 'exact-genuine-outer-reference100-fee')
    tools = output / 'public-tools'; tools.mkdir(mode=0o700)
    expected_codec = profile.executables['w-codec']['sha256']
    need(a.w_codec_sha256 == expected_codec and a.r0_host_sha256 == HOST_SHA, 'selected-codec-and-R0-host')
    for name, path, expected in (('w-codec', a.w_codec, expected_codec), ('r0-host', a.r0_host, HOST_SHA)):
        target = tools / name; write_new(target, excluded.read(path, expected)); target.chmod(0o500)
    result = subprocess.run([str(tools / 'w-codec')], input=encoded({'operation': 'body', 'case': candidate}),
        capture_output=True, env=dict(CLEAN))
    need(result.returncode == 0 and not result.stderr, 'selected-native-public-body-codec')
    native = parse(result.stdout)
    need(native['template_kind'] == 'ACTUAL_R0_W' and native['outer_image_hex32'] == profile.image_id.hex()
         and native['financial_projection_hex'] == projection.hex() and native['journal_hex424'] == journal.hex()
         and native['journal_sha256'] == digest(journal) and native['financial_projection_sha256'] == digest(projection)
         and native['native_VM_executed'] is False and native['receipt_or_child_G16_verified'] is False,
         'independent-native-Python-P8301-J424-byte-join')
    for name, value in (('validation-case.json', candidate), ('contexts.json', contexts),
        ('projection.bin', projection), ('journal.bin', journal), ('native-body.json', native), ('metrics.json', metrics)):
        write_new(output / name, value)
    host = subprocess.run([str(tools / 'r0-host'), 'host-check', str(output / 'projection.bin'),
        str(output / 'journal.bin'), str(output / 'host-check')], capture_output=True, env=dict(CLEAN))
    need(host.returncode == 0, 'selected-R0-host-public-predicate')
    result = {'schema': 'kpx6-four-wallet-accepted-outer-preparation/v1', **bindings,
        'prefix_sha256': a.prefix_sha256, 'projection_sha256': digest(projection),
        'journal_sha256': digest(journal), 'transaction_id': candidate['transaction']['id'],
        'accepted_founding_outpoint': base['entry']['founding_outpoint'], 'fee_sompi': metrics['actual_fee_sompi'],
        'new_reserve_sompi': after['reserve'], 'accepted_source_replayed': True,
        'independent_inner_G16_NF_CM_replay': True, 'host_predicate_and_independent_native_codec_match': True,
        'selected_public_software_receipt': receipt,
        'classification': 'UNPROVED_PROSPECTIVE_SETTLEMENT_FROM_RECORDED_ACCEPTED_GN2',
        'outer_case_accepted_or_spend_authorized': False, 'outer_receipt_or_native_Full': False,
        'private_backup_PK_key_witness_R0_proof_generation_or_RPC_read_or_run': False}
    write_new(output / 'PREPARATION.json', result)
    return {'status': 'ACCEPTED_BASE_UNPROVED_OUTER_PREPARED', 'trial_id': a.trial_id,
        'projection_sha256': digest(projection), 'journal_sha256': digest(journal),
        'outer_case_accepted_or_spend_authorized': False}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('op', choices=('quote-payment', 'prepare'))
    for name in ('financial-profile', 'software-root', 'inventory', 'descriptor', 'fetch', 'bundle-directory', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('trial-id', 'financial-sha256', 'inventory-sha256', 'descriptor-sha256', 'fetch-sha256'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--exclude-trial-directory', required=True, action='append', type=Path)
    p.add_argument('--prefix', type=Path); p.add_argument('--prefix-sha256')
    p.add_argument('--w-codec', type=Path); p.add_argument('--w-codec-sha256')
    p.add_argument('--r0-host', type=Path); p.add_argument('--r0-host-sha256')
    p.add_argument('--net-principal-sompi', type=int, default=1_000_000_000)
    return p


if __name__ == '__main__':
    p = parser()
    try:
        print(encoded(run(p.parse_args())).decode())
    except (ValueError, OSError, KeyError, TypeError, StopIteration):
        p.exit(2, 'accepted outer preparation incomplete; no local-history fallback or submission\n')
