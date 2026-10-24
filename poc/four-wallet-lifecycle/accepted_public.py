#!/usr/bin/env python3
"""Closed public accepted-history finalization and campaign accounting.

The selected descriptor/fetch are verified by the fixed chain adapter, using
actual accepted contexts and retained Full pages. A proposal remains unaccepted
until separately submitted and observed. No LOCAL history, backup, PK, signer,
proving worker or RPC interface is available in this worker.
"""
import argparse
import copy
import json
from pathlib import Path
import stat
import subprocess
import time
import uuid
from types import SimpleNamespace

from installation import (CLEAN, checked, digest, entries, mapping, need,
                          network_page_rows, outside, parse, read_public, regular)

PROFILE_SHA = '41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a'
INSTALLATION_SHA = '5158c1e39038454a6db1d7426acea39672283e9cc19cffdc9832499526b302b9'
CONTROLS_SHA = '9ee6e5ea2fcc9efee9a1dae4e19052353121d5cbc610c4f38754c4bdb2dd41f4'
LEDGER_SHA = '10ef9e0a4516739998bdd5e930f6cf8b8b942547bccbc15ae7c4b95deeffb63c'
CODEC_SHA = '3cc966dab7af0fb0e015f52fc281c7c4f70a41975afdc9afd15e3fd1dd090939'


def pin(value):
    need(type(value) is str and len(value) == 64
         and all(char in '0123456789abcdef' for char in value), 'external-canonical-SHA256')
    return value


def trial(value):
    need(type(value) is str, 'external-trial-selector')
    parsed = uuid.UUID(value)
    need(str(parsed) == value and parsed.version == 4 and parsed.variant == uuid.RFC_4122,
         'canonical-v4-trial-selector')
    return value


def save(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = value if type(value) is bytes else (json.dumps(value, sort_keys=True,
        separators=(',', ':'), allow_nan=False)+'\n').encode()
    with path.open('xb') as file:
        file.write(raw)
    path.chmod(0o400)
    return raw


def exclusions(roots):
    roots = tuple(outside(value) for value in roots)
    need(len(roots) >= 2 and len(set(roots)) == len(roots), 'both-original-private-root-selectors')
    inodes, directories = set(), []
    for root in roots:
        for role in 'ABCD':
            directory = checked(root / 'owners' / role)
            need(directory.is_dir(), 'complete-original-owner-directory')
            info = checked(directory / 'backup.json').stat()
            need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                 'original-backup-metadata-only')
            inodes.add((info.st_dev, info.st_ino)); directories.append(directory)
    need(len(inodes) == 4 * len(roots), 'distinct-original-backup-inodes')
    return frozenset(inodes), tuple(directories)


def bubble():
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC']


def stage(args):
    forbidden, directories = exclusions(args.exclude_private_root)
    need(args.financial_sha256 == PROFILE_SHA, 'independently-selected-reviewed-financial-profile')
    trial(args.trial_id); pin(args.inventory_sha256); pin(args.program_sha256)
    output = outside(args.output); need(not output.exists(), 'fresh-public-accepted-controller')
    inventory = checked(args.software_root) / 'SOFTWARE-BUNDLE.json'
    files = [('financial', args.financial_profile, PROFILE_SHA),
        ('descriptor', args.descriptor, pin(args.descriptor_sha256)),
        ('fetch', args.fetch, pin(args.fetch_sha256)),
        ('accepted_public.py', Path(__file__), args.program_sha256),
        ('installation.py', Path(__file__).with_name('installation.py'), INSTALLATION_SHA)]
    if args.op == 'finalize':
        files += [(name, getattr(args, name), pin(getattr(args, name+'_sha256')))
                  for name in ('case', 'proof', 'projection', 'journal', 'preparation')]
        files += [('w-codec', args.codec, CODEC_SHA), ('finalization_controls.py',
                   Path(__file__).with_name('finalization_controls.py'), CONTROLS_SHA)]
    else:
        need(type(args.recipient_exit_index) is list and len(args.recipient_exit_index) == 2
             and len(set(args.recipient_exit_index)) == 2
             and all(type(index) is int and 0 <= index < 4 for index in args.recipient_exit_index),
             'two-distinct-selected-recipient-exit-indices')
        files += [(name, getattr(args, name), pin(getattr(args, name+'_sha256')))
                  for name in ('exit_receipts', 'recovery_receipts')]
        files += [('ledger.py', Path(__file__).with_name('ledger.py'), LEDGER_SHA)]
    for path in (inventory, *(path for _, path, _ in files)):
        regular(path, forbidden, directories)
    rows = entries(SimpleNamespace(inventory=inventory, inventory_sha256=args.inventory_sha256,
        software_root=args.software_root, source_kind='accepted'), forbidden, directories)
    # Retained Full pages, including the post-query delta, are all materialized
    # and metadata-guarded before the first page/software member read or copy.
    fetch_raw = read_public(args.fetch, forbidden, directories)
    pages = network_page_rows(fetch_raw, args.fetch_sha256)
    bundle = checked(args.bundle_directory)
    for relative, _ in pages:
        regular(bundle / relative, forbidden, directories)
    output.mkdir(parents=True, mode=0o700)
    software = output / 'software'; software.mkdir(mode=0o700)
    for row, path in rows:
        raw = read_public(path, forbidden, directories)
        need(len(raw) == row['bytes'] and digest(raw) == row['sha256'], 'selected-software-member-bytes')
        target = software / row['path']; save(target, raw)
        if row['kind'] == 'selected-executable':
            target.chmod(0o500)
    command = bubble()
    for relative, destination in mapping('accepted').items():
        command += ['--ro-bind', str(software / relative), destination]
    for name, path, expected in files:
        raw = read_public(path, forbidden, directories)
        need(digest(raw) == expected, 'selected-public-input-or-source-bytes')
        target = output / name; save(target, raw)
        if name == 'w-codec':
            target.chmod(0o500)
        destination = '/work/poc/four-wallet-lifecycle/'+name if name.endswith('.py') else '/'+name
        command += ['--ro-bind', str(target), destination]
    retained = output / 'retained'; retained.mkdir(mode=0o700)
    for relative, _ in pages:
        save(retained / relative, read_public(bundle / relative, forbidden, directories))
    client = output / 'public-output'; client.mkdir(mode=0o700)
    command += ['--ro-bind', str(retained), '/bundle', '--bind', str(client), '/out',
        '--chdir', '/work/poc/four-wallet-lifecycle', '/usr/bin/python3', '-B',
        '/work/poc/four-wallet-lifecycle/accepted_public.py', '_'+args.op,
        '--financial-sha256', PROFILE_SHA, '--trial-id', args.trial_id,
        '--descriptor-sha256', args.descriptor_sha256, '--fetch-sha256', args.fetch_sha256]
    if args.op == 'finalize':
        for name in ('case', 'proof', 'projection', 'journal', 'preparation'):
            command += ['--'+name+'-sha256', getattr(args, name+'_sha256')]
    else:
        for name in ('exit_receipts', 'recovery_receipts'):
            command += ['--'+name.replace('_', '-')+'-sha256', getattr(args, name+'_sha256')]
        for index in args.recipient_exit_index:
            command += ['--recipient-exit-index', str(index)]
    if not args.execute:
        return {'staged': True, 'executed': False, 'private_backup_PK_proving_worker_network_or_submission': False}
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, env=dict(CLEAN))
    save(output / 'PRIVATE-stdout.log', result.stdout.encode())
    save(output / 'PRIVATE-stderr.log', result.stderr.encode())
    save(output / 'EXECUTION.json', {'returncode': result.returncode,
        'wall_seconds': time.monotonic()-started, 'closed_public_worker_exit_observed': True,
        'private_backup_PK_proving_worker_network_or_submission': False})
    need(result.returncode == 0 and (client / ('RESULTS.json' if args.op == 'finalize' else 'LEDGER.json')).is_file(),
         'accepted-public-worker-incomplete-see-retained-evidence')
    return parse((client / ('RESULTS.json' if args.op == 'finalize' else 'LEDGER.json')).read_bytes())


def selected(path, expected):
    raw = read_public(path, ())
    need(digest(raw) == pin(expected), 'external-accepted-worker-input-pin')
    return raw


def accepted_base(args, output):
    from contracts import chain, financial
    from runtime import Runtime
    need(args.financial_sha256 == PROFILE_SHA, 'selected-financial-profile-before-accepted-replay')
    profile = financial(selected('/financial', PROFILE_SHA), PROFILE_SHA)
    runtime = Runtime(profile, '/runtime')
    replayed = chain().replay_bundle(selected('/descriptor', args.descriptor_sha256), args.descriptor_sha256,
        selected('/fetch', args.fetch_sha256), args.fetch_sha256, profile, runtime,
        output / 'accepted-source-replay', bundle_directory='/bundle')
    need(replayed['trial_id'] == trial(args.trial_id)
         and replayed['network_evidence_consistency_validated'] is True
         and replayed['currentness_scope'] == 'TRUSTED_NONATOMIC_NODE_OBSERVATION_AT_RECORDED_CHECKPOINT',
         'exact-independent-trial-and-accepted-source-scope')
    return profile, runtime, replayed


def finalize_worker(args):
    from compat import core, public
    from preparation import virtual_prefix
    from source import actual_daa
    from finalization_controls import binding_cases
    output = Path('/out'); profile, runtime, base = accepted_base(args, output)
    need(base['point'] is not None and base['reserve'] > 0, 'current-accepted-W-base-for-proposal')
    c = core(); v = public().virtual
    need(profile.codec_sha256 == CODEC_SHA, 'selected-independent-native-codec')
    candidate = parse(selected('/case', args.case_sha256))
    proof = selected('/proof', args.proof_sha256)
    need(len(proof) == 128 and proof != bytes(128), 'externally-selected-genuine-compressed-proof128')
    projection = selected('/projection', args.projection_sha256)
    journal = selected('/journal', args.journal_sha256)
    preparation = parse(selected('/preparation', args.preparation_sha256))
    frame = bytes.fromhex(candidate['transaction']['inputs'][0]['signatureScript'])
    state = base['snapshot'].state(profile.domain); redeem = runtime.emit(state)
    need(frame[:68] == c.native_runtime.push(bytes(65))+b'\x4c\x80' and frame[68:196] == bytes(128)
         and frame[196:199] == b'\x4d'+len(redeem).to_bytes(2, 'little') and frame[199:] == redeem,
         'exact-selected-accepted-base-zero-proof-W-frame')
    records = v.decode_payload(bytes.fromhex(candidate['transaction']['payload']))
    after = virtual_prefix(runtime, base, records, output / 'independent-proposed-child-replay')
    successor = after['snapshot'].state(profile.domain); daa = actual_daa(base, runtime)
    zero, contexts, metrics = runtime.normalize_case(candidate, output / 'zero-normalize')
    need(zero == candidate and contexts == [base['head_context']]
         and candidate['transaction']['inputs'][0]['previousOutpoint'] == base['point']
         and candidate['transaction']['inputs'][0]['computeBudget'] == profile.aggregate_budget
         and candidate['transaction']['outputs'] == [{'value': after['reserve'],
            'scriptPublicKey': c.native_runtime.p2sh(runtime.emit(successor)), 'covenant': None}],
         'exact-actual-accepted-point-context-and-authorized-proposal-body')
    runtime.sdk(candidate['transaction'], contexts)

    def codecs(case, label):
        derived_projection = v.financial_projection(case)
        derived_journal = v.encode_journal(profile.wrapper_domain, profile.domain, base['point'], state,
            base['reserve'], successor, after['reserve'], base['reserve']-after['reserve'], records, derived_projection)
        need(derived_projection == projection and derived_journal == journal
             and len(projection) == 8301 and len(journal) == 424, 'derived-accepted-base-exact-public-claim')
        result = subprocess.run(['/w-codec'], input=json.dumps({'operation': 'body', 'case': case}),
            capture_output=True, text=True, env=dict(CLEAN))
        need(result.returncode == 0 and not result.stderr, 'selected-independent-native-body-codec')
        native = parse(result.stdout); save(output / (label+'-native-codec.json'), native)
        need(native['template_kind'] == 'ACTUAL_R0_W' and native['outer_image_hex32'] == profile.image_id.hex()
             and native['financial_projection_hex'] == projection.hex() and native['journal_hex424'] == journal.hex()
             and native['journal_sha256'] == args.journal_sha256
             and native['financial_projection_sha256'] == args.projection_sha256,
             'independent-native-and-Python-accepted-claim-join')

    codecs(candidate, 'before')
    changed = copy.deepcopy(candidate); altered = bytearray(frame); altered[68:196] = proof
    changed['transaction']['inputs'][0]['signatureScript'] = altered.hex()
    actual, actual_contexts, actual_metrics = runtime.normalize_case(changed, output / 'genuine-normalize')
    need(actual == changed and actual_contexts == contexts and actual_metrics == metrics,
         'proof-slot-only-official-body-ID-mass-and-context-preserved')
    runtime.sdk(actual['transaction'], actual_contexts); codecs(actual, 'after')
    need(metrics['actual_fee_sompi'] == base['reserve']-after['reserve']
         and metrics['actual_fee_sompi'] == 100 * metrics['mining_mass']
         and preparation['schema'] == 'kpx6-four-wallet-accepted-outer-preparation/v1'
         and preparation['financial_profile_sha256'] == PROFILE_SHA and preparation['trial_id'] == args.trial_id
         and preparation['descriptor_sha256'] == args.descriptor_sha256
         and preparation['fetch_sha256'] == args.fetch_sha256
         and preparation['journal_sha256'] == args.journal_sha256
         and preparation['projection_sha256'] == args.projection_sha256
         and preparation['transaction_id'] == actual['transaction']['id']
         and type(preparation['actual_DAA']) is int and preparation['actual_DAA'] == daa
         and preparation['fee_sompi'] == metrics['actual_fee_sompi']
         and preparation['new_reserve_sompi'] == after['reserve']
         and preparation['outer_case_accepted_or_spend_authorized'] is False
         and preparation['outer_receipt_or_native_Full'] is False,
         'independent-accepted-preparation-body-and-actual-fee-join')
    outcomes = []; cases = (('genuine-actual-W-positive', actual),)+binding_cases(actual)
    need(len(cases) == 6, 'exact-six-accepted-proposal-binding-cases')
    for index, (label, case) in enumerate(cases):
        normalized, ctx, mass = runtime.normalize_case(case, output / ('control-normalize-'+str(index)))
        need(bytes.fromhex(normalized['transaction']['inputs'][0]['signatureScript'])[68:196] == proof,
             'each-public-control-retains-genuine-proof')
        runtime.sdk(normalized['transaction'], ctx)
        directory = output / ('control-'+str(index)); directory.mkdir(mode=0o700)
        save(directory / 'validation-case.json', normalized)
        runtime.native.run(['validate-transaction', directory / 'validation-case.json', directory / 'native'])
        report = parse((directory / 'native/native-validation.json').read_bytes())
        checked_mass = parse((directory / 'native/metrics.json').read_bytes())
        engines = report['per_input_ScriptEngine']; expected = index == 0
        need(mass == checked_mass and report['isolation'] == 'PASS' and len(engines) == 1
             and report['Full']['accepted'] is expected and report['all_input_engines_accepted'] is expected
             and engines[0]['accepted'] is expected, 'fresh-accepted-proposal-native-binding-'+label)
        error = engines[0].get('typed_error', '')
        expected_error = None if expected else 'ZkIntegrity' if index in (1, 2) else 'VerifyError'
        need(expected_error is None or expected_error in error, 'typed-accepted-proposal-binding-rejection')
        outcomes.append({'label': label, 'Full_accepted': expected, 'engine_accepted': expected,
            'isolation_PASS': True, 'engine_typed_error': error, 'engine_units': engines[0]['units'],
            'actual_fee_sompi': mass['actual_fee_sompi'], 'mining_mass': mass['mining_mass']})
    save(output / 'validation-case.json', actual)
    result = {'schema': 'kpx6-four-wallet-accepted-base-outer-finalization/v1',
        'financial_profile_sha256': PROFILE_SHA, 'trial_id': args.trial_id,
        'descriptor_sha256': args.descriptor_sha256, 'fetch_sha256': args.fetch_sha256,
        'proof_sha256': args.proof_sha256, 'projection_sha256': args.projection_sha256,
        'journal_sha256': args.journal_sha256, 'transaction_id': actual['transaction']['id'],
        'actual_DAA': daa, 'fee_sompi': metrics['actual_fee_sompi'], 'reserve_after_sompi': after['reserve'],
        'native_binding_case_count': 6, 'native_outcomes': outcomes,
        'proof_slot_only_body_ID_mass_preserved': True, 'SDK_roundtrip': True,
        'independent_codec_before_after_identical': True, 'whole_selected_W_native_Full_all_engines': True,
        'accepted_base_currentness_scope': base['currentness_scope'],
        'accepted_base_observation_checkpoint': base['observation_checkpoint'],
        'proposal_accepted_or_current': False, 'fresh_prebroadcast_current_head_recheck_required': True,
        'private_backup_PK_proving_worker_network_or_submission': False,
        'local_history_used_or_created': False}
    save(output / 'RESULTS.json', result); return result


def recognition_counts(row):
    need(type(row) is dict and row['op'] == 'recover', 'selected-final-recognition-receipt')
    names = ('recognized_historical_receipt_count', 'recognized_spent_receipt_count',
        'recognized_unspent_claim_count_before', 'historical_native_payout_key_control_match_count',
        'unresolved_owned_NF_payout_records')
    need(all(type(row[name]) is int and row[name] >= 0 for name in names), 'integer-cold-recognition-counts')
    return {'schema': 'kpx6-cold-original-backup-recognition-counts/v1',
        'financial_profile_sha256': PROFILE_SHA, **{name: row[name] for name in names},
        'per_owner_payout_amount_script_owned_positions_or_backup_hash_exported': False,
        'PK_or_proving_worker_required': False}


def ledger_worker(args):
    from ledger import close
    output = Path('/out'); profile, runtime, replayed = accepted_base(args, output)
    exits = parse(selected('/exit_receipts', args.exit_receipts_sha256))
    scans = parse(selected('/recovery_receipts', args.recovery_receipts_sha256))
    need(type(exits) is list and len(exits) == 4 and type(scans) is list and len(scans) == 4,
         'four-private-exit-and-final-recovery-receipts')
    indices = args.recipient_exit_index
    need(type(indices) is list and len(indices) == 2 and len(set(indices)) == 2
         and all(type(index) is int and 0 <= index < 4 for index in indices), 'selected-two-recipient-exit-rows')
    for row in (*exits, *scans):
        need(type(row) is dict and row['financial_profile_sha256'] == PROFILE_SHA
             and row['public_source_kind'] == 'accepted'
             and row['public_network_evidence_consistency_validated'] is True
             and row['currentness_scope'] == 'TRUSTED_NONATOMIC_NODE_OBSERVATION_AT_RECORDED_CHECKPOINT',
             'accepted-scope-owner-receipts-not-local-substitutes')
    result = close(replayed, exits, scans, [exits[index] for index in indices], [1_000_000_000, 1_000_000_000])
    save(output / 'LEDGER.json', result)
    for index, row in enumerate(scans):
        save(output / ('recognition-counts-'+str(index)+'.json'), recognition_counts(row))
    save(output / 'SCOPE.json', {'schema': 'kpx6-four-wallet-accepted-final-ledger-scope/v1',
        'financial_profile_sha256': PROFILE_SHA, 'trial_id': args.trial_id,
        'descriptor_sha256': args.descriptor_sha256, 'fetch_sha256': args.fetch_sha256,
        'accepted_source_currentness_scope': replayed['currentness_scope'],
        'observation_checkpoint': replayed['observation_checkpoint'],
        'CM_count': replayed['snapshot'].cm_cursor, 'NF_count': len(replayed['snapshot'].nullifiers),
        'remaining_reserve_sompi': replayed['reserve'], 'remaining_current_point': replayed['point'],
        'owner_identity_distinctness_proven_by_count_receipts': False,
        'per_owner_payout_correspondence_exported': False,
        'private_backup_PK_proving_worker_network_or_submission': False})
    return result


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('op', choices=('finalize', 'ledger', '_finalize', '_ledger'))
    for name in ('output', 'software-root', 'financial-profile', 'descriptor', 'fetch', 'bundle-directory',
                 'case', 'proof', 'projection', 'journal', 'preparation', 'codec', 'exit-receipts', 'recovery-receipts'):
        parser.add_argument('--'+name, type=Path)
    for name in ('inventory', 'financial', 'descriptor', 'fetch', 'case', 'proof', 'projection',
                 'journal', 'preparation', 'exit-receipts', 'recovery-receipts', 'program'):
        parser.add_argument('--'+name+'-sha256')
    parser.add_argument('--trial-id')
    parser.add_argument('--recipient-exit-index', type=int, action='append', default=[])
    parser.add_argument('--exclude-private-root', type=Path, action='append', default=[])
    parser.add_argument('--execute', action='store_true')
    return parser.parse_args()


if __name__ == '__main__':
    try:
        args = arguments()
        result = finalize_worker(args) if args.op == '_finalize' else ledger_worker(args) if args.op == '_ledger' else stage(args)
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        print(json.dumps({'error': 'accepted-public-operation-incomplete', 'submitted': False,
            'category': str(error) if type(error) is ValueError else type(error).__name__}))
        raise SystemExit(1)
