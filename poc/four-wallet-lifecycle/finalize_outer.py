#!/usr/bin/env python3
"""Public local-W finalization and binding controls; no owner or PK interface.

An externally pinned genuine proof replaces the selected zero slot only. The
closed worker independently replays the public GN2/children, compares both
body codecs, normalizes/roundtrips the genuine body, executes six Native Full
cases, and replays the appended local history. Nothing grants chain authority.
"""
import argparse
import copy
import json
from pathlib import Path
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

from installation import (CLEAN, checked, digest, entries, mapping, need, outside,
                          parse, read_public, regular)

PROFILE_SHA = '41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a'
INVENTORY_SHA = '798c246f5769ade14b27d0fb119077600e4cfcacc9c375dc8076041e58e2236b'
INSTALLATION_SHA = '5158c1e39038454a6db1d7426acea39672283e9cc19cffdc9832499526b302b9'
CONTROLS_SHA = '9ee6e5ea2fcc9efee9a1dae4e19052353121d5cbc610c4f38754c4bdb2dd41f4'
CODEC_SHA = '3cc966dab7af0fb0e015f52fc281c7c4f70a41975afdc9afd15e3fd1dd090939'
JOURNAL_SHA = '135b7e01cb8bb9d8897c78020f1362187977f0760540955284458ab862044880'
PROJECTION_SHA = '0607de94bae73a50dda5e4c6a62fe4487241c4f3bd59ffaf6d496370b12a8a8d'
HISTORY_SHA = '9f2373d7a4ba7b627d615ba2e46fc147590b6d50a9ea4235a92569246fee1a6a'
TRIAL = 'fd3bdcb5-c018-418d-ab66-02f8c7f37d2e'


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
    need(len(roots) >= 2 and len(set(roots)) == len(roots), 'both-local-and-live-private-root-selectors')
    forbidden, directories = set(), []
    for root in roots:
        for role in 'ABCD':
            directory = checked(root / 'owners' / role)
            need(directory.is_dir(), 'whole-original-owner-directory')
            path = checked(directory / 'backup.json'); info = path.stat()
            need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                 'original-backup-metadata-only')
            forbidden.add((info.st_dev, info.st_ino)); directories.append(directory)
    need(len(forbidden) == 4 * len(roots), 'distinct-original-backup-inodes')
    return frozenset(forbidden), tuple(directories)


def bubble():
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC']


def stage(args):
    forbidden, directories = exclusions(args.exclude_private_root)
    output = outside(args.output)
    need(not output.exists(), 'fresh-public-finalization-controller')
    inventory = checked(args.software_root) / 'SOFTWARE-BUNDLE.json'
    files = [('financial', args.financial_profile, PROFILE_SHA),
        ('history', args.history, HISTORY_SHA), ('case', args.case, args.case_sha256),
        ('proof', args.proof, args.proof_sha256), ('projection', args.projection, PROJECTION_SHA),
        ('journal', args.journal, JOURNAL_SHA), ('preparation', args.preparation, args.preparation_sha256),
        ('w-codec', args.codec, CODEC_SHA), ('finalize_outer.py', Path(__file__), args.program_sha256),
        ('finalization_controls.py', Path(__file__).with_name('finalization_controls.py'), CONTROLS_SHA),
        ('installation.py', Path(__file__).with_name('installation.py'), INSTALLATION_SHA)]
    for path in (inventory, *(path for _, path, _ in files)):
        regular(path, forbidden, directories)
    rows = entries(SimpleNamespace(inventory=inventory, inventory_sha256=INVENTORY_SHA,
        software_root=args.software_root, source_kind='accepted'), forbidden, directories)
    # Every fixed input and every selected software member's metadata is now
    # guarded against all eight originals before the first member byte/copy.
    output.mkdir(parents=True, mode=0o700)
    software = output / 'software'; software.mkdir(mode=0o700)
    for row, path in rows:
        raw = read_public(path, forbidden, directories)
        need(len(raw) == row['bytes'] and digest(raw) == row['sha256'], 'selected-public-software-bytes')
        target = software / row['path']; save(target, raw)
        if row['kind'] == 'selected-executable':
            target.chmod(0o500)
    command = bubble()
    for relative, target in mapping('accepted').items():
        command += ['--ro-bind', str(software / relative), target]
    for name, path, expected in files:
        raw = read_public(path, forbidden, directories)
        need(type(expected) is str and len(expected) == 64 and digest(raw) == expected,
             'external-selected-public-input-pin')
        target = output / name; save(target, raw)
        if name == 'w-codec':
            target.chmod(0o500)
        destination = '/work/poc/four-wallet-lifecycle/' + name if name.endswith('.py') else '/' + name
        command += ['--ro-bind', str(target), destination]
    client = output / 'public-output'; client.mkdir(mode=0o700)
    command += ['--bind', str(client), '/out', '--chdir', '/work/poc/four-wallet-lifecycle',
        '/usr/bin/python3', '-B', '/work/poc/four-wallet-lifecycle/finalize_outer.py', '_worker',
        '--case-sha256', args.case_sha256, '--proof-sha256', args.proof_sha256,
        '--preparation-sha256', args.preparation_sha256]
    if not args.execute:
        return {'staged': True, 'executed': False, 'private_backup_PK_or_prover_worker': False}
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, env=dict(CLEAN))
    save(output / 'stdout.log', result.stdout.encode()); save(output / 'stderr.log', result.stderr.encode())
    save(output / 'EXECUTION.json', {'returncode': result.returncode,
        'wall_seconds': time.monotonic()-started, 'closed_public_worker_exit_observed': True,
        'original_backup_PK_proof_generation_network_or_broadcast': False})
    need(result.returncode == 0 and (client / 'RESULTS.json').is_file(),
         'public-finalization-incomplete-see-retained-results')
    return parse((client / 'RESULTS.json').read_bytes())


def selected(path, expected):
    raw = read_public(path, ())
    need(digest(raw) == expected, 'external-public-worker-input-pin')
    return raw


def append_local_case(history, case, remaining, daa):
    """Public bookkeeping only. Full replay of the result is always required."""
    need(type(history) is dict and set(history) == {'schema', 'classification',
        'financial_profile_sha256', 'trial_id', 'funding_case', 'records', 'head_context'}
        and history['schema'] == 'kpx6-four-wallet-local-history/v1'
        and history['classification'] == 'UNFUNDED_SUPPLIED_GN2_CONTEXTS_NOT_ACCEPTED'
        and history['financial_profile_sha256'] == PROFILE_SHA and history['trial_id'] == TRIAL
        and type(history['records']) is list, 'exact-selected-local-history-scope')
    need(type(remaining) is int and 0 <= remaining <= 2_870_000_000_000_000_000
         and type(daa) is int and 0 <= daa < 1 << 64, 'canonical-local-head-amount-and-DAA')
    need(type(case) is dict and set(case) == {'transaction', 'entries'}
         and len(case['transaction']['inputs']) == len(case['entries']) == 1,
         'one-current-W-input-for-public-append')
    prior = history['head_context']
    need(type(prior) is dict, 'no-case-after-terminal-local-reserve')
    predecessor = (history['records'][-1] if history['records'] else history['funding_case'])['transaction']
    entry, body = case['entries'][0], case['transaction']
    need(body['inputs'][0]['previousOutpoint'] == {'transactionId': predecessor['id'], 'index': 0}
         and str(entry['amount']) == prior['amount_sompi']
         and entry['scriptPublicKey'] == prior['script_public_key']
         and str(entry['blockDaaScore']) == prior['block_daa_score']
         and entry['isCoinbase'] is False and entry['covenantId'] is None,
         'appended-case-exact-prior-local-point-and-context')
    result = copy.deepcopy(history); result['records'].append(copy.deepcopy(case))
    result['head_context'] = None
    if remaining:
        out = body['outputs'][0]
        need(type(out['value']) is int and out['value'] == remaining and out['covenant'] is None,
             'appended-local-reserve-output')
        result['head_context'] = {'amount_sompi': str(remaining),
            'script_public_key': out['scriptPublicKey'], 'block_daa_score': str(daa),
            'is_coinbase': False, 'covenant_id': None}
    return result


def worker(args):
    from contracts import financial
    from compat import core, public
    from runtime import Runtime
    from local_source import replay_local
    from preparation import virtual_prefix
    from source import actual_daa
    from replay import snapshot_record
    from finalization_controls import binding_cases
    output = Path('/out'); c = core(); v = public().virtual
    profile = financial(selected('/financial', PROFILE_SHA), PROFILE_SHA)
    need(profile.codec_sha256 == CODEC_SHA, 'selected-independent-native-codec')
    runtime = Runtime(profile, '/runtime')
    raw_history = selected('/history', HISTORY_SHA); history = parse(raw_history)
    base = replay_local(raw_history, HISTORY_SHA, profile, runtime, output / 'base-replay')
    need(not base['operations'], 'selected-first-local-W-aggregate')
    candidate = parse(selected('/case', args.case_sha256))
    proof = selected('/proof', args.proof_sha256)
    need(type(proof) is bytes and len(proof) == 128 and proof != bytes(128), 'genuine-selected-proof128')
    expected_projection = selected('/projection', PROJECTION_SHA)
    expected_journal = selected('/journal', JOURNAL_SHA)
    preparation = parse(selected('/preparation', args.preparation_sha256))
    original_frame = bytes.fromhex(candidate['transaction']['inputs'][0]['signatureScript'])
    need(original_frame[:68] == c.native_runtime.push(bytes(65)) + b'\x4c\x80'
         and original_frame[68:196] == bytes(128)
         and original_frame[196:199] == b'\x4d' + len(runtime.emit(base['snapshot'].state(profile.domain))).to_bytes(2, 'little')
         and original_frame[199:] == runtime.emit(base['snapshot'].state(profile.domain)),
         'exact-actual-W-zero-proof-frame')
    records = v.decode_payload(bytes.fromhex(candidate['transaction']['payload']))
    after = virtual_prefix(runtime, base, records, output / 'independent-two-child-replay')
    state, successor = base['snapshot'].state(profile.domain), after['snapshot'].state(profile.domain)
    daa = actual_daa(base, runtime)
    zero, contexts, metrics = runtime.normalize_case(candidate, output / 'zero-normalize')
    need(zero == candidate and contexts == [base['head_context']]
         and candidate['transaction']['inputs'][0]['previousOutpoint'] == base['point']
         and candidate['transaction']['inputs'][0]['computeBudget'] == profile.aggregate_budget
         and candidate['transaction']['outputs'] == [{'value': after['reserve'],
            'scriptPublicKey': c.native_runtime.p2sh(runtime.emit(successor)), 'covenant': None}],
         'exact-original-current-context-and-authorized-outer-body')
    runtime.sdk(candidate['transaction'], contexts)

    def codecs(case, label):
        projection = v.financial_projection(case)
        journal = v.encode_journal(profile.wrapper_domain, profile.domain, base['point'], state,
            base['reserve'], successor, after['reserve'], base['reserve']-after['reserve'], records, projection)
        need(projection == expected_projection and journal == expected_journal
             and len(projection) == 8301 and len(journal) == 424, 'exact-selected-projection-and-journal')
        result = subprocess.run(['/w-codec'], input=json.dumps({'operation': 'body', 'case': case}),
            capture_output=True, text=True, env=dict(CLEAN))
        need(result.returncode == 0 and not result.stderr, 'selected-independent-native-body-codec')
        native = parse(result.stdout)
        save(output / (label+'-native-codec.json'), native)
        need(native['template_kind'] == 'ACTUAL_R0_W' and native['outer_image_hex32'] == profile.image_id.hex()
             and native['financial_projection_hex'] == projection.hex() and native['journal_hex424'] == journal.hex()
             and native['journal_sha256'] == JOURNAL_SHA and native['financial_projection_sha256'] == PROJECTION_SHA,
             'independent-native-Python-codec-exact-join')
        return projection, journal

    codecs(candidate, 'before')
    changed = copy.deepcopy(candidate); frame = bytearray(original_frame); frame[68:196] = proof
    changed['transaction']['inputs'][0]['signatureScript'] = frame.hex()
    actual, actual_contexts, actual_metrics = runtime.normalize_case(changed, output / 'genuine-normalize')
    need(actual == changed and actual_contexts == contexts and actual_metrics == metrics,
         'only-proof-slot-changed-official-body-ID-mass-preserved')
    runtime.sdk(actual['transaction'], actual_contexts); codecs(actual, 'after')
    need(metrics['actual_fee_sompi'] == base['reserve']-after['reserve']
         and metrics['actual_fee_sompi'] == 100 * metrics['mining_mass']
         and preparation['financial_profile_sha256'] == PROFILE_SHA
         and preparation['history_sha256'] == HISTORY_SHA and preparation['journal_sha256'] == JOURNAL_SHA
         and preparation['projection_sha256'] == PROJECTION_SHA
         and preparation['transaction_id'] == actual['transaction']['id']
         and preparation['fee_sompi'] == metrics['actual_fee_sompi']
         and preparation['new_reserve_sompi'] == after['reserve'], 'genuine-outer-fee-and-preparation-join')
    outcomes = []
    cases = (('genuine-actual-W-positive', actual),) + binding_cases(actual)
    need(len(cases) == 6, 'exact-positive-plus-five-binding-cases')
    for index, (label, case) in enumerate(cases):
        checked_case, ctx, mass = runtime.normalize_case(case, output / ('control-normalize-'+str(index)))
        need(bytes.fromhex(checked_case['transaction']['inputs'][0]['signatureScript'])[68:196] == proof,
             'every-control-keeps-genuine-proof-unchanged')
        runtime.sdk(checked_case['transaction'], ctx)
        directory = output / ('control-'+str(index)); directory.mkdir(mode=0o700)
        save(directory / 'validation-case.json', checked_case)
        runtime.native.run(['validate-transaction', directory / 'validation-case.json', directory / 'native'])
        report = parse((directory / 'native/native-validation.json').read_bytes())
        checked_mass = parse((directory / 'native/metrics.json').read_bytes())
        engines = report['per_input_ScriptEngine']; expected = index == 0
        need(mass == checked_mass and report['isolation'] == 'PASS' and len(engines) == 1
             and report['Full']['accepted'] is expected
             and report['all_input_engines_accepted'] is expected and engines[0]['accepted'] is expected,
             'fresh-Native-Full-binding-outcome-'+label)
        error = engines[0].get('typed_error', '')
        expected_error = None if expected else 'ZkIntegrity' if index in (1, 2) else 'VerifyError'
        need(expected_error is None or expected_error in error, 'typed-native-public-binding-rejection')
        outcomes.append({'label': label, 'Full_accepted': expected, 'engine_accepted': expected,
            'isolation_PASS': True, 'engine_typed_error': error, 'engine_units': engines[0]['units'],
            'actual_fee_sompi': mass['actual_fee_sompi'], 'mining_mass': mass['mining_mass']})
    # No zero-proof candidate ever enters wallet history. The complete result
    # is independently replayed from signed GN2 by the exact selected runtime.
    appended = append_local_case(history, actual, after['reserve'], daa)
    raw_next = save(output / 'HISTORY-1.json', appended); next_sha = digest(raw_next)
    replayed = replay_local(raw_next, next_sha, profile, runtime, output / 'appended-history-replay')
    need(replayed['reserve'] == after['reserve'] and replayed['point'] == {
        'transactionId': actual['transaction']['id'], 'index': 0}
        and snapshot_record(replayed['snapshot']) == snapshot_record(after['snapshot'])
        and len(replayed['operations']) == 1 and not replayed['payouts'], 'exact-replayed-local-aggregate-history')
    save(output / 'validation-case.json', actual)
    result = {'schema': 'kpx6-four-wallet-genuine-outer-finalization/v1',
        'classification': 'GENUINE_NATIVE_FULL_UNFUNDED_SUPPLIED_CONTEXTS_NOT_ACCEPTED',
        'financial_profile_sha256': PROFILE_SHA, 'proof_sha256': args.proof_sha256,
        'projection_sha256': PROJECTION_SHA, 'journal_sha256': JOURNAL_SHA,
        'history1_sha256': next_sha, 'transaction_id': actual['transaction']['id'],
        'fee_sompi': metrics['actual_fee_sompi'], 'reserve_after_sompi': after['reserve'],
        'native_binding_case_count': 6, 'native_outcomes': outcomes,
        'proof_slot_only_body_ID_mass_preserved': True, 'SDK_roundtrip': True,
        'independent_codec_before_after_identical': True, 'appended_history_replayed': True,
        'whole_selected_W_native_Full_all_engines': True,
        'private_backup_PK_proof_generation_network_or_broadcast': False,
        'accepted_chain_backing_currentness_or_privacy_claimed': False}
    save(output / 'RESULTS.json', result)
    return result


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('op', choices=('finalize', '_worker'))
    for name in ('output', 'software-root', 'financial-profile', 'history', 'case', 'proof',
                 'projection', 'journal', 'preparation', 'codec'):
        parser.add_argument('--'+name, type=Path)
    for name in ('case-sha256', 'proof-sha256', 'preparation-sha256', 'program-sha256'):
        parser.add_argument('--'+name)
    parser.add_argument('--exclude-private-root', type=Path, action='append', default=[])
    parser.add_argument('--execute', action='store_true')
    return parser.parse_args()


if __name__ == '__main__':
    try:
        args = arguments()
        print(json.dumps(worker(args) if args.op == '_worker' else stage(args), sort_keys=True))
    except Exception as error:
        print(json.dumps({'error': 'public-actual-W-finalization-incomplete', 'submitted': False,
            'category': str(error) if type(error) is ValueError else type(error).__name__}))
        raise SystemExit(1)
