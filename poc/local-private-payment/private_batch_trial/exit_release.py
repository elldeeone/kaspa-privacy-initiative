#!/usr/bin/env python3
"""Explicitly release one owner's prepared public AuthExit candidate.

The controller admits paths and public selections only. A network-off role
opens the private candidate, checks its exact selected context/policy and real
AuthExit proof, then exports its public bytes. This is not native validation,
accepted-history admission, submission or a privacy qualification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

import exit_wire

HERE = Path(__file__).absolute().parent
SCOPE = 'UNFUNDED_SUPPLIED_CONTEXT'


def need(value, category):
    if not value:
        raise ValueError(category)


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'exit-release-duplicate-json-key')
        value[key] = item
    return value


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def fields(value, names):
    need(type(value) is dict and set(value) == set(names), 'exit-release-exact-fields')


def hx(value, width):
    need(type(value) is str and len(value) == width * 2
         and re.fullmatch('[0-9a-f]+', value) is not None, 'exit-release-canonical-hex')
    return bytes.fromhex(value)


def selected_head(value, identity):
    """Decode an explicitly supplied head; this does not admit its history."""
    fields(value, ('schema', 'scope', 'chain_hex32', 'pool_hex32', 'profile_hex32',
                   'domain_hex32', 'service_hex32', 'genesis', 'transitions', 'head'))
    need(value['schema'] == 'kpb-private-batch-public-history/v1' and value['scope'] == SCOPE,
         'exit-release-only-supplied-context')
    actual = tuple(hx(value[name], 32) for name in
                   ('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32', 'service_hex32'))
    need(actual == identity, 'exit-release-selected-profile')
    head = value['head']
    fields(head, ('outpoint_hex36', 'state_hex112', 'reserve_sompi'))
    state = hx(head['state_hex112'], 112)
    need(state[:8] == exit_wire.STATE_TAG and state[8:40] == actual[3], 'exit-release-selected-state')
    context = exit_wire.HeadContext(*actual, hx(head['outpoint_hex36'], 36), state[40:72], state[76:108],
        int.from_bytes(state[72:76], 'little'), int.from_bytes(state[108:112], 'little'), head['reserve_sompi'])
    need(type(context.reserve) is int and context.state() == state, 'exit-release-selected-live-head')
    return context


def validate_candidate(value, context, tail, verify):
    fields(value, ('schema', 'scope', 'projection_hex', 'proof_hex128', 'statement_hex152',
                   'native_or_chain_acceptance'))
    need(value['schema'] == 'kpb-owner-prepared-independent-exit/v1' and value['scope'] == SCOPE
         and value['native_or_chain_acceptance'] is False, 'exit-release-unfunded-candidate-only')
    projection = hx(value['projection_hex'], len(value['projection_hex']) // 2)
    proof, statement = hx(value['proof_hex128'], 128), hx(value['statement_hex152'], 152)
    exit_wire.require_current_head(projection, context, tail)
    need(statement == exit_wire.statement(projection), 'exit-release-exact-owner-statement')
    need(verify(statement, proof) is True, 'exit-release-genuine-AuthExit-proof')
    # Reconstruct the finite public schema; no unrecognized private field can
    # be carried across the role boundary, even if its JSON is otherwise valid.
    return {'schema': 'kpb-owner-prepared-independent-exit/v1', 'scope': SCOPE,
        'projection_hex': projection.hex(), 'proof_hex128': proof.hex(),
        'statement_hex152': statement.hex(), 'native_or_chain_acceptance': False}


def stable_read(path, expected=None, *, private=False):
    path = Path(path)
    need(not path.is_symlink() and not any(p.is_symlink() for p in path.parents), 'exit-release-regular-path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'exit-release-single-leaf')
        need(not private or stat.S_IMODE(before.st_mode) == 0o600, 'exit-release-private-mode')
        raw = handle.read()
        after = os.fstat(handle.fileno())
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink')
        need(all(getattr(before, k) == getattr(after, k) for k in keys), 'exit-release-stable-leaf')
    need(expected is None or hashlib.sha256(raw).hexdigest() == expected, 'exit-release-selected-hash')
    return raw


def write(path, value, mode=0o400):
    raw = value if type(value) is bytes else encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return hashlib.sha256(raw).hexdigest()


def worker():
    config = parse(stable_read('/CONFIG.json'))
    need(parse(stable_read('/NAMESPACE.json')) == {'schema': 'kpb-owner-exit-release-namespace/v1',
         'network': 'disabled', 'private_candidate_slots': 1, 'Original_slots': 0}, 'exit-release-role-marker')
    interfaces = [line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    need(interfaces == ['lo'] and not Path('/original').exists() and not Path('/home/luke/.codex').exists(),
         'exit-release-private-and-network-isolation')
    for row in config['source_members'] + config['runtime_members']:
        stable_read(row['path'], row['sha256'])
    tail = stable_read('/public/IMMUTABLE-TAIL.bin', config['tail_sha256'])
    history = parse(stable_read('/public/PUBLIC-HISTORY.json', config['history_sha256']))
    identity = tuple(hx(config[name], 32) for name in
                     ('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32', 'service_hex32'))
    context = selected_head(history, identity)
    def verify(statement, proof):
        request = {'operation': 'verify', 'role': 'new-auth-exit',
            'profile': {'domain_hex32': config['domain_hex32'], 'profile_id_hex32': config['profile_hex32']},
            'statement_hex': statement.hex(), 'proof_hex128': proof.hex(),
            'parameters': {'manifest': '/parameters/MANIFEST.json', 'manifest_sha256': config['manifest_sha256']}}
        result = subprocess.run(['/runtime/prover'], input=encoded(request), stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        need(result.returncode == 0, 'exit-release-verifier-refused')
        return parse(result.stdout).get('accepted') is True
    public = validate_candidate(parse(stable_read('/candidate/EXIT-CANDIDATE.json', private=True)), context, tail, verify)
    digest = write('/out/PUBLIC-CANDIDATE.json', public)
    write('/out/PUBLIC.json', {'schema': 'kpb-explicit-owner-exit-release/v1', 'scope': SCOPE,
        'candidate_sha256': digest, 'AuthExit_proof_verified': True, 'Original_or_openings_exported': False,
        'native_or_chain_acceptance': False, 'privacy_qualification': False})


def run(args):
    # Host-only imports are intentionally absent from the finite release role.
    import runpy
    import new_private_trial as bootstrap
    import private_lifecycle as lifecycle
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    need(re.fullmatch('[a-z][a-z0-9-]{0,63}', args.label), 'exit-release-fresh-label')
    trial = parse(read(bootstrap.checked(args.bootstrap_trial), args.bootstrap_trial_sha256))
    need(trial['schema'] == 'kpb-fresh-unfunded-private-original-trial/v1'
         and trial['owner_count'] == 3 and trial['controller_read_or_hashed_private_bodies'] is False,
         'exit-release-admitted-Original-trial')
    parent = bootstrap.checked(trial['private_original_parent'])
    need(parent.parent == bootstrap.PRIVATE and parent.name == trial['label'], 'exit-release-exact-trial-parent')
    prepared_path = bootstrap.checked(args.prepared_exit_result)
    prepared = parse(read(prepared_path, args.prepared_exit_result_sha256))
    need(prepared['schema'] == 'kpb-original-lifecycle-controller-result/v1' and prepared['scope'] == SCOPE
         and prepared['operation'] == 'exit' and prepared['bootstrap_trial_id'] == trial['trial_id']
         and prepared['controller_read_or_hashed_private_bodies'] is False
         and prepared['native_settlement_or_privacy_qualification'] is False, 'exit-release-prepared-role-result')
    previous = parse(read(prepared_path.parent / 'SELECTION.json'))
    need(previous['schema'] == 'kpb-original-lifecycle-selection/v1' and previous['operation'] == 'exit'
         and previous['operation_id'] == prepared['operation_id'] and previous['bootstrap_trial_id'] == trial['trial_id']
         and previous['history_sha256'] == args.history_sha256 and previous['tail_sha256'] == args.tail_sha256,
         'exit-release-exact-preparation-context')
    owners = [row for row in prepared['owners'] if row['owner_component'] == args.owner_component]
    need(len(owners) == 1, 'exit-release-one-prepared-owner')
    lifecycle.public_receipt(owners[0]['status'], 'exit')
    own = bootstrap.checked(owners[0]['private_output_directory'])
    need(own.is_relative_to(parent / 'operations') and own.name == 'owner-' + str(args.owner_component),
         'exit-release-derived-private-role-path')
    candidate = lifecycle.private_leaf(own / 'EXIT-CANDIDATE.json')  # metadata only
    public = bootstrap.checked(lifecycle.PUBLIC / args.label)
    private = bootstrap.checked(parent / 'operations' / args.label)
    need(not public.exists() and not private.exists(), 'exit-release-unused-operation')
    public.mkdir(mode=0o700, parents=True); private.mkdir(mode=0o700, parents=True)
    shared, out = public / 'selected-public', public / 'owner-release'
    shared.mkdir(mode=0o700); out.mkdir(mode=0o700)
    descriptor = parse(read(bootstrap.PROFILE, bootstrap.PROFILE_SHA))
    profile = descriptor['profile_descriptor']
    identity = (profile['chain_genesis_hex32'], lifecycle.POOL_HEX, descriptor['profile_id_hex32'],
                profile['domain_hex32'], profile['service_policy_hex32'])
    history_raw, tail = read(bootstrap.checked(args.history), args.history_sha256), read(bootstrap.checked(args.tail), args.tail_sha256)
    selected_head(parse(history_raw), tuple(bytes.fromhex(word) for word in identity))
    write(shared / 'PUBLIC-HISTORY.json', history_raw); write(shared / 'IMMUTABLE-TAIL.bin', tail)
    mounts, sources, runtimes = [], [], []
    for index, path in enumerate((HERE / 'exit_release.py', HERE / 'exit_wire.py', HERE.parent / 'verification/wire.py')):
        raw = read(path)
        saved = shared / ('source-' + str(index)); pin = write(saved, raw)
        sources.append({'path': str(path), 'sha256': pin})
        mounts += ['--ro-bind', str(saved), str(path)]
    for alias, path, pin in (('/runtime/prover', bootstrap.BINARY, bootstrap.BINARY_SHA),
        ('/parameters/MANIFEST.json', lifecycle.EXIT_PARAMETERS / 'MANIFEST.json', lifecycle.EXIT_MANIFEST_SHA)):
        saved = shared / ('runtime-' + str(len(runtimes)))
        write(saved, read(path, pin), 0o500 if alias == '/runtime/prover' else 0o400)
        runtimes.append({'path': alias, 'sha256': pin}); mounts += ['--ro-bind', str(saved), alias]
    config = dict(zip(('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32', 'service_hex32'), identity))
    config.update(history_sha256=args.history_sha256, tail_sha256=args.tail_sha256,
                  manifest_sha256=lifecycle.EXIT_MANIFEST_SHA, source_members=sources, runtime_members=runtimes)
    write(shared / 'CONFIG.json', config)
    write(shared / 'NAMESPACE.json', {'schema': 'kpb-owner-exit-release-namespace/v1',
        'network': 'disabled', 'private_candidate_slots': 1, 'Original_slots': 0})
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', *mounts,
        '--ro-bind', str(shared / 'CONFIG.json'), '/CONFIG.json',
        '--ro-bind', str(shared / 'NAMESPACE.json'), '/NAMESPACE.json',
        '--ro-bind', str(shared / 'PUBLIC-HISTORY.json'), '/public/PUBLIC-HISTORY.json',
        '--ro-bind', str(shared / 'IMMUTABLE-TAIL.bin'), '/public/IMMUTABLE-TAIL.bin',
        '--ro-bind', str(candidate), '/candidate/EXIT-CANDIDATE.json', '--bind', str(out), '/out',
        '--chdir', '/out', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
        '/usr/bin/python3', '-B', str(HERE / 'exit_release.py'), '_owner']
    selection = {'schema': 'kpb-explicit-owner-exit-release-selection/v1', 'scope': SCOPE,
        'bootstrap_trial_id': trial['trial_id'], 'prepared_operation_id': prepared['operation_id'],
        'owner_component': args.owner_component, 'history_sha256': args.history_sha256, 'tail_sha256': args.tail_sha256,
        'source_members': sources, 'runtime_members': runtimes, 'private_candidate_path': str(candidate),
        'controller_read_or_hashed_private_bodies': False, 'native_or_chain_acceptance': False}
    write(public / 'SELECTION.json', selection)
    if not args.execute:
        return {'status': 'EXIT_RELEASE_STAGED_NO_PRIVATE_READ_OR_EXPORT', 'selection': str(public / 'SELECTION.json')}
    launched = time.monotonic_ns()
    with (private / 'STDOUT.log').open('xb') as stdout, (private / 'STDERR.log').open('xb') as stderr:
        completed = subprocess.run(argv, env=bootstrap.CLEAN, stdout=stdout, stderr=stderr)
    write(public / 'OBSERVED-RELEASE-ROUTE.json', {'schema': 'kpb-observed-owner-exit-release/v1',
        'owner_component': args.owner_component, 'prepared_operation_id': prepared['operation_id'],
        'private_candidate_path': str(candidate), 'launch_monotonic_ns': launched,
        'complete_monotonic_ns': time.monotonic_ns(), 'worker_returncode': completed.returncode})
    need(completed.returncode == 0, 'exit-release-owner-worker-incomplete')
    receipt = parse(read(out / 'PUBLIC.json'))
    fields(receipt, ('schema', 'scope', 'candidate_sha256', 'AuthExit_proof_verified',
                     'Original_or_openings_exported', 'native_or_chain_acceptance', 'privacy_qualification'))
    need(receipt['schema'] == 'kpb-explicit-owner-exit-release/v1' and receipt['scope'] == SCOPE
         and receipt['AuthExit_proof_verified'] is True and receipt['Original_or_openings_exported'] is False
         and receipt['native_or_chain_acceptance'] is False and receipt['privacy_qualification'] is False,
         'exit-release-typed-public-completion')
    read(out / 'PUBLIC-CANDIDATE.json', receipt['candidate_sha256'])  # now explicitly released public bytes
    return {'status': 'PUBLIC_EXIT_CANDIDATE_EXPLICITLY_RELEASED', 'candidate': str(out / 'PUBLIC-CANDIDATE.json'),
            'candidate_sha256': receipt['candidate_sha256'], 'native_or_chain_acceptance': False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('release', '_owner'))
    for name in ('label', 'bootstrap-trial', 'bootstrap-trial-sha256', 'prepared-exit-result',
                 'prepared-exit-result-sha256', 'history', 'history-sha256', 'tail', 'tail-sha256'):
        parser.add_argument('--' + name)
    parser.add_argument('--owner-component', type=int, choices=(0, 1, 2))
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if args.operation == '_owner':
        worker()
    else:
        need(all(getattr(args, name.replace('-', '_')) is not None for name in
            ('label', 'bootstrap-trial', 'bootstrap-trial-sha256', 'prepared-exit-result',
             'prepared-exit-result-sha256', 'history', 'history-sha256', 'tail', 'tail-sha256', 'owner-component')),
            'exit-release-explicit-selection-required')
        print(json.dumps(run(args), sort_keys=True))


if __name__ == '__main__':
    main()
