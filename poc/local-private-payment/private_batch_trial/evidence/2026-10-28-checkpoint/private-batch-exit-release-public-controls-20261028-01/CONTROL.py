#!/usr/bin/env python3
"""Known public genuine AuthExit fixtures; no Original or private wallet run."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
HERE = ROOT / 'poc/local-private-payment/private_batch_trial'
OUT = ROOT / '.local/private-batch-exit-release-public-controls-20261028-01'
read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
for path in (HERE / 'exit_release.py', HERE / 'exit_wire.py', HERE / 'new_private_trial.py'):
    read(path)
sys.path.insert(0, str(HERE))
import exit_release as release
import exit_wire
import new_private_trial as bootstrap

os.umask(0o077)
started = time.monotonic()
sources, mounts = [], []
shared = OUT / 'selected-public'
shared.mkdir(mode=0o700)
for index, path in enumerate((HERE / 'exit_release.py', HERE / 'exit_wire.py', HERE.parent / 'verification/wire.py')):
    raw = read(path)
    copied = shared / ('source-' + str(index))
    pin = release.write(copied, raw)
    sources.append({'path': str(path), 'sha256': pin})
    mounts += ['--ro-bind', str(copied), str(path)]
runtimes = []
for alias, path, pin in (
    ('/runtime/prover', bootstrap.BINARY, bootstrap.BINARY_SHA),
    ('/parameters/MANIFEST.json', ROOT / '.local/private-batch-component-parameters/auth-exit-01/MANIFEST.json',
     'bc41c97e06f07a06ee9ab2af59ef1ba8c5190a126dfb0eb120d586667aaddd8f')):
    copied = shared / ('runtime-' + str(len(runtimes)))
    release.write(copied, read(path, pin), 0o500 if alias == '/runtime/prover' else 0o400)
    runtimes.append({'path': alias, 'sha256': pin})
    mounts += ['--ro-bind', str(copied), alias]
release.write(shared / 'NAMESPACE.json', {'schema': 'kpb-owner-exit-release-namespace/v1',
    'network': 'disabled', 'private_candidate_slots': 1, 'Original_slots': 0})
results = []
for kind in ('continuing-positive', 'terminal-positive', 'changed-proof-negative'):
    source_kind = 'continuing-positive' if kind == 'changed-proof-negative' else kind
    path = ROOT / ('poc/local-private-payment/private-batch-public/native/evidence/'
                   '2026-10-28-exit-component/native') / source_kind / 'CASE.json'
    case_raw = read(path)
    case = release.parse(case_raw)
    script = bytes.fromhex(case['transaction']['inputs'][0]['signatureScript'])
    assert script[:2] == b'\x4c\x80' and script[130:131] == b'\x4d'
    proof, size, redeem = script[2:130], int.from_bytes(script[131:133], 'little'), script[133:]
    assert size == len(redeem) == 8211 and redeem[:2] == b'\x4c\x70'
    tail = redeem[114:]
    body = bytes.fromhex(case['transaction']['payload'])
    context = exit_wire.parse_body(body).context
    projection = exit_wire.projection(body, tail)
    if kind == 'changed-proof-negative':
        proof = bytes([proof[0] ^ 1]) + proof[1:]
    candidate = {'schema': 'kpb-owner-prepared-independent-exit/v1', 'scope': release.SCOPE,
        'projection_hex': projection.hex(), 'proof_hex128': proof.hex(),
        'statement_hex152': exit_wire.statement(projection).hex(), 'native_or_chain_acceptance': False}
    role = OUT / kind
    role.mkdir(mode=0o700)
    public = role / 'public'
    public.mkdir(mode=0o700)
    # This is an explicitly known public fixture, never an actual private leaf.
    release.write(role / 'KNOWN-PUBLIC-MODEL-CANDIDATE.json', candidate, 0o600)
    identities = (context.chain, context.pool, context.profile, context.domain, context.service)
    names = ('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32', 'service_hex32')
    history = dict(zip(names, (word.hex() for word in identities)))
    history.update(schema='kpb-private-batch-public-history/v1', scope=release.SCOPE, genesis={}, transitions=[],
        head={'outpoint_hex36': context.point.hex(), 'state_hex112': context.state().hex(),
              'reserve_sompi': context.reserve})
    history_pin = release.write(role / 'PUBLIC-HISTORY.json', history)
    tail_pin = release.write(role / 'IMMUTABLE-TAIL.bin', tail)
    config = dict(zip(names, (word.hex() for word in identities)))
    config.update(source_members=sources, runtime_members=runtimes, history_sha256=history_pin,
        tail_sha256=tail_pin, manifest_sha256=runtimes[1]['sha256'])
    release.write(role / 'CONFIG.json', config)
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', *mounts,
        '--ro-bind', str(role / 'CONFIG.json'), '/CONFIG.json',
        '--ro-bind', str(shared / 'NAMESPACE.json'), '/NAMESPACE.json',
        '--ro-bind', str(role / 'PUBLIC-HISTORY.json'), '/public/PUBLIC-HISTORY.json',
        '--ro-bind', str(role / 'IMMUTABLE-TAIL.bin'), '/public/IMMUTABLE-TAIL.bin',
        '--ro-bind', str(role / 'KNOWN-PUBLIC-MODEL-CANDIDATE.json'), '/candidate/EXIT-CANDIDATE.json',
        '--bind', str(public), '/out', '--chdir', '/out', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8', '/usr/bin/python3', '-B', str(HERE / 'exit_release.py'), '_owner']
    completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    release.write(role / 'KNOWN-PUBLIC-STDOUT.log', completed.stdout)
    release.write(role / 'KNOWN-PUBLIC-STDERR.log', completed.stderr)
    expected = kind != 'changed-proof-negative'
    assert (completed.returncode == 0) == expected, (kind, completed.stderr.decode(errors='replace'))
    assert (public / 'PUBLIC-CANDIDATE.json').exists() == expected
    if expected:
        assert release.parse((public / 'PUBLIC-CANDIDATE.json').read_bytes()) == candidate
        status = release.parse((public / 'PUBLIC.json').read_bytes())
        assert status['AuthExit_proof_verified'] is True
        assert status['native_or_chain_acceptance'] is False
    results.append({'control': kind, 'expected_public_release': expected,
        'actual_returncode': completed.returncode, 'source_public_CASE_sha256': hashlib.sha256(case_raw).hexdigest(),
        'passed': True})
result = {'schema': 'kpb-explicit-exit-release-public-controls/v1', 'status': 'PASS',
    'scope': 'KNOWN_PUBLIC_GENUINE_AUTH_EXIT_FIXTURES_ONLY', 'controls': results,
    'source_members': sources, 'runtime_members': runtimes,
    'actual_Original_private_candidate_truth_or_MPC_input_read': False,
    'Output_or_AuthExit_proving_key_mounted': False, 'network_mining_funding_or_broadcast': False,
    'accepted_history_native_Full_or_privacy_qualification': False,
    'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'wall_seconds': time.monotonic() - started}
release.write(OUT / 'RESULT.json', result)
print(json.dumps({'status': 'PASS', 'controls': len(results), 'result': str(OUT / 'RESULT.json')}))
