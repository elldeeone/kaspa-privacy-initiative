#!/usr/bin/env python3
"""One explicitly released FIRST submit for action8; no retry or state repair.

Main06 remains held and retains its caller flock. This separate operator uses
its own lock, never opens STATE/PLAN/Originals, and never acquires/changes the
caller's lock. The unchanged submit47c6 entry still owns both global O_EXCL
intent reservations, two fresh exact-input queries and the only submit RPC.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess

BASE = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/local-private-payment')
ROOT = Path('/var/tmp/kpi-local-private-payment-01/campaign/trial-02')
CONTROL = ROOT / 'control/first-submit8-recovery-01'
PRIVATE = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01')
TRIAL = '8e9b72ce-ea5f-48e1-a385-ecb14ed4e6ea'
STAGE = 'action-0008'
TXID = '35f828828e86fddd6eae3f64681a085b2d12a90bec832af83f1767c26ef00f5c'
PID = 2342132
UNIT = 'local-payment-campaign-06.service'
INVOCATION = '7c04a7e41e04459abd0de1ef2162ed4a'
UNIT_START = '690328647092'
KERNEL_START = '69032864'
ENDPOINT = 'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}


def row(path, sha):
    return {'path': str(path), 'sha256': sha}


CASE = row(ROOT / 'run/action-0008/native/CASE.json', 'f4d2f7d6956668251f04cd04eac8bb97a34a1de9f49a1c8700b904f7364ad79c')
REFUSAL = row(ROOT / 'run/action-0008/submission/INCOMPLETE.json', '0ae507bb4201f87fd61aebbe267296b3081b3da6547279c44254c9c04484dfe2')
CANDIDATE = row(ROOT / 'run/action-0008/submission/pool-preflight/result/SDK-CANDIDATE.json', '6b41caa4acec2f5bcc68e439ea9bf4f5be20e13a0a04ddf60bcfedfb758df0a5')
NATIVE = row(ROOT / 'run/action-0008/native/RESULT.json', '15910b7fe2386dc6856bab8bc4c54a576a7682b017da78b17660c053b5f9ce59')
HOLD = row(CONTROL / 'ROOT-MAIN-06-HOLD.json', 'c8e6a2ff3cb334c74d8f999aa8ae126af93d3c30f4c1b37679af3ed8b57d9c04')
HEAD = row(ROOT / 'run/action-0007/confirmation-1793006312502170950/HANDOFF.json', '9a217db86e95735513bc4a309503bbab202ba0261a34ca414b0fb5f6a1ffac5a')
SELECTION = row(ROOT / 'pool-campaign-01/CAMPAIGN-SELECTION.json', 'b5616b6bd845df73eb00fc3cd5382f54494feea2fc5552181b5998d0e453af69')
POOL = row(ROOT / 'pool-campaign-01/POOL-SELECTION.json', '36885fbf27474972ace077581c2a58502e64a1429bf254eb2feff27ad440b4d3')
SUBMIT = row(BASE / 'chain/submit_pool.mjs', '47c695afc9dc229b65fcb9dd0f3d7988a240e40209103436da0aff739656fab1')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def checked(value):
    p = Path(value).absolute()
    need('..' not in p.parts and not any(q.is_symlink() for q in (p, *p.parents)), 'canonical-path-no-symlinks')
    return p


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite-json'))


def public_read(selected):
    return runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](selected['path'], selected['sha256'])


def save(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    fd = os.open(checked(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        remaining = memoryview(raw)
        while remaining:
            n = os.write(fd, remaining)
            need(n > 0, 'public-write-incomplete')
            remaining = remaining[n:]
        os.fsync(fd)
        need(os.fstat(fd).st_size == len(raw), 'public-write-size')
    finally:
        os.close(fd)
    return row(path, hashlib.sha256(raw).hexdigest())


def no_attempt(value):
    expected = {'schema': 'kpxa-single-native-submission/v1', 'trial_id': TRIAL, 'stage': STAGE,
        'transaction_id': TXID, 'status': 'INCOMPLETE_QUERY_ONLY', 'durable_intent_reserved': False,
        'submission_attempted': False, 'automatic_resubmission_permitted': False,
        'confirmation_claimed': False, 'stage_already_used': False,
        'category': 'PUBLIC_RPC_OR_INTENT_UNAVAILABLE'}
    need(value == expected and all(value[k] is False for k in ('durable_intent_reserved',
        'submission_attempted', 'automatic_resubmission_permitted', 'confirmation_claimed', 'stage_already_used')),
        'exact-pinned-no-attempt-record-required')


def same_financial_evidence(candidate, native, case):
    need(candidate['schema'] == 'kpxa-public-submit-candidate/v1'
         and candidate['trial_id'] == TRIAL and candidate['stage'] == STAGE
         and candidate['mode'] == 'lifecycle' and candidate['case_sha256'] == CASE['sha256']
         and candidate['transaction']['id'] == TXID
         and candidate['actual_native_Full_passed'] is True and candidate['broadcast_performed'] is False
         and native['native_Full_accepted'] is True and native['all_input_scripts_accepted'] is True
         and native['mode'] == 'direct-exit' and native['transaction_id'] == TXID
         and native['validated_case_sha256'] == CASE['sha256']
         and case['transaction']['id'] == TXID, 'same-qualified-whole-exit-CASE-and-candidate-required')


def intent_targets():
    return (PRIVATE / 'submission-intents' / TRIAL / ('stage-' + STAGE + '.intent.json'),
            PRIVATE / 'submission-transactions' / ('tx-' + TXID + '.intent.json'))


def absent_intents():
    for target in intent_targets():
        try:
            checked(target).lstat()  # Metadata only; never open/hash/remove an intent.
        except FileNotFoundError:
            continue
        raise ValueError('intent-exists-reconcile-read-only-never-submit')


def process_metadata():
    p = subprocess.run(['/usr/bin/systemctl', '--user', 'show', UNIT, '--property=MainPID',
        '--property=ActiveState', '--property=InvocationID', '--property=ExecMainStartTimestampMonotonic'],
        capture_output=True, text=True, env=dict(CLEAN, XDG_RUNTIME_DIR='/run/user/' + str(os.getuid())))
    need(p.returncode == 0, 'main-unit-metadata-unavailable')
    unit = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
    # Kernel process identity metadata only, no cmdline/environment/log access.
    suffix = Path('/proc/' + str(PID) + '/stat').read_text().rsplit(')', 1)[1].split()
    return unit, suffix[0], suffix[19]


def held_identity(unit, state, ticks):
    need(unit.get('MainPID') == str(PID) and unit.get('ActiveState') == 'active'
         and unit.get('InvocationID') == INVOCATION
         and unit.get('ExecMainStartTimestampMonotonic') == UNIT_START
         and state == 'T' and ticks == KERNEL_START, 'exact-Root-held-main06-identity-required')


def held_gate():
    held_identity(*process_metadata())
    need(not os.path.lexists(ROOT / 'run/action-0009')
         and not os.path.lexists(ROOT / 'run/action-0008/CONFIRMED.json'), 'same-consumed8-public-boundary-required')
    sock = checked('/var/tmp/kpi-local-private-payment-01/pool-ipc-06/p.sock')
    s, parent = sock.lstat(), sock.parent.lstat()
    need(stat.S_ISSOCK(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600 and s.st_uid == os.getuid()
         and stat.S_IMODE(parent.st_mode) == 0o700 and parent.st_uid == os.getuid(), 'same-closed-warm-pool06-required')


def evidence():
    no_attempt(parse(public_read(REFUSAL)))
    same_financial_evidence(parse(public_read(CANDIDATE)), parse(public_read(NATIVE)), parse(public_read(CASE)))
    hold = parse(public_read(HOLD))
    need(hold['schema'] == 'kpxa-root-main-only-hold/v1' and hold['pid'] == PID
         and hold['invocation_id'] == INVOCATION and hold['kernel_start_ticks'] == KERNEL_START
         and hold['state'] == 'T' and hold['both_global_intent_records_absent_metadata_only'] is True
         and hold['incomplete_sha256'] == REFUSAL['sha256'], 'exact-Root-hold-evidence-required')
    selection, head, pool = (parse(public_read(r)) for r in (SELECTION, HEAD, POOL))
    need(selection['trial_id'] == TRIAL and selection['scripts']['submit'] == SUBMIT
         and head['trial_id'] == TRIAL and head['accepted_whole_CASE_equals_expected'] is True
         and head['accepted_transactions'] == 8
         and pool['socket'] == '/var/tmp/kpi-local-private-payment-01/pool-ipc-06/p.sock',
         'same-reviewed-campaign-current-head-and-warm-pool')
    for selected in pool['source_members']:
        public_read(selected)
    public_read(selection['node'])
    public_read(SUBMIT)
    return selection, head


def arguments(selection, head, output, *, execute):
    argv = [selection['node']['path'], SUBMIT['path'], '--mode', 'lifecycle', '--stage', STAGE,
        '--trial-id', TRIAL, '--case', CASE['path'], '--case-sha256', CASE['sha256'],
        '--output', str(output / 'submission'), '--journal', str(PRIVATE / 'campaign-trial-02/controller/submission-journal'),
        '--rpc', ENDPOINT, '--pool-selection', POOL['path'], '--pool-selection-sha256', POOL['sha256']]
    activation = parse(public_read(selection['activation']))
    for name in ('selection', 'descriptor', 'assets', 'parameters', 'codec'):
        r = activation[name]
        public_read(r)
        argv += ['--' + name, r['path'], '--' + name + '-sha256', r['sha256']]
    fetch = head['selectors']['fetch.json']
    argv += ['--fetch', fetch['path'], '--fetch-sha256', fetch['sha256'], '--bundle-directory', str(Path(fetch['path']).parent),
        '--baseline-fetch', fetch['path'], '--baseline-fetch-sha256', fetch['sha256'],
        '--baseline-bundle-directory', str(Path(fetch['path']).parent), '--trusted-local-cache']
    cache = head['selectors']['CACHE.json']
    argv += ['--baseline-cache', cache['path'], '--baseline-cache-sha256', cache['sha256']]
    for key, flag in (('runtime_source', 'runtime-source'), ('admission', 'cache-admission')):
        r = selection['cache_policy'][key]
        argv += ['--' + flag, r['path'], '--' + flag + '-sha256', r['sha256']]
    if execute:
        argv.append('--execute')
    return argv


def run(output, *, execute=False):
    selection, head = evidence()
    held_gate()
    absent_intents()
    output = checked(output)
    need(output.is_relative_to(CONTROL) and not os.path.lexists(output), 'fresh-public-operator-output-required')
    output.mkdir(mode=0o700)
    # This new operator lock is separate from the caller's still-owned flock.
    # Never acquire, clear, steal, unlock or inspect the caller's lock/STATE.
    fd = os.open(checked(CONTROL / 'FIRST-SUBMIT8-OPERATOR-LOCK'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
             'separate-single-link-operator-lock')
        argv = arguments(selection, head, output, execute=execute)
        save(output / 'INVOCATION.json', {'schema': 'kpxa-explicit-first-submit8/v1', 'execute': execute,
            'trial_id': TRIAL, 'stage': STAGE, 'transaction_id': TXID, 'case': CASE, 'candidate': CANDIDATE,
            'no_attempt': REFUSAL, 'Root_hold': HOLD, 'submitter': SUBMIT, 'pool': POOL,
            'selected_rpc': ENDPOINT, 'argv': argv, 'caller_lock_or_STATE_PLAN_Original_read_or_changed': False,
            'automatic_retry_or_resubmission_permitted': False})
        # Repeat immediately before the unchanged child's live checks/O_EXCL.
        # A partial reservation always blocks this helper, never gets cleared.
        held_gate()
        absent_intents()
        process = subprocess.run(argv, capture_output=True, env=CLEAN)
        result = {'schema': 'kpxa-explicit-first-submit8-result/v1', 'execute': execute,
            'returncode': process.returncode, 'submission_result_directory': str(output / 'submission'),
            'confirmation_claimed': False, 'automatic_retry_or_resubmission_permitted': False,
            'private_STATE_PLAN_Original_contents_read_or_mutated': False,
            'private_intents_may_be_created_only_by_frozen_submitter': execute,
            'signals_or_caller_restart_performed': False}
        save(output / 'RESULT.json', result)
        return result
    finally:
        os.close(fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--execute', action='store_true')
    a = p.parse_args()
    value = run(a.output, execute=a.execute)
    print(json.dumps(value, sort_keys=True))
    raise SystemExit(value['returncode'])


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('first-submit8 refused; preserve state/intents; no automatic retry, resume or signals')
