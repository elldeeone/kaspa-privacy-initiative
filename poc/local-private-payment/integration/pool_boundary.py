#!/usr/bin/env python3
"""Public-metadata-only optional boundary hold; never stops a submit/GPU child."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import stat
import subprocess
import time
import uuid

PUBLIC = Path('/var/tmp/kpi-local-private-payment-01/campaign/trial-02')
UNIT = 'local-payment-campaign-05.service'
PID = 2236369
SUBMISSION = PUBLIC / 'run/action-0004/submission/RESULTS.json'
NEXT = PUBLIC / 'run/action-0005'
TXID = '8dfea1ffaf36910bd5b00f1308b447b4c896b8130dfb0d15bcf080a159ab22a2'
CASE_SHA = 'ce69c977e8aa5dfedcf3883c330865b8ce0b64dbc6e5949e1e57c05b84f9b7d3'


def need(ok, category):
    if not ok:
        raise ValueError(category)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def save(path, value):
    raw = encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as f:
        need(f.write(raw) == len(raw), 'complete-public-control-write')
        f.flush()
        os.fsync(f.fileno())
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}


def metadata_exists(path):
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def unit_metadata():
    p = subprocess.run(['/usr/bin/systemctl', '--user', 'show', UNIT, '--property=MainPID',
        '--property=ActiveState', '--property=ExecMainStartTimestampMonotonic'], capture_output=True, text=True)
    need(p.returncode == 0, 'unit-metadata-unavailable')
    return dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)


def same_main(value, expected_start):
    return (value.get('MainPID') == str(PID) and value.get('ActiveState') == 'active'
            and value.get('ExecMainStartTimestampMonotonic') == expected_start)


def kernel_start_ticks():
    """Read only Linux process identity metadata, never a command line/log."""
    value = Path('/proc/' + str(PID) + '/stat').read_text()
    # comm is parenthesized and may itself contain spaces or ')'. Field 22 is
    # starttime; the suffix starts with field 3 (state).
    suffix = value.rsplit(')', 1)[1].split()
    ticks = suffix[19]
    need(ticks.isascii() and ticks.isdecimal() and str(int(ticks)) == ticks,
         'kernel-process-start-identity')
    return ticks


def checked_pidfd(proposal):
    fd = os.pidfd_open(PID)
    try:
        need(kernel_start_ticks() == proposal['kernel_start_ticks']
             and same_main(unit_metadata(), proposal['main_start_monotonic']),
             'pidfd-open-must-bind-selected-kernel-and-unit-start-identity')
        return fd
    except BaseException:
        os.close(fd)
        raise


def held_status(proposal, current, kernel_ticks, next_exists, stopped):
    # NEXT can race the pre-signal check. Holding is best-effort, not atomic.
    # Never resume automatically after a race; Root reviews the stopped main.
    if (not same_main(current, proposal['main_start_monotonic'])
            or kernel_ticks != proposal['kernel_start_ticks'] or next_exists or not stopped):
        return 'HELD_REQUIRES_ROOT_REVIEW'
    return 'MAIN_ONLY_HELD_AWAITING_ROOT_TYPED_ACK_REVIEW'


def ready_value(proposal):
    return {'schema': 'kpxa-Root-qualified-pool-ready/v1',
        'classification': 'ROOT_QUALIFIED_PROFILE_READY_FOR_BOUNDARY_HOLD',
        'watch_id': proposal['watch_id'], 'unit': UNIT, 'main_pid': PID,
        'kernel_start_ticks': proposal['kernel_start_ticks'],
        'qualified_profile': proposal['qualified_profile'], 'boundary_action': 'action-0004',
        'transaction_id': TXID, 'case_sha256': CASE_SHA, 'next_action': 'action-0005'}


def may_hold(proposal, ready, marker_info, next_exists, current):
    return (ready == ready_value(proposal) and marker_info is not None
            and stat.S_ISREG(marker_info.st_mode) and marker_info.st_nlink == 1
            and not next_exists and same_main(current, proposal['main_start_monotonic']))


def prepare(profile, profile_sha, output):
    profile = Path(profile).absolute()
    output = output.absolute()
    need(profile.is_relative_to(PUBLIC.parents[1]) and output.is_relative_to(PUBLIC)
         and '..' not in profile.parts and '..' not in output.parts
         and type(profile_sha) is str and len(profile_sha) == 64
         and all(c in '0123456789abcdef' for c in profile_sha), 'exact-public-qualified-profile-and-control')
    need(not output.exists(), 'fresh-control-identity-directory')
    current = unit_metadata()
    need(same_main(current, current.get('ExecMainStartTimestampMonotonic'))
         and current.get('ExecMainStartTimestampMonotonic', '').isdecimal(), 'exact-current-main-identity')
    ticks = kernel_start_ticks()
    need(same_main(unit_metadata(), current['ExecMainStartTimestampMonotonic'])
         and kernel_start_ticks() == ticks, 'stable-prepare-kernel-and-unit-identity')
    output.mkdir(mode=0o700, parents=True)
    proposal = {'schema': 'kpxa-optional-pool-boundary-watch/v1', 'watch_id': str(uuid.uuid4()),
        'qualified_profile': {'path': str(profile), 'sha256': profile_sha},
        'main_start_monotonic': current['ExecMainStartTimestampMonotonic'],
        'kernel_start_ticks': ticks,
        'ready_flag': str(output / 'ROOT-QUALIFIED-PROFILE.READY.json'), 'output': str(output),
        'unit': UNIT, 'main_pid': PID, 'submission': str(SUBMISSION), 'next_action_directory': str(NEXT)}
    selected = save(output / 'PROPOSAL.json', proposal)
    save(output / 'READY-CONTENT-TEMPLATE-ONLY.json', {'classification': 'TEMPLATE_ONLY_NOT_A_READY_FLAG',
        'Root_ready_content': ready_value(proposal)})
    return selected


def watch(proposal, read):
    need(proposal['schema'] == 'kpxa-optional-pool-boundary-watch/v1'
         and proposal['unit'] == UNIT and proposal['main_pid'] == PID
         and proposal['submission'] == str(SUBMISSION)
         and proposal['next_action_directory'] == str(NEXT), 'fixed-public-boundary')
    out = Path(proposal['output'])
    ready_path = Path(proposal['ready_flag'])
    need(out.is_relative_to(PUBLIC) and ready_path == out / 'ROOT-QUALIFIED-PROFILE.READY.json'
         and '..' not in out.parts and not any(p.is_symlink() for p in (out, *out.parents)),
         'exact-Root-ready-flag-path')
    result = {'schema': 'kpxa-optional-boundary-watch-result/v1', 'watch_id': proposal['watch_id'],
        'unit': UNIT, 'main_pid': PID, 'signal_sent': False,
        'private_STATE_PLAN_log_Original_or_owner_data_read': False,
        'submit_or_GPU_child_signalled': False, 'financial_retry_or_submission_performed': False}
    while True:
        current = unit_metadata()
        if not same_main(current, proposal['main_start_monotonic']):
            result['status'] = 'NO_HOLD_MAIN_IDENTITY_CHANGED'
            break
        if metadata_exists(NEXT) is not None:
            result['status'] = 'NO_HOLD_NEXT_ACTION_ALREADY_STARTED'
            break
        marker = metadata_exists(SUBMISSION)
        if marker is None:
            time.sleep(0.2)
            continue
        # The watcher reads no submission contents. Root verifies its typed ACK
        # after the main-only hold and before deciding any kill/resume action.
        if metadata_exists(ready_path) is None:
            result['status'] = 'NO_HOLD_QUALIFIED_PROFILE_NOT_READY'
            break
        try:
            ready = json.loads(read(str(ready_path)))
        except Exception:
            result['status'] = 'NO_HOLD_READY_FLAG_UNREADABLE'
            break
        if not may_hold(proposal, ready, marker, metadata_exists(NEXT) is not None, current):
            result['status'] = 'NO_HOLD_READY_OR_BOUNDARY_MISMATCH'
            break
        profile = proposal['qualified_profile']
        read(profile['path'], profile['sha256'])  # Exact public qualified profile, never private payload.
        pidfd = checked_pidfd(proposal)
        try:
            # Recheck unit/start identity and absence immediately before the
            # pidfd-bound main signal. No process-group or child signal exists.
            if not may_hold(proposal, ready, metadata_exists(SUBMISSION),
                            metadata_exists(NEXT) is not None, unit_metadata()) \
                    or kernel_start_ticks() != proposal['kernel_start_ticks']:
                result['status'] = 'NO_HOLD_BOUNDARY_CHANGED'
                break
            signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
            result['signal_sent'] = True
        finally:
            os.close(pidfd)
        try:
            state = subprocess.run(['/usr/bin/ps', '-p', str(PID), '-o', 'stat='],
                                   capture_output=True, text=True).stdout.strip()
            result['main_metadata_stopped'] = state.startswith('T')
            result['status'] = held_status(proposal, unit_metadata(), kernel_start_ticks(),
                                          metadata_exists(NEXT) is not None, state.startswith('T'))
        except Exception:
            result['main_metadata_stopped'] = None
            result['status'] = 'HELD_REQUIRES_ROOT_REVIEW'
        result['boundary_hold_is_best_effort_not_atomic'] = True
        break
    return save(out / 'RESULT.json', result)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('prepare', 'watch'))
    for name in ('qualified-profile', 'proposal'):
        p.add_argument('--' + name, type=Path)
        p.add_argument('--' + name + '-sha256')
    p.add_argument('--output', type=Path)
    p.add_argument('--execute', action='store_true')
    a = p.parse_args()
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    if a.operation == 'prepare':
        need(not a.execute, 'prepare-never-signals')
        print(json.dumps(prepare(a.qualified_profile, a.qualified_profile_sha256, a.output), sort_keys=True))
    else:
        proposal = json.loads(read(str(a.proposal), a.proposal_sha256))
        need(a.execute, 'Root-watch-activation-required')
        print(json.dumps(watch(proposal, read), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('boundary watch refused; no restart, kill, resume or financial retry performed')
