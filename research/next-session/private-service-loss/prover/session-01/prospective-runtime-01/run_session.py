#!/usr/bin/env python3
"""One fresh setup/resident session; private bootstrap and raw logs stay private."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def save_new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def save(path, value):
    save_new(path, encoded(value))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    evidence, private_config = Path(sys.argv[1]).resolve(), Path(sys.argv[2])
    plan = json.loads((evidence / 'PLAN.json').read_bytes())
    for pin in json.loads((evidence / 'RUNTIME-FREEZE.json').read_bytes())['files']:
        raw = Path(pin['path']).read_bytes()
        if len(raw) != pin['bytes'] or digest(raw) != pin['sha256']:
            raise RuntimeError('public_runtime_input_changed')
    # This object and all host-side private paths remain outside Git and are
    # never included in public argv/launcher manifests, events or errors.
    configuration = json.loads(private_config.read_bytes())
    if set(configuration) != {'schema', 'shape', 'stage'} or configuration['schema'] != 'kpx3-private-setup-runtime/v1':
        raise RuntimeError('private_configuration_invalid')
    stage = Path(configuration['stage'])
    stage.mkdir(mode=0o700)
    output = stage / 'out'
    output.mkdir(mode=0o700)
    save(stage / 'PRIVATE-EXECUTION.json', configuration)
    fifo = stage / 'commands.fifo'
    os.mkfifo(fifo, 0o600)
    control = os.open(fifo, os.O_RDWR)
    bootstrap = json.dumps(configuration, separators=(',', ':')).encode() + b'\n'
    if len(bootstrap) >= 4096 or os.write(control, bootstrap) != len(bootstrap):
        os.close(control)
        raise RuntimeError('private_bootstrap_invalid')
    unit = plan['unit']
    if subprocess.run(['systemctl', '--user', 'show', unit, '--property=LoadState', '--value'],
                      capture_output=True, text=True).stdout.strip() not in ('', 'not-found'):
        os.close(control)
        raise RuntimeError('session_unit_used')
    properties = ['ActiveState', 'SubState', 'MainPID', 'ControlGroup', 'CPUUsageNSec',
                  'MemoryCurrent', 'MemoryPeak', 'MemorySwapCurrent']
    rows, events, proofs, seen_lines, ready = [], [], [], 0, None
    child, returncode, error = None, None, None
    started = now()
    setup_keys = {'schema', 'trial_id', 'network_id', 'genesis_hash_hex', 'domain_hex32',
        'core_source_identity', 'build_identity', 'compiled_build_identity_sha256', 'constraint_shape',
        'queries', 'vk_hex328', 'vk_sha256', 'format', 'pk_bytes', 'pk_sha256', 'setup_rng',
        'fresh_setup_and_finalized_shape_measurement_seconds',
        'official_serialization_stream_hash_fsync_and_same_fd_readback_seconds'}

    def observe_events():
        nonlocal seen_lines, ready
        chunks = (stage / 'raw-unit.log').read_text(errors='replace').splitlines(keepends=True)
        # Do not mark a partially written JSON event consumed before its newline.
        lines = chunks if not chunks or chunks[-1].endswith('\n') else chunks[:-1]
        for line in lines[seen_lines:]:
            try:
                value = json.loads(line)
            except ValueError:
                continue
            kind = value.get('event') if isinstance(value, dict) else None
            if kind == 'ready' and ready is None:
                raw = (output / 'setup-01/report.json').read_bytes()
                report = json.loads(raw)
                if set(report) != setup_keys or report['schema'] != 'kpx3-private-cashout-setup-result/v1':
                    raise RuntimeError('public_setup_report_schema')
                for key in ('trial_id', 'domain_hex32', 'compiled_build_identity_sha256', 'core_source_identity'):
                    if report[key] != plan[key]:
                        raise RuntimeError('public_setup_identity_mismatch')
                if report['network_id'] != 'testnet-10' or report['genesis_hash_hex'] != plan['genesis_hash_hex']:
                    raise RuntimeError('public_setup_network_mismatch')
                shape, queries = report['constraint_shape'], report['queries']
                if (set(shape) != {'constraints', 'witness_variables', 'instances_including_one'}
                    or set(queries) != {'a', 'b_g1', 'b_g2', 'l', 'h', 'instances_including_one'}
                    or any(type(v) is not int or v <= 0 for v in [*shape.values(), *queries.values()])
                    or shape['instances_including_one'] != 3 or queries['instances_including_one'] != 3
                    or queries['a'] != shape['witness_variables'] + 3
                    or queries['b_g1'] != queries['a'] or queries['b_g2'] != queries['a']
                    or queries['l'] != shape['witness_variables']):
                    raise RuntimeError('actual_setup_dimensions_invalid')
                vk = (output / 'setup-01/verification-key.bin').read_bytes()
                if (len(vk) != 328 or vk.hex() != report['vk_hex328'] or digest(vk) != report['vk_sha256']
                    or report['setup_rng'] != 'OsRng' or report['format'] != 'arkworks0.6-bn254-uncompressed'):
                    raise RuntimeError('actual_setup_vk_invalid')
                if (type(report['pk_bytes']) is not int or report['pk_bytes'] <= 0
                    or not isinstance(report['pk_sha256'], str) or len(report['pk_sha256']) != 64
                    or any(c not in '0123456789abcdef' for c in report['pk_sha256'])):
                    raise RuntimeError('actual_setup_pk_identity_invalid')
                if report['build_identity'] != plan['build_identity']:
                    raise RuntimeError('actual_setup_build_invalid')
                (evidence / 'setup-01').mkdir(mode=0o700)
                save_new(evidence / 'setup-01/report.json', raw)
                save_new(evidence / 'setup-01/verification-key.bin', vk)
                ready = {'event': 'ready', 'trial_id': report['trial_id'], 'domain_hex32': report['domain_hex32'],
                    'vk_hex328': report['vk_hex328'], 'vk_sha256': report['vk_sha256'],
                    'pk_bytes': report['pk_bytes'], 'pk_sha256': report['pk_sha256'],
                    'constraint_shape': shape, 'queries': queries,
                    'compiled_build_identity_sha256': report['compiled_build_identity_sha256']}
                save(evidence / 'READY.json', ready)
                events.append(ready)
                print(json.dumps(ready), flush=True)
            elif kind == 'proof-complete':
                allowed = {'event', 'proof_sha256', 'authorization_sha256', 'vk_sha256', 'domain_hex32',
                           'compiled_build_identity_sha256', 'genuine_Groth16_verified'}
                if (ready is None or set(value) != allowed or value['genuine_Groth16_verified'] is not True
                    or value['vk_sha256'] != ready['vk_sha256'] or value['domain_hex32'] != plan['domain_hex32']
                    or value['compiled_build_identity_sha256'] != plan['compiled_build_identity_sha256']
                    or any(not isinstance(value[key], str) or len(value[key]) != 64
                           or any(c not in '0123456789abcdef' for c in value[key])
                           for key in ('proof_sha256', 'authorization_sha256'))):
                    raise RuntimeError('public_proof_event_invalid')
                proofs.append(value)
                events.append(value)
                # No private owner association, witness path/hash, or statement
                # bytes are exported. The trial lane owns exact private outputs.
                print(json.dumps(dict(value, proof_number=len(proofs))), flush=True)
        seen_lines = len(lines)

    try:
        with os.fdopen(os.open(stage / 'raw-unit.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as raw_log:
            child = subprocess.Popen(['systemd-run', '--user', '--wait', '--pipe', '--unit=' + unit,
                '--property=CPUQuota=' + str(plan['cpu_workers'] * 100) + '%',
                '--property=MemoryMax=' + str(plan['memory_max_bytes']), '--property=MemorySwapMax=0',
                '--property=RuntimeMaxSec=10800', '/usr/bin/python3', plan['inside_helper'], plan['inside_selection']],
                stdin=control, stdout=raw_log, stderr=subprocess.STDOUT)
            save(evidence / 'START.json', {'started_utc':started, 'unit':unit,
                'private_inputs_and_raw_logs_retained_outside_git':True})
            print(json.dumps({'event':'session-started', 'unit':unit}), flush=True)
            while child.poll() is None:
                result = subprocess.run(['systemctl', '--user', 'show', unit,
                    '--property=' + ','.join(properties)], capture_output=True, text=True)
                row = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
                row['observed_utc'] = now()
                group = row.get('ControlGroup')
                if group:
                    for name in ('memory.current', 'memory.peak', 'memory.swap.current'):
                        try:
                            row[name] = (Path('/sys/fs/cgroup') / group.lstrip('/') / name).read_text().strip()
                        except OSError:
                            row[name] = None
                rows.append(row)
                observe_events()
                time.sleep(0.5)
            returncode = child.wait()
            observe_events()
    except BaseException:
        error = 'session_runtime_failed'
    finally:
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
        os.close(control)
        if child is not None and child.poll() is None:
            child.wait(timeout=30)
        final = subprocess.run(['systemctl', '--user', 'show', unit,
            '--property=' + ','.join(properties)], capture_output=True, text=True)
        save(evidence / 'telemetry.json', rows)
        save(evidence / 'PUBLIC-EVENTS.json', events)
        save(evidence / 'CLEANUP.json', {'observed_utc':now(), 'unit':unit, 'returncode':returncode,
            'error':error, 'state':dict(line.split('=',1) for line in final.stdout.splitlines() if '=' in line)})
        if (output / 'resources-app.log').exists():
            # Inner argv uses only generic mounted protocol names.
            save_new(evidence / 'resources-app.log', (output / 'resources-app.log').read_bytes())
    result = {'schema':'kpx3-one-fresh-private-setup-session/v1', 'start_utc':started, 'end_utc':now(),
        'returncode':returncode, 'error':error, 'fresh_setup_ready':ready is not None,
        'fresh_setup_count':int(ready is not None), 'genuine_verified_proof_count':len(proofs),
        'expected_proofs':plan['expected_proofs'], 'all_complete':returncode == 0 and error is None
            and ready is not None and len(proofs) == plan['expected_proofs'],
        'old_PK_or_matrix_loaded':False, 'hosted_prover':False,
        'private_witness_or_hash_or_host_path_exported':False,
        'raw_logs_retained_privately':True, 'whole_process_resources_include_idle':True,
        'independent_phase_peaks':False, 'p95_qualified':False}
    save(evidence / 'RESULT.json', result)
    print(json.dumps(result), flush=True)
    if not result['all_complete']:
        raise SystemExit(1)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('{"event":"error","code":"session_controller_failed"}', flush=True)
        raise SystemExit(1)
