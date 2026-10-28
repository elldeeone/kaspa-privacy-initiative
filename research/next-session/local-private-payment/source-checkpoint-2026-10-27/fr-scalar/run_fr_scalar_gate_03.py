#!/usr/bin/env python3
"""Fresh public-fixture Fr gate using frozen stock compiler/MASCOT plumbing.

Source proposal only until Root reviews the complete closure and releases
resources. This code never opens, hashes or logs a TLS private-key body, wallet,
Original, real witness, proving key or existing MPC state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import time
import traceback
import types
import uuid

HERE = Path(__file__).resolve().parent
REPO = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
COMMON_ROOT = Path('/var/tmp/kpi-sender-private-lifecycle-01/assets/shared-mpc-software-01')
SOFTWARE = COMMON_ROOT / 'software'
TRANSPORT_PARENT = Path('/var/tmp/kpi-owner-private-lifecycle-01/private')
COMMON_SHA = '7aa260678e118f15d23c707feb906a9ed75695fd36af06cb1ba5b72bfc6a237e'
INSTALLATION_SHA = '5d0def4ae617f6365fccb5f243922088faaf7a6148aa0938c3a3f9520c4ff594'
ENGINE_SHA = '47d9ae6f52003825946a4abb6cf9dc62f62a4e2fc2c19a5e3ee6f59a6889b07e'
BACKEND_SHA = '5b82fceca4b382b58e41a0499518736d2597587aecb4dfe5a15444991ef3f451'
CODEC_SHA = '6b6ef7f294e333f458cffc4c2d5ad18fc59ab084c04b948deecbf2abcac35fa3'
IMAGE = 'sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea'
FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def plain_directory(path):
    need(path.is_absolute() and '..' not in path.parts and
         all(not parent.is_symlink() for parent in (path, *path.parents)), 'canonical-directory')


def module_from_admitted(name, path, raw):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def selected_sources(args, read):
    raw = read(str(args.freeze), args.freeze_sha256)
    selection = json.loads(raw)
    need(selection['schema'] == 'kpxa-public-fr-scalar-source-proposal/v1' and
         selection['field_decimal'] == str(FR) and selection['public_synthetic_inputs_only'] is True,
         'selected-scalar-source-profile')
    rows = selection['files']
    need(type(rows) is list and len({row['path'] for row in rows}) == len(rows), 'unique-selected-files')
    files = {}
    required = {'kpi_fr_scalar_gate.mpc', 'fixture_preflight.py', 'PUBLIC-FIXTURE-01.json',
                'fr_scalar_party_03.py', 'run_fr_scalar_gate_03.py'}
    for row in rows:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'closed-selected-file')
        path = Path(row['path'])
        need(path.parent == HERE and re.fullmatch('[0-9a-f]{64}', row['sha256']) and
             type(row['bytes']) is int and row['bytes'] >= 0, 'fixed-source-package-file')
        if path.name in required:
            body = read(str(path), row['sha256'])
            need(len(body) == row['bytes'], 'selected-source-length')
            files[path.name] = (row, body)
    need(set(files) == required and
         files['run_fr_scalar_gate_03.py'][0]['sha256'] == args.source_sha256, 'complete-source-and-self-selection')
    return selection, files


def stock_sources(read):
    common = json.loads(read(str(COMMON_ROOT / 'COMMON.json'), COMMON_SHA))
    inventory = json.loads(read(str(COMMON_ROOT / 'INSTALLATION.json'), INSTALLATION_SHA))
    need(common['schema'] == 'kpx9-mascot-readonly-public-software/v1' and
         common['image'] == IMAGE and common['engine_sha256'] == ENGINE_SHA and
         common['installation_sha256'] == INSTALLATION_SHA, 'exact-stock-vendor-origin')
    origin = {row['path']: row for row in inventory['files']}
    selected = []
    for row in common['files']:
        relative = row['path']
        need(relative.startswith('software/'), 'closed-common-root')
        vendor = relative[len('software/'):]
        if vendor.startswith(('Compiler/', 'compiler-dependency/')) or vendor in ('compile.py', 'mascot-party.x'):
            need(vendor in origin and row['sha256'] == origin[vendor]['sha256'] and
                 row['bytes'] == origin[vendor]['bytes'], 'vendor-installation-join')
            path = COMMON_ROOT / relative
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o222,
                 'readonly-single-link-vendor-file')
            body = read(str(path), row['sha256'])
            need(len(body) == row['bytes'], 'exact-vendor-file-size')
            selected.append(row)
    expected = {row['path'] for row in inventory['files']
                if row['path'].startswith(('Compiler/', 'compiler-dependency/')) or
                row['path'] in ('compile.py', 'mascot-party.x')}
    need({row['path'][len('software/'):] for row in selected} == expected and
         {'compile.py', 'mascot-party.x'} <= expected, 'complete-stock-compiler-and-engine-closure')
    return selected


def public_generated_programs(root, read):
    rows = []
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        need(not stat.S_ISLNK(info.st_mode), 'generated-program-symlink')
        if stat.S_ISREG(info.st_mode):
            need(info.st_nlink == 1, 'generated-program-single-link')
            path.chmod(0o400)
            body = read(str(path))
            rows.append({'path':str(path), 'bytes':len(body), 'sha256':hashlib.sha256(body).hexdigest()})
        else:
            need(stat.S_ISDIR(info.st_mode), 'generated-program-file-type')
    need(any(row['path'].endswith('.bc') and row['bytes'] > 0 for row in rows), 'nonempty-new-bytecode')
    return rows


def execute(args):
    need(args.execute, 'explicit-runtime-release-required')
    plain_directory(args.output)
    need(args.output.parent == HERE and not args.output.exists(), 'fresh-owned-direct-child-output')
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    read(str(Path(__file__)), args.source_sha256)
    selection, files = selected_sources(args, read)
    vendor = stock_sources(read)
    fixture = module_from_admitted('selected_fr_fixture', HERE / 'fixture_preflight.py',
                                  files['fixture_preflight.py'][1])
    streams = fixture.validate_fixture(files['PUBLIC-FIXTURE-01.json'][1])
    # Reuse only the exact reviewed process/namespace plumbing. Old Q session,
    # phase, preparation, party and financial functions are never called.
    admission = REPO / 'poc/sender-private-lifecycle/admission'
    module_from_admitted('codec', admission / 'codec.py', read(str(admission / 'codec.py'), CODEC_SHA))
    legacy = module_from_admitted('selected_stock_runtime_plumbing', admission / 'backend.py',
                                 read(str(admission / 'backend.py'), BACKEND_SHA))
    need(legacy.IMAGE == IMAGE, 'plumbing-image-join')
    run_id = uuid.uuid4().hex
    args.output.mkdir(mode=0o700)
    output = args.output
    save(output / 'RUN-ID.json', encoded({'run_id':run_id, 'field_decimal':str(FR)}))
    save(output / 'SELECTED-SOURCES.json', encoded({'proposal_freeze_sha256':args.freeze_sha256,
         'files':[row for row, _ in files.values()], 'stock_vendor':vendor,
         'plumbing_backend_sha256':BACKEND_SHA, 'plumbing_codec_sha256':CODEC_SHA,
         'old_Q_profile_or_state_reused':False}))
    programs = output / 'Programs'
    (programs / 'Source').mkdir(parents=True)
    save(programs / 'Source/kpi_fr_scalar_gate.mpc', files['kpi_fr_scalar_gate.mpc'][1])
    compile_work = output / 'compiler'
    compile_work.mkdir()
    command = legacy.bubble() + ['--ro-bind',str(SOFTWARE),'/software', '--bind',str(compile_work),'/work',
        '--bind',str(programs),'/work/Programs', '--chdir','/work',
        '--setenv','PYTHONPATH','/software/compiler-dependency', '/usr/bin/python3','-B',
        '/software/compile.py','-F','252','-P',str(FR),'kpi_fr_scalar_gate',run_id]
    save(output / 'COMPILE-ARGV.json', encoded(command))
    started = time.monotonic()
    with (output / 'compiler.stdout').open('xb') as out, (output / 'compiler.stderr').open('xb') as err:
        compiled = subprocess.run(command, stdout=out, stderr=err, stdin=subprocess.DEVNULL, env=CLEAN)
    compile_ms = int((time.monotonic() - started) * 1000)
    if compiled.returncode != 0:
        save(output / 'RESULT.json', encoded({'schema':'kpxa-public-fr-scalar-gate/v1',
            'status':'INCOMPLETE', 'run_id':run_id, 'field_decimal':str(FR),
            'failed_stage':'public-compiler', 'compile_exit':compiled.returncode,
            'compile_milliseconds':compile_ms, 'actual_Original_or_engine_executed':False}))
        raise ValueError('public-compiler-failed')
    schedule = programs / 'Schedules' / ('kpi_fr_scalar_gate-' + run_id + '.sch')
    header = read(str(schedule)).decode().splitlines()
    need([line for line in header if line.startswith(('p:', 'R:', 'lgp:'))] == ['p:' + str(FR)],
         'exact-new-Fr-schedule-field-header')
    generated = public_generated_programs(programs, read)
    save(output / 'GENERATED-PROGRAMS.json', encoded(generated))
    input_rows = []
    for party, raw in enumerate(streams):
        path = output / ('PUBLIC-INPUT-P%d.txt' % party)
        save(path, raw)
        body = read(str(path))
        info = path.lstat()
        input_rows.append((path, info, hashlib.sha256(body).hexdigest()))
    plain_directory(TRANSPORT_PARENT)
    need(TRANSPORT_PARENT.is_dir(), 'reserved-guarded-private-parent')
    transport = TRANSPORT_PARENT / ('fr-scalar-transport-' + run_id)
    transport.mkdir(mode=0o700)
    certificates = output / 'public-certificates'
    certificates.mkdir()
    work = []
    for party in range(3):
        directory = transport / ('party-%d' % party)
        directory.mkdir(mode=0o700)
        cert, key = certificates / ('P%d.pem' % party), directory / ('P%d.key' % party)
        completed = subprocess.run(['/usr/bin/openssl','req','-config','/dev/null','-newkey','rsa:2048',
            '-nodes','-x509','-days','1','-out',str(cert),'-keyout',str(key),'-subj','/CN=P%d' % party],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=CLEAN)
        need(completed.returncode == 0, 'fresh-transport-certificate-setup')
        key.chmod(0o400)
        info = key.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size > 0, 'fresh-transport-key-metadata')
        work.append(directory)
    for directory in work:
        for party in range(3):
            cert = certificates / ('P%d.pem' % party)
            save(directory / cert.name, read(str(cert)))
        completed = subprocess.run(['/usr/bin/openssl','rehash',str(directory)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=CLEAN)
        need(completed.returncode == 0, 'fresh-peer-certificate-rehash')
    token = str(uuid.uuid4())
    docker = legacy.Docker(output, token)
    need(json.loads(docker.cli('image','inspect',IMAGE,'--format','{{json .Id}}').stdout) == IMAGE,
         'existing-selected-image-no-pull')
    names = ['kpi-fr-' + run_id + '-anchor'] + ['kpi-fr-' + run_id + '-p%d' % party for party in range(3)]
    processes, opened, results = [], [], []
    result = {'schema':'kpxa-public-fr-scalar-gate/v1', 'status':'INCOMPLETE', 'run_id':run_id,
        'field_decimal':str(FR), 'source_freeze_sha256':args.freeze_sha256,
        'compile_exit':compiled.returncode, 'compile_milliseconds':compile_ms,
        'full_Groth16_or_active_privacy_or_financial_qualification':False,
        'private_transport_and_engine_logs_retained':True, 'TLS_key_bodies_read_hashed_or_logged_by_controller':False}
    stage = 'isolated-anchor'
    last_sample, sample_attempts, telemetry_failures = 0, 0, []
    started = time.monotonic()
    try:
        anchor = docker.base(names[0], 'none', anchor=True) + ['--detach','--entrypoint','/usr/bin/env',
            IMAGE,'-i','PATH=/usr/bin:/bin','/usr/bin/sleep','infinity']
        need(subprocess.run(anchor, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env=docker.env).returncode == 0, 'isolated-loopback-anchor-start')
        stage = 'three-scalar-workers'
        for party, (path, before, digest) in enumerate(input_rows):
            now = path.lstat()
            need((now.st_dev,now.st_ino,now.st_size,now.st_mtime_ns,now.st_ctime_ns) ==
                 (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns),
                 'public-input-handle-changed')
            command = docker.base(names[party+1], 'container:' + names[0]) + [
                '--mount',f'type=bind,src={path},dst=/public-input.txt,readonly',
                '--mount',f'type=bind,src={work[party]},dst=/work/Player-Data',
                '--mount',f'type=bind,src={work[party] / ("P%d.key" % party)},dst=/work/Player-Data/P{party}.key,readonly',
                '--mount',f'type=bind,src={programs},dst=/work/Programs,readonly',
                '--mount',f'type=bind,src={SOFTWARE / "mascot-party.x"},dst=/engine,readonly',
                '--mount',f'type=bind,src={HERE / "fr_scalar_party_03.py"},dst=/app/fr_scalar_party.py,readonly',
                '--workdir','/work','--entrypoint','/usr/bin/env',IMAGE,'-i',
                'PATH=/usr/bin:/bin','LANG=C.UTF-8','TZ=UTC','/usr/bin/python3','-B',
                '/app/fr_scalar_party.py',str(party),run_id,digest,str(before.st_dev),str(before.st_ino)]
            save(output / ('PARTY-%d-ARGV.json' % party), encoded(command))
            out = (output / ('PUBLIC-PARTY-%d.json' % party)).open('xb')
            err = (work[party] / 'worker-status.stderr').open('xb')
            opened.extend((out,err))
            processes.append(subprocess.Popen(command, stdout=out, stderr=err,
                stdin=subprocess.DEVNULL, env=docker.env))
        while any(process.poll() is None for process in processes):
            need(all(process.poll() in (None,0) for process in processes), 'party-failed-no-subset')
            if time.monotonic() - last_sample >= 1:
                sample_attempts += 1
                try:
                    docker.sample()
                except Exception as telemetry_error:
                    # Observation failures never decide arithmetic acceptance.
                    telemetry_failures.append({'error_type':type(telemetry_error).__name__})
                last_sample = time.monotonic()
            time.sleep(0.1)
        need([process.returncode for process in processes] == [0,0,0], 'all-three-party-exits')
        for stream in opened:
            stream.close()
        stage = 'complete-public-results'
        expected_fields = {'schema','status','party','run_id','field_decimal','engine_argv','engine_exit',
                           'residuals','insecure_warning_seen','elapsed_milliseconds'}
        for party in range(3):
            value = json.loads(read(str(output / ('PUBLIC-PARTY-%d.json' % party))))
            expected_argv = ['/engine','-N','3','-I','-p',str(party),'-h','127.0.0.1','-pn','17349',
                '--prime',str(FR),'--batch-size','1024','kpi_fr_scalar_gate-' + run_id]
            need(type(value) is dict and set(value) == expected_fields and
                 value['schema'] == 'kpxa-public-fr-scalar-party/v1' and value['status'] == 'PASS' and
                 type(value['party']) is int and value['party'] == party and value['run_id'] == run_id and
                 value['field_decimal'] == str(FR) and value['engine_argv'] == expected_argv and
                 type(value['engine_exit']) is int and value['engine_exit'] == 0 and
                 type(value['residuals']) is list and len(value['residuals']) == 28 and
                 all(type(item) is int and item == 0 for item in value['residuals']) and
                 value['insecure_warning_seen'] is False and
                 type(value['elapsed_milliseconds']) is int and value['elapsed_milliseconds'] >= 0,
                 'exact-complete-party-projection')
            results.append(value)
        need(results[0]['residuals'] == results[1]['residuals'] == results[2]['residuals'],
             'all-three-residual-vector-agreement')
        result.update(status='PASS', party_exits=[0,0,0], parties=results,
                      expected_residuals_per_party=28, actual_original_or_real_witness_used=False)
    except Exception as error:
        result.update(failed_stage=stage, error_type=type(error).__name__)
        raise
    finally:
        for stream in opened:
            if not stream.closed:
                stream.close()
        try:
            docker.cleanup()
            for process in processes:
                process.wait()
            result['all_owned_containers_removed'] = True
        except Exception as cleanup_error:
            result.update(status='INCOMPLETE', all_owned_containers_removed=False,
                          cleanup_error_type=type(cleanup_error).__name__)
            raise
        finally:
            result['telemetry'] = {'sample_attempts':sample_attempts,
                'sample_records':len(docker.samples), 'failures':telemetry_failures,
                'absent':not bool(docker.samples), 'acceptance_depends_on_telemetry':False,
                'complete_lifetime_peak_or_simultaneous_host_peak_claimed':False}
            result['worker_wrapper_exits'] = [process.poll() for process in processes]
            result['runtime_milliseconds'] = int((time.monotonic()-started)*1000)
            save(output / 'RESULT.json', encoded(result))
    return {'status':result['status'], 'result_path':str(output / 'RESULT.json'), 'run_id':run_id,
            'scope':'PUBLIC_SYNTHETIC_SCALAR_CORRECTNESS_ONLY'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze',type=Path,required=True)
    parser.add_argument('--freeze-sha256',required=True)
    parser.add_argument('--source-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--execute',action='store_true')
    args = parser.parse_args()
    for digest in (args.freeze_sha256,args.source_sha256):
        need(re.fullmatch('[0-9a-f]{64}',digest), 'canonical-source-selection-sha256')
    try:
        result = execute(args)
    except Exception as error:
        if args.output.parent == HERE and args.output.is_dir() and not (args.output / 'RESULT.json').exists():
            save(args.output / 'RESULT.json', encoded({'schema':'kpxa-public-fr-scalar-gate/v1',
                'status':'INCOMPLETE', 'error_type':type(error).__name__,
                'failed_stage':'source-admission-or-preparation',
                'public_source_frames':[{'file':Path(frame.filename).name,'line':frame.lineno,
                                         'function':frame.name}
                    for frame in traceback.extract_tb(error.__traceback__)
                    if Path(frame.filename).name in ('run_fr_scalar_gate_03.py','fixture_preflight.py','backend.py')]}))
        raise
    print(encoded(result).decode().strip())


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('FR scalar gate incomplete; inspect the selected public result record.')
