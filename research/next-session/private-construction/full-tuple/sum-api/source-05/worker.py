#!/usr/bin/env python3
"""ADR0062 worker: public fixtures, isolated local TCP and separate party roots."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

Q = 6554484396890773809930967563523245729705921265872317281365359162392183254199
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
ROOT = Path('/software')
OUT = Path('/out')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as f:
        json.dump(value, f, sort_keys=True, indent=2); f.write('\n')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(raw):
    need(type(raw) is bytes and len(raw) == 32, 'canonical-scalar-length')
    value = int.from_bytes(raw, 'little')
    need(value < Q, 'canonical-scalar-less-than-q')
    return value


def bubble():
    return ['/usr/bin/bwrap', '--unshare-all', '--share-net', '--die-with-parent',
        '--new-session', '--clearenv', '--ro-bind', '/usr', '/usr',
        '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev',
        '--tmpfs', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC']


def loopback():
    # Bubblewrap already configures this new namespace's loopback. No network
    # administration capability or redundant interface mutation is required.
    interfaces = [line.split(':')[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    need(interfaces == ['lo'], 'isolated-loopback-only-network')
    with socket.socket() as listener:
        listener.settimeout(5);listener.bind(('127.0.0.1',0));listener.listen()
        with socket.create_connection(listener.getsockname(),timeout=5) as client:
            with listener.accept()[0] as server:
                client.sendall(b'PING');need(server.recv(4)==b'PING','isolated-loopback-TCP-read')
                server.sendall(b'PONG');need(client.recv(4)==b'PONG','isolated-loopback-TCP-reply')
    return {'loopback_up': True, 'visible_interfaces': interfaces,
        'host_network_or_home_mounted': False}


def compile_program():
    work = OUT / 'compiler'; work.mkdir()
    (work / 'Compiler').symlink_to(ROOT / 'Compiler', target_is_directory=True)
    (work / 'compile.py').symlink_to(ROOT / 'compile.py')
    (work / 'Programs/Source').mkdir(parents=True)
    (work / 'Programs/Source/kpi_delta.mpc').write_bytes((ROOT / 'kpi_delta.mpc').read_bytes())
    process = subprocess.run(['/usr/bin/python3', '-B', str(work / 'compile.py'),
        '-F', '252', '-P', str(Q), 'kpi_delta'], cwd=work, capture_output=True, env=CLEAN)
    (OUT / 'compiler.stdout').write_bytes(process.stdout)
    (OUT / 'compiler.stderr').write_bytes(process.stderr)
    need(process.returncode == 0, 'compiler-see-retained-stderr')
    rows = []
    for name in ('Schedules', 'Bytecode'):
        for path in sorted((work / 'Programs' / name).rglob('*')):
            if path.is_file():
                rows.append({'path': str(path.relative_to(work / 'Programs')),
                    'bytes': path.stat().st_size, 'sha256': digest(path)})
    need(rows and any(r['path'] == 'Schedules/kpi_delta.sch' for r in rows), 'compiled-schedule-required')
    schedule = (work / 'Programs/Schedules/kpi_delta.sch').read_text()
    need(str(Q) in schedule, 'actual-compiled-schedule-exact-prime')
    save(OUT / 'COMPILED.json', {'schema': 'kpx6-private-sum-compiled/v1',
        'prime_decimal': str(Q), 'source_sha256': digest(ROOT / 'kpi_delta.mpc'), 'files': rows,
        'schedule_sha256': digest(work / 'Programs/Schedules/kpi_delta.sch'),
        'compile_returncode': process.returncode, 'engine_executed': False})


def certificates(case):
    public = case / 'certificates'; public.mkdir()
    private = []
    for party in range(3):
        directory = case / f'party-{party}'; directory.mkdir(mode=0o700)
        key, cert = directory / f'P{party}.key', public / f'P{party}.pem'
        process = subprocess.run(['/usr/bin/openssl', 'req', '-config', '/dev/null', '-newkey', 'rsa:2048',
            '-nodes', '-x509', '-days', '1', '-out', str(cert), '-keyout', str(key),
            '-subj', f'/CN=P{party}'], capture_output=True, env=CLEAN)
        need(process.returncode == 0, 'fresh-public-test-TLS-material')
        key.chmod(0o400); private.append(directory)
    for directory in private:
        for cert in public.iterdir():
            (directory / cert.name).write_bytes(cert.read_bytes())
        process = subprocess.run(['/usr/bin/openssl', 'rehash', str(directory)],
            capture_output=True, env=CLEAN)
        need(process.returncode == 0, 'public-TLS-certificate-hash-links')
    return private


def metadata_programs():
    value = json.loads(Path('/compiled.json').read_bytes())
    need(value['prime_decimal'] == str(Q), 'selected-compiled-prime')
    for row in value['files']:
        relative = Path(row['path'])
        need(not relative.is_absolute() and '..' not in relative.parts, 'compiled-canonical-path')
        path = Path('/programs') / relative
        need(path.is_file() and not path.is_symlink() and path.stat().st_size == row['bytes']
             and digest(path) == row['sha256'], 'selected-actual-compiled-bytes')
    return value


def party_command(private, program_dir, *, calibration=False, calibration_port=None, runtime_prime=Q):
    command = bubble() + ['--ro-bind', str(program_dir), '/work/Programs',
        '--bind', str(private), '/work/Player-Data', '--chdir', '/work']
    if calibration:
        need(type(calibration_port)is int,'explicit-parent-local-calibration-port')
        code = "from pathlib import Path; import json,socket; p=Path('/work/Player-Data'); s=socket.create_connection(('127.0.0.1',"+str(calibration_port)+"),timeout=5);s.sendall(b'PING');assert s.recv(4)==b'PONG';s.close();print(json.dumps({'own_input_files':len(list(p.glob('Input-P*-0'))),'own_TLS_keys':len(list(p.glob('P*.key'))),'no_host_home':not Path('/home/luke').exists(),'no_global_out':not Path('/out').exists(),'no_other_owner_root':not Path('/case').exists(),'actual_parent_child_TCP_roundtrip':True}))"
        return command + ['/usr/bin/python3', '-B', '-c', code]
    return command + ['--ro-bind', str(ROOT / 'mascot-party.x'), '/engine',
        '/engine', '-N', '3', '-I', '-p', private.name.split('-')[-1], '-h', '127.0.0.1',
        '-pn', '17349', '--prime', str(runtime_prime), 'kpi_delta']


def run_case(kind, values, expected, ordinal):
    identity = str(uuid.uuid4()); case = OUT / f'{ordinal:02d}-{kind}-{identity}'; case.mkdir(mode=0o700)
    private = certificates(case)
    programs = []
    gates = []
    for party, directory in enumerate(private):
        value = canonical(values[party].to_bytes(32, 'little'))
        (directory / f'Input-P{party}-0').write_text(str(value) + '\n')
        root = case / f'programs-{party}'; root.mkdir()
        for name in ('Schedules', 'Bytecode'):
            shutil.copytree(Path('/programs') / name, root / name)
        (root / 'Public-Input').mkdir()
        gate = root / 'Public-Input/kpi_delta'; os.mkfifo(gate, 0o600)
        gates.append(os.open(gate, os.O_RDWR | os.O_NONBLOCK)); programs.append(root)
    processes, streams, started = [], [], time.monotonic()
    marker_seen = [False] * 3
    try:
        for party in range(3):
            if kind == 'lost-before-input' and party == 2:
                # A real party process is stopped before engine/input entry.
                command = bubble() + ['/usr/bin/python3', '-B', '-c',
                    'import signal,time; signal.raise_signal(signal.SIGSTOP); time.sleep(3600)']
            else:
                command = party_command(private[party], programs[party],
                    runtime_prime=Q+2 if kind=='wrong-runtime-prime' else Q)
            stdin = (private[party] / f'Input-P{party}-0').open('rb')
            stdout = (case / f'party-{party}.stdout').open('xb')
            stderr = (case / f'party-{party}.stderr').open('xb')
            streams.extend((stdin, stdout, stderr))
            processes.append(subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr, env=CLEAN))
        if kind == 'lost-before-input':
            os.kill(processes[2].pid, signal.SIGKILL)
        reason, released, killed = None, False, kind == 'lost-before-input'
        while True:
            for party in range(3):
                marker_seen[party] = b'KPX6_INPUTS_COMPLETE' in (case / f'party-{party}.stdout').read_bytes()
            if all(marker_seen) and not released:
                if kind == 'lost-after-input':
                    os.kill(processes[2].pid, signal.SIGKILL)
                    need(processes[2].wait() != 0, 'declared-lost-party-reaped-before-release')
                    killed = True
                for party, gate in enumerate(gates):
                    if not (kind == 'lost-after-input' and party == 2):
                        os.write(gate, b'1\n')
                released = True
            statuses = [p.poll() for p in processes]
            if all(s is not None for s in statuses):
                break
            if kind != 'wrong-runtime-prime' and any(s is not None and s != 0 for s in statuses):
                reason = 'peer-process-failed-or-declared-lost'; break
            if time.monotonic() - started > 900:
                reason = 'operational-wait-incomplete-not-protocol-or-privacy-result'; break
            time.sleep(0.05)
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
        statuses = [process.wait() for process in processes]
        for stream in streams: stream.close()
        for gate in gates: os.close(gate)
    sums = []
    for party in range(3):
        found = re.findall(rb'KPX6_SUM ([0-9]+)', (case / f'party-{party}.stdout').read_bytes())
        sums.append([int(x) for x in found])
    complete = kind == 'normal' and released and all(s == 0 for s in statuses) and sums == [[expected]] * 3
    if kind == 'normal': need(complete, 'normal-case-incomplete-see-party-logs')
    if kind != 'normal':
        need(not any(sums), 'incomplete-case-must-not-export-sum')
        if kind == 'lost-after-input': need(all(marker_seen) and killed, 'actual-after-input-marker-required')
        if kind == 'wrong-runtime-prime':
            need(all(s != 0 for s in statuses) and all(
                b'Different prime for compilation and computation.' in
                (case / f'party-{party}.stderr').read_bytes() for party in range(3)),
                'actual-engine-runtime-prime-mismatch-refusal-required')
    report = {'schema': 'kpx6-existing-engine-sum-case/v1', 'identity': identity, 'kind': kind,
        'classification': 'PUBLIC_SYNTHETIC_FUNCTIONAL_COMPONENT_ONLY',
        'status': 'COMPLETE' if complete else 'INCOMPLETE', 'expected_decimal': str(expected),
        'sum_decimal': str(sums[0][0]) if complete else None,
        'all_three_input_instruction_markers_observed': all(marker_seen),
        'public_gate_released': released, 'party_returncodes': statuses,
        'runtime_prime_decimal': str(Q+2 if kind=='wrong-runtime-prime' else Q),
        'before_input_loss_location': 'ISOLATED_PARTY_WRAPPER_BEFORE_ENGINE_ENTRY'
             if kind=='lost-before-input' else None,
        'wall_seconds': time.monotonic() - started, 'cleanup_all_owned_children_reaped': True,
        'operational_reason': reason, 'actual_malicious_wire_injection': False,
        'financial_authorization_or_KAS_interface': False}
    save(case / 'RESULTS.json', report)
    return report


def calibrate():
    loopback(); case = OUT / 'calibration'; case.mkdir(); private = certificates(case)
    results = []
    for party, directory in enumerate(private):
        (directory / f'Input-P{party}-0').write_text('PUBLIC-SYNTHETIC-CALIBRATION\n')
        programs = case / f'empty-programs-{party}'; programs.mkdir()
        with socket.socket() as listener:
            listener.settimeout(10);listener.bind(('127.0.0.1',0));listener.listen()
            process = subprocess.Popen(party_command(directory,programs,calibration=True,
                calibration_port=listener.getsockname()[1]),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=CLEAN)
            try:
                with listener.accept()[0]as server:
                    need(server.recv(4)==b'PING','actual-inner-party-TCP-request');server.sendall(b'PONG')
                stdout,stderr=process.communicate()
            finally:
                if process.poll()is None:process.kill();process.wait()
        need(process.returncode == 0, 'public-namespace-calibration-failed')
        result = json.loads(stdout)
        need(result == {'own_input_files': 1, 'own_TLS_keys': 1, 'no_host_home': True,
            'no_global_out': True, 'no_other_owner_root': True, 'actual_parent_child_TCP_roundtrip': True},
            'separate-party-filesystem-capability-calibration')
        results.append(result)
    rejected = []
    for raw in (Q.to_bytes(32, 'little'), (Q + 1).to_bytes(32, 'little'), bytes(31)):
        try: canonical(raw)
        except ValueError: rejected.append(True)
        else: raise AssertionError('noncanonical-boundary-accepted')
    save(OUT / 'CALIBRATION.json', {'passed': True, 'parties': results,
        'canonical_boundary_negative_count': len(rejected),
        'downloaded_compiler_engine_or_curve_program_executed': False})


def main():
    op = sys.argv[1]
    if op == 'calibrate': calibrate()
    elif op == 'compile': compile_program()
    elif op == 'run':
        loopback(); compiled = metadata_programs()
        results = []
        for ordinal, values in enumerate(((Q-1,Q-2,6), (0,0,0), (Q-1,1,0), (5,11,17))):
            results.append(run_case('normal', values, sum(values) % Q, ordinal))
        for ordinal, kind in enumerate(('lost-before-input','lost-after-input'), start=4):
            results.append(run_case(kind, (Q-1,Q-2,6), 3, ordinal))
        results.append(run_case('wrong-runtime-prime', (Q-1,Q-2,6), 3, 6))
        save(OUT / 'RESULTS.json', {'schema':'kpx6-existing-engine-sum-results/v1',
            'compiled': compiled, 'cases': results, 'correct_complete_count': 4,
            'declared_party_loss_incomplete_count': 2, 'actual_engine_wrong_prime_refusal_count': 1,
            'privacy_qualified': False,
            'adaptive_corruption_or_malicious_share_injection_tested': False})
    elif op == 'build-consumer':
        environment = dict(CLEAN, PATH='/toolchain/bin:/usr/bin:/bin', CARGO_HOME='/cargo',
            CARGO_TARGET_DIR='/out/target', CARGO_NET_OFFLINE='true',
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER='/usr/bin/gcc')
        process = subprocess.run(['/toolchain/bin/cargo','build','--release','--offline',
            '--frozen','--jobs','4','--manifest-path','/software/Cargo.toml'],
            capture_output=True,env=environment)
        (OUT/'build.stdout').write_bytes(process.stdout);(OUT/'build.stderr').write_bytes(process.stderr)
        need(process.returncode==0,'consumer-build-see-retained-stderr')
        binary = OUT/'target/release/private-sum-api-consumer'
        save(OUT/'BUILT.json',{'schema':'kpx6-private-sum-curve-consumer-build/v1',
            'binary_sha256':digest(binary),'binary_bytes':binary.stat().st_size,
            'Cargo_lock_sha256':digest(ROOT/'Cargo.lock'),'consumer_executed':False})
    elif op == 'consumer':
        results = json.loads(Path('/sum-results.json').read_bytes())
        primary = results['cases'][0]
        need(primary['kind']=='normal' and primary['status']=='COMPLETE'
             and primary['party_returncodes']==[0,0,0], 'actual-complete-primary-MPC-result')
        scalar = int(primary['sum_decimal'])
        need(0<=scalar<Q,'actual-engine-aggregate-canonical-range')
        request = {'schema':'kpx6-public-sum-binding-consumer/v1',
            'scalar_hex32':scalar.to_bytes(32,'little').hex()}
        encoded=(json.dumps(request,sort_keys=True,separators=(',',':'))+'\n').encode()
        (OUT/'request.json').write_bytes(encoded)
        process=subprocess.run(['/consumer'],input=encoded,capture_output=True,env=CLEAN)
        (OUT/'consumer.stdout').write_bytes(process.stdout);(OUT/'consumer.stderr').write_bytes(process.stderr)
        need(process.returncode==0,'actual-aggregate-curve-consumer-see-retained-stderr')
        verified=json.loads(process.stdout)
        need(verified['actual_received_scalar_hex32']==request['scalar_hex32']
             and all(verified[k] is True for k in ('correct_actual_delta_verifies',
               'wrong_delta_rejected','wrong_digest_rejected','wrong_fee_rejected')),
             'actual-result-and-existing-curve-verifier-join')
        save(OUT/'RESULTS.json',{'schema':'kpx6-actual-private-sum-curve-join/v1',
            'source_sum_results_sha256':digest(Path('/sum-results.json')),
            'actual_primary_identity':primary['identity'],'request_sha256':hashlib.sha256(encoded).hexdigest(),
            'consumer':verified,'native_or_Sapling_transaction_validated':False})
    else: raise ValueError('fixed-op-required')


if __name__ == '__main__':
    main()
