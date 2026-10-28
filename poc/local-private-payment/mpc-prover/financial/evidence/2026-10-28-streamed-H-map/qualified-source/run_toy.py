#!/usr/bin/env python3
"""One fresh, isolated public-fixture MASCOT full-proof attempt.

The controller reads only selected public source/model/binaries/certificates and
fixed public result sidecars. It never opens or hashes TLS private-key bodies,
party stdout/stderr, preprocessing state, or candidate proof files. All such
files are retained locally. Each invocation creates a new identity.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def public_fields(model):
    names = {'source', 'pk_sha256', 'vk_sha256'}
    found = {}
    for line in model.read_text().splitlines():
        words = line.split()
        if words and words[0] in names:
            if len(words) != 2 or words[0] in found:
                raise RuntimeError('invalid selected public model metadata')
            found[words[0]] = words[1]
    if set(found) != names:
        raise RuntimeError('incomplete selected public model metadata')
    return found


def port_block():
    for _ in range(1000):
        base = 20000 + secrets.randbelow(30000)
        reserved = []
        try:
            for offset in range(3):
                channel = socket.socket()
                reserved.append(channel)
                channel.bind(('127.0.0.1', base + offset))
            return base
        except OSError:
            pass
        finally:
            for channel in reserved:
                channel.close()
    raise RuntimeError('no free local port block')


def selected_resources(run_id):
    entries = Path('/proc/self/cgroup').read_text().splitlines()
    unified = [line.split(':', 2)[2] for line in entries if line.startswith('0::')]
    if len(unified) != 1 or f'kpi-mascot-toy-{run_id}.scope' not in unified[0]:
        raise RuntimeError('selected shared resource scope is absent')
    scope = Path('/sys/fs/cgroup') / unified[0].lstrip('/')
    memory = (scope / 'memory.max').read_text().strip()
    cpu = (scope / 'cpu.max').read_text().strip()
    quota, period = cpu.split()
    if memory != str(6 * 1024**3) or quota == 'max' or int(quota) > 4 * int(period):
        raise RuntimeError('shared resource scope does not match selected window')
    return {'memory_max_bytes': int(memory), 'cpu_max': cpu}


class Attempt:
    def __init__(self, args):
        self.args = args
        self.source = Path(__file__).resolve().parent
        self.root = args.output_parent.resolve() / args.run_id
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.private = self.root / 'private-controller'
        self.private.mkdir(mode=0o700)
        self.public = self.root / 'public'
        self.public.mkdir(mode=0o700)
        self.processes = {}
        self.streams = []
        self.commands = []
        self.stage_paths = {}

    def command(self, name, argv, *, capture_public=False):
        # Key generation and tool diagnostics remain private and unread.
        stdout_path = self.private / (name + '.stdout')
        stderr_path = self.private / (name + '.stderr')
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
            result = subprocess.run(argv, stdout=subprocess.PIPE if capture_public else stdout,
                                    stderr=stderr, check=False)
        self.commands.append({'name': name, 'argv': argv, 'exit': result.returncode})
        if result.returncode:
            raise RuntimeError('selected command refused: ' + name)
        return result.stdout if capture_public else None

    def certificates(self):
        keys = self.root / 'private-tls-keys'
        keys.mkdir(mode=0o700)
        certs = self.public / 'certificates'
        certs.mkdir(mode=0o700)
        self.command('ca', ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(keys / 'ca.key'), '-out', str(certs / 'ca.pem'),
            '-days', '1', '-subj', '/CN=KPI-MASCOT-TOY-' + self.args.run_id[:24]])
        pins = {}
        for role in ['P0', 'P1', 'P2', 'C0', 'C1']:
            extension = certs / (role + '.ext')
            extension.write_text('basicConstraints=critical,CA:FALSE\n'
                'keyUsage=critical,digitalSignature,keyEncipherment\n'
                'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:' + role + '\n')
            self.command(role + '-csr', ['openssl', 'req', '-new', '-newkey', 'rsa:2048',
                '-nodes', '-keyout', str(keys / (role + '.key')),
                '-out', str(certs / (role + '.csr')), '-subj', '/CN=' + role])
            self.command(role + '-certificate', ['openssl', 'x509', '-req',
                '-in', str(certs / (role + '.csr')), '-CA', str(certs / 'ca.pem'),
                '-CAkey', str(keys / 'ca.key'), '-CAcreateserial', '-days', '1',
                '-out', str(certs / (role + '.pem')), '-extfile', str(extension)])
            der = self.command(role + '-public-DER', ['openssl', 'x509', '-in',
                str(certs / (role + '.pem')), '-outform', 'DER'], capture_public=True)
            pins[role] = hashlib.sha256(der).hexdigest()
        if len(set(pins.values())) != 5:
            raise RuntimeError('distinct selected role certificates required')
        return keys, certs, pins

    def freeze(self):
        args = self.args
        if digest(args.model) != args.expected_model_sha256:
            raise RuntimeError('unselected public model')
        if digest(args.verifier) != args.expected_verifier_sha256:
            raise RuntimeError('unselected independent verifier')
        build = json.loads((args.binary.parent / 'BUILD-RESULT.json').read_text())
        if not build['success']:
            raise RuntimeError('selected C++ build did not pass')
        for name, expected in build['source_sha256'].items():
            if digest(self.source / name) != expected:
                raise RuntimeError('selected C++ source no longer matches build')
        for name, path in [('mpc-fullproof', args.binary), ('owner-client', args.owner_client)]:
            records = [r for r in build['link'] if r['binary'] == name]
            if len(records) != 1 or records[0]['sha256'] != digest(path):
                raise RuntimeError('selected executable no longer matches build')
        for artifact in build['vendor_artifacts']:
            if digest(Path(artifact['path'])) != artifact['sha256']:
                raise RuntimeError('selected vendor artifact no longer matches build')
        source_files = [self.source / name for name in build['source_sha256']]
        source_files += [Path(__file__).resolve(), self.source / 'public-model/Cargo.toml',
                         self.source / 'public-model/Cargo.lock', self.source / 'public-model/src/main.rs']
        records = [{'path': str(p), 'sha256': digest(p), 'bytes': p.stat().st_size}
                   for p in source_files]
        freeze = {'schema': 'kpi-mascot-fullproof-attempt-freeze/v1',
            'run_id': args.run_id, 'control': args.control,
            'model_sha256': args.expected_model_sha256,
            'verifier_sha256': args.expected_verifier_sha256,
            'binary_sha256': digest(args.binary), 'owner_client_sha256': digest(args.owner_client),
            'vendor_artifacts': build['vendor_artifacts'],
            'public_sources': records, 'resources': selected_resources(args.run_id),
            'fixtures': {'x': 3, 'y': 5, 'public_t': 128},
            'expected': 'verified-proof' if args.control == 'positive' else 'refusal-before-proof-release',
            'private_keys_or_raw_diagnostics_read_or_hashed': False,
            'scope': 'public-fixture same-host functional proof; no payment/privacy/native/fee claim'}
        write_json(self.public / 'SOURCE-AND-CONTROL-FREEZE.json', freeze)
        return freeze

    def preflight_controls(self):
        original = self.args.model.read_text()
        cases = [('positive', original, True, None),
            ('wrong-model-or-source-pin', original.replace('source ', 'source ', 1), False, '0' * 64),
            ('wrong-field', original.replace('field 21888242871839275222246405745257275088548364400416034343698204186575808495617',
                'field 21888242871839275222246405745257275088548364400416034343698204186575808495616', 1), False, None),
            ('wrong-curve', original.replace('curve BN254', 'curve BLS12_381', 1), False, None),
            ('wrong-arity', original.replace('num_private 3', 'num_private 2', 1), False, None)]
        lines = original.splitlines()
        position = next(i for i, line in enumerate(lines) if line.startswith('alpha_g1 '))
        lines[position] = 'alpha_g1 g1 0 1 1'
        cases.append(('off-curve-point', '\n'.join(lines) + '\n', False, None))
        results = []
        for name, body, expected, selected in cases:
            model = self.public / ('preflight-' + name + '.txt')
            model.write_text(body)
            expected_sha = selected or hashlib.sha256(body.encode()).hexdigest()
            stdout = self.private / ('preflight-' + name + '.stdout')
            stderr = self.private / ('preflight-' + name + '.stderr')
            with stdout.open('xb') as out, stderr.open('xb') as err:
                result = subprocess.run([str(self.args.binary), 'preflight', str(model), expected_sha],
                    stdout=out, stderr=err)
            passed = result.returncode == (0 if expected else 1)
            results.append({'case': name, 'expected_accepted': expected,
                            'exit': result.returncode, 'passed': passed})
            if not passed:
                write_json(self.public / 'PREFLIGHT-CONTROLS.json', results)
                raise RuntimeError('preflight control mismatch: ' + name)
        write_json(self.public / 'PREFLIGHT-CONTROLS.json', results)

    def contracts(self, pins, freeze):
        fields = public_fields(self.args.model)
        cohort = hashlib.sha256(json.dumps({'run': self.args.run_id, 'certificates': pins,
            'model': self.args.expected_model_sha256, 'source_freeze': freeze,
            'control': self.args.control}, sort_keys=True).encode()).hexdigest()
        contracts = []
        for owner in range(2):
            body = ('KPI_OWNER_CONTRACT_V1\nrun_nonce ' + self.args.run_id +
                '\nmodel ' + self.args.expected_model_sha256 + '\nsource ' + fields['source'] +
                '\npk ' + fields['pk_sha256'] + '\nvk ' + fields['vk_sha256'] +
                '\ncohort ' + cohort + '\nowner_id ' + str(owner) + '\ninput_count 1\n')
            for party in range(3):
                body += 'server_certificate_' + str(party) + ' ' + pins['P' + str(party)] + '\n'
            body += 'owner_certificate ' + pins['C' + str(owner)] + '\nEND\n'
            path = self.public / ('owner-' + str(owner) + '.contract')
            path.write_text(body)
            contracts.append(path)
        return contracts

    def preinput_contract_controls(self, contracts):
        originals = [p.read_text() for p in contracts]
        source = public_fields(self.args.model)['source']
        lines = originals[0].splitlines()
        server0 = next(line.split()[1] for line in lines if line.startswith('server_certificate_0 '))
        server1 = next(line.split()[1] for line in lines if line.startswith('server_certificate_1 '))
        owner0 = next(line.split()[1] for line in lines if line.startswith('owner_certificate '))
        cases = [
            ('duplicate-server-certificate', 0, originals[0].replace('server_certificate_1 ' + server1,
                'server_certificate_1 ' + server0)),
            ('owner-server-certificate-overlap', 0, originals[0].replace('owner_certificate ' + owner0,
                'owner_certificate ' + server0)),
            ('wrong-source', 0, originals[0].replace('source ' + source, 'source ' + '0' * 64)),
            ('wrong-input-arity', 0, originals[0].replace('input_count 1', 'input_count 2')),
            ('duplicate-owner-role', 1, originals[1].replace('owner_id 1', 'owner_id 0')),
            ('wrong-run-job', 1, originals[1].replace('run_nonce ' + self.args.run_id,
                'run_nonce ' + ('1' if self.args.run_id[0] == '0' else '0') + self.args.run_id[1:])),
        ]
        results = []
        for name, owner, body in cases:
            changed = self.public / ('bad-contract-' + name + '.txt')
            changed.write_text(body)
            selected = list(contracts)
            selected[owner] = changed
            output = self.public / ('bad-contract-' + name + '-unexpected-output')
            argv = [str(self.args.binary), 'serve', '0', '59000', '59010',
                str(self.args.model), self.args.expected_model_sha256,
                str(selected[0]), str(selected[1]), str(self.args.verifier),
                self.args.expected_verifier_sha256, str(output), 'positive']
            with (self.private / (name + '.stdout')).open('xb') as stdout, \
                 (self.private / (name + '.stderr')).open('xb') as stderr:
                process = subprocess.Popen(argv, stdout=stdout, stderr=stderr,
                                           start_new_session=True)
                while process.poll() is None:
                    if output.exists():
                        os.killpg(process.pid, signal.SIGTERM)
                        process.wait()
                        raise RuntimeError('bad owner contract reached network admission: ' + name)
                    time.sleep(0.05)
                passed = process.returncode == 1 and not output.exists()
            results.append({'case': name, 'exit': process.returncode,
                'refused_before_network_or_owner_intake': passed})
            if not passed:
                write_json(self.public / 'CONTRACT-CONTROLS.json', results)
                raise RuntimeError('owner contract preinput control mismatch: ' + name)
        write_json(self.public / 'CONTRACT-CONTROLS.json', results)

    def role_command(self, role, keys, certs, command):
        work = self.root / role
        work.mkdir(mode=0o700)
        data = work / 'Player-Data'
        data.mkdir(mode=0o700)
        for certificate in certs.glob('*.pem'):
            shutil.copyfile(certificate, data / certificate.name)  # Public only.
        self.command(role + '-public-trust-links', ['openssl', 'rehash', str(data)])
        (data / (role + '.key')).touch(mode=0o600)  # Empty mount point only.
        vendor = self.args.vendor_root
        argv = ['bwrap', '--unshare-all', '--share-net', '--die-with-parent', '--new-session',
            '--clearenv', '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
            '--ro-bind', '/lib64', '/lib64', '--dir', '/etc', '--dir', '/etc/ssl',
            '--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs',
            '--ro-bind', '/etc/hosts', '/etc/hosts', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--dir', '/app', '--ro-bind', str(self.args.binary), '/app/mpc-fullproof',
            '--ro-bind', str(self.args.owner_client), '/app/owner-client',
            '--ro-bind', str(self.args.verifier), '/app/verifier',
            '--ro-bind', str(vendor / 'MP-SPDZ/libSPDZ.so'), '/app/libSPDZ.so',
            '--ro-bind', str(vendor / 'prefix/usr/lib/x86_64-linux-gnu'), '/app/prefix-libs',
            '--ro-bind', str(self.public), '/public', '--ro-bind', str(self.args.model), '/app/model.txt',
            '--bind', str(work), '/work', '--ro-bind', str(keys / (role + '.key')),
            '/work/Player-Data/' + role + '.key', '--chdir', '/work',
            '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LD_LIBRARY_PATH', '/app:/app/prefix-libs',
            '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'HOME', '/nonexistent',
            '--setenv', 'TMPDIR', '/tmp', *command]
        return argv, work

    def launch(self, role, argv, work, private_input=None):
        stdout = (self.private / (role + '.stdout')).open('xb')
        stderr = (self.private / (role + '.stderr')).open('xb')
        self.streams += [stdout, stderr]
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if private_input else subprocess.DEVNULL,
            stdout=stdout, stderr=stderr, start_new_session=True)
        self.processes[role] = process
        self.commands.append({'role': role, 'argv': argv, 'pid': process.pid})
        if private_input:
            process.stdin.write(private_input)
            process.stdin.close()
        self.stage_paths[role] = work / 'result/PUBLIC-STAGE.json'

    def wait_stage(self, required):
        order = ['preinput-admitted', 'interparty-addresses-ready', 'interparty-TLS-ready',
            'authenticated-field-and-MAC-setup-started', 'authenticated-field-and-MAC-setup-ready',
            'authenticated-protocol-set-started', 'authenticated-protocol-set-ready',
            'three-party-context-ready', 'owner-listeners-ready',
            'first-owner-input-received', 'second-owner-input-received', 'cross-owner-auxiliary-derived',
            'full-assignment-check-started', 'assignment-row-products-derived',
            'assignment-validity-MAC-checked', 'full-assignment-check-complete',
            'authenticated-H-map-started', 'authenticated-H-map-complete',
            'authenticated-proof-masks-derived', 'group-MAC-coordinators-ready',
            'masked-A-and-B1-MAC-checked',
            'final-B2-and-C-MAC-checked',
            'complete-proof-and-MAC-checks', 'independent-Ark-verification-complete', 'complete']
        while True:
            ready = True
            for role, process in self.processes.items():
                if process.poll() not in (None, 0):
                    raise RuntimeError('isolated role refused: ' + role + ' exit ' + str(process.returncode))
                if not role.startswith('P'):
                    continue
                path = self.stage_paths[role]
                if not path.exists():
                    ready = False
                    continue
                try:
                    stage = json.loads(path.read_text())
                except json.JSONDecodeError:
                    ready = False  # Sidecar writer may be replacing a small file.
                    continue
                if stage.get('schema') != 'kpi-mascot-public-stage/v1' or stage.get('status') == 'refused':
                    raise RuntimeError('isolated role phase refused: ' + role)
                phase = stage.get('phase')
                if phase not in order or order.index(phase) < order.index(required):
                    ready = False
            if ready:
                print(json.dumps({'stage': required, 'run_id': self.args.run_id}), flush=True)
                return
            time.sleep(0.1)

    def stop_owned(self):
        for process in self.processes.values():
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for process in self.processes.values():
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        for stream in self.streams:
            stream.close()

    def wait_expected_refusal(self):
        expected = {'invalid-assignment': 'invalid-assignment-refused',
                    'tamper-mac': 'mac-refused'}[self.args.control]
        expected_phase = {'invalid-assignment': 'assignment-validity-MAC-checked',
                          'tamper-mac': 'assignment-row-products-derived'}[self.args.control]
        while True:
            for role, process in self.processes.items():
                path = self.stage_paths[role]
                if role.startswith('P') and path.exists():
                    try:
                        stage = json.loads(path.read_text())
                    except json.JSONDecodeError:
                        continue
                    if stage.get('schema') == 'kpi-mascot-public-stage/v1' and \
                       stage.get('status') == expected and \
                       stage.get('phase') == expected_phase:
                        return {'role': role, 'public_stage': stage}
                    if stage.get('status') in {'refused', 'invalid-assignment-refused', 'mac-refused'}:
                        raise RuntimeError('wrong failure class for selected control: ' + role)
                if process.poll() not in (None, 0):
                    raise RuntimeError('role exited without expected typed refusal: ' + role)
            if all(p.poll() == 0 for role, p in self.processes.items() if role.startswith('P')):
                raise RuntimeError('failure-only control completed without refusal')
            time.sleep(0.1)

    def execute(self):
        freeze = self.freeze()
        self.preflight_controls()
        keys, certs, pins = self.certificates()
        contracts = self.contracts(pins, freeze)
        self.preinput_contract_controls(contracts)
        network_port, owner_port = port_block(), port_block()
        while abs(owner_port - network_port) < 4:
            owner_port = port_block()
        for party in range(3):
            command = ['/app/mpc-fullproof', 'serve', str(party), str(network_port), str(owner_port),
                '/app/model.txt', self.args.expected_model_sha256,
                '/public/' + contracts[0].name, '/public/' + contracts[1].name,
                '/app/verifier', self.args.expected_verifier_sha256, '/work/result', self.args.control]
            argv, work = self.role_command('P' + str(party), keys, certs, command)
            self.launch('P' + str(party), argv, work)
        self.wait_stage('owner-listeners-ready')
        for owner in range(2):
            command = ['/app/owner-client', '/public/' + contracts[owner].name,
                str(owner_port), '127.0.0.1', '127.0.0.1', '127.0.0.1']
            argv, work = self.role_command('C' + str(owner), keys, certs, command)
            self.launch('C' + str(owner), argv, work, private_input=(b'3\n' if owner == 0 else b'5\n'))
            if owner == 0 or self.args.control == 'positive':
                self.wait_stage('first-owner-input-received' if owner == 0 else 'second-owner-input-received')
        if self.args.control != 'positive':
            # Only the matching fixed typed invariant/MAC exception supplies
            # rejection credit. OOM, networking failure and elapsed time do not.
            refusal = self.wait_expected_refusal()
            self.stop_owned()
            if any((self.root / f'P{i}/result'/name).exists()
                   for i in range(3) for name in ['PUBLIC-RESULT.json', 'candidate-proof.bin']):
                raise RuntimeError('failure-only control released a proof')
            result = {'schema': 'kpi-mascot-fullproof-run/v1', 'run_id': self.args.run_id,
                'control': self.args.control, 'status': 'EXPECTED_REFUSAL',
                'any_public_proof_result': False, 'typed_refusal': refusal}
        else:
            self.wait_stage('complete')
            for process in self.processes.values():
                if process.wait() != 0:
                    raise RuntimeError('completed role returned failure')
            results = [json.loads((self.root / f'P{i}/result/PUBLIC-RESULT.json').read_text()) for i in range(3)]
            if any(r['status'] != 'VERIFIED' or r['party'] != i or
                r['model_sha256'] != self.args.expected_model_sha256 or
                r['payment_privacy_qualified'] is not False for i, r in enumerate(results)):
                raise RuntimeError('invalid typed party result')
            if len({r['proof_hex'] for r in results}) != 1 or len({r['proof_sha256'] for r in results}) != 1:
                raise RuntimeError('complete proof disagreement')
            proof = bytes.fromhex(results[0]['proof_hex'])
            if len(proof) != 128 or hashlib.sha256(proof).hexdigest() != results[0]['proof_sha256']:
                raise RuntimeError('invalid public proof encoding')
            proof_path = self.public / 'completed-proof.bin'
            proof_path.write_bytes(proof)
            checks = []
            for value, expected in [('128', 0), ('129', 1)]:
                with (self.private / ('verify-' + value + '.stdout')).open('xb') as out, \
                     (self.private / ('verify-' + value + '.stderr')).open('xb') as err:
                    code = subprocess.run([str(self.args.verifier), 'verify', str(self.args.model),
                        str(proof_path), value, self.args.expected_model_sha256], stdout=out, stderr=err).returncode
                checks.append({'public_input': value, 'exit': code, 'expected_exit': expected})
                if code != expected:
                    raise RuntimeError('independent public verifier control mismatch')
            result = {'schema': 'kpi-mascot-fullproof-run/v1', 'run_id': self.args.run_id,
                'control': 'positive', 'status': 'VERIFIED', 'parties': results,
                'public_verifier_controls': checks, 'payment_privacy_qualified': False}
        for source in freeze['public_sources']:
            if digest(Path(source['path'])) != source['sha256']:
                raise RuntimeError('source changed during selected attempt')
        for artifact in freeze['vendor_artifacts']:
            if digest(Path(artifact['path'])) != artifact['sha256']:
                raise RuntimeError('vendor artifact changed during selected attempt')
        for path, key in [(self.args.binary, 'binary_sha256'),
                          (self.args.owner_client, 'owner_client_sha256'),
                          (self.args.verifier, 'verifier_sha256'),
                          (self.args.model, 'model_sha256')]:
            if digest(path) != freeze[key]:
                raise RuntimeError('selected public runtime changed during attempt')
        result['private_keys_or_raw_diagnostics_read_or_hashed'] = False
        write_json(self.public / 'RESULT.json', result)
        return result


def main():
    parser = argparse.ArgumentParser()
    for name in ['binary', 'owner-client', 'verifier', 'model', 'vendor-root', 'output-parent']:
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--expected-model-sha256', required=True)
    parser.add_argument('--expected-verifier-sha256', required=True)
    parser.add_argument('--control', choices=['positive', 'invalid-assignment', 'tamper-mac'], default='positive')
    parser.add_argument('--run-id', default=None)
    parser.add_argument('--inside-scope', action='store_true')
    args = parser.parse_args()
    if args.run_id is None:
        args.run_id = secrets.token_hex(32)
    if len(args.run_id) != 64 or any(c not in '0123456789abcdef' for c in args.run_id):
        raise SystemExit('canonical fresh run identity required')
    for name in ['binary', 'owner_client', 'verifier', 'model', 'vendor_root', 'output_parent']:
        setattr(args, name, getattr(args, name).resolve())
    if not args.inside_scope:
        command = ['systemd-run', '--user', '--scope', '--quiet', '--collect',
            '--unit', 'kpi-mascot-toy-' + args.run_id,
            '--property=MemoryMax=6G', '--property=CPUQuota=400%', sys.executable,
            str(Path(__file__).resolve()), *sys.argv[1:], '--run-id', args.run_id, '--inside-scope']
        raise SystemExit(subprocess.run(command).returncode)
    os.umask(0o077)
    attempt = Attempt(args)
    try:
        result = attempt.execute()
        print(json.dumps({'run_id': args.run_id, 'status': result['status'],
                          'public_result': str(attempt.public / 'RESULT.json')}), flush=True)
    except BaseException as error:
        # This exception contains only controller-controlled names/statuses.
        # No child diagnostic is read to obtain an explanation.
        write_json(attempt.public / 'CONTROLLER-STOP.json', {'status': 'STOPPED',
            'reason': str(error), 'run_id': args.run_id,
            'role_exit_statuses_before_cleanup': {
                role: process.poll() for role, process in attempt.processes.items()},
            'private_keys_or_raw_diagnostics_read_or_hashed': False})
        raise
    finally:
        attempt.stop_owned()
        write_json(attempt.public / 'COMMANDS.json', attempt.commands)


if __name__ == '__main__':
    main()
