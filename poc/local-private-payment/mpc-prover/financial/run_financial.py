#!/usr/bin/env python3
"""Fresh fixed unfunded financial qualification; no registration or settlement.

Only the three isolated owner executables read their own private input files.
The controller reads public sources, parameters, certificates and typed results.
Raw MPC diagnostics, owner inputs and TLS private-key bodies remain unread.
"""
import argparse
import array
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import threading

SOURCE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('financial_isolation', SOURCE / 'run_toy.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
MODEL = 'f3ca3c18f17ed8175fa420364e9aa2824a12af4320ca1dc00ba2508f60ba28ff'
SOURCE_SHA = '3ff31adfc6f2666ac53606ecf60336366d850951fda22a38b7445262f380d829'
TRACE = '4c3dec7c553f66e45775bff2c950417060980cf443ab83a2d198587fc604808e'
LAYOUT = '9a3ee5f5eb98384273e2b608f71a60f89c49e6fc9c1029586f8f201b84617e1e'
PK = '170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945'
PK_GZ = '4a3d0ac3143ecc32a875af8107c923b851036363a68a8a744b97c74d0a3879ff'
VK = '2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102'
VERIFIER = 'c1805cfe7ae9b2db7d58fd58727b57e92a0fec866506cd720fbd59242359131f'
SCOPE = 'PUBLIC_UNFUNDED_UNREGISTERED_QUALIFICATION_ONLY'


def need(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    # These callers pass PUBLIC files only. Never use this for owner inputs or
    # keys, even when the synthetic fixture happens to have known values.
    result = hashlib.sha256()
    with path.open('rb') as source:
        while block := source.read(4 * 1024**2):
            result.update(block)
    return result.hexdigest()


base.digest = digest


class FinancialAttempt(base.Attempt):
    def freeze(self):
        args = self.args
        build = json.loads((args.binary.parent / 'BUILD-RESULT.json').read_text())
        need(build['success'] and build['schema'] == 'kpi-financial-qualification-build/v1', 'unqualified financial build')
        self.decoder = Path(build['zlib_binary']['path'])
        for name, expected in build['source_sha256'].items():
            need(digest(SOURCE / name) == expected, 'financial source changed')
        for name, path in [('mpc-financial-qualification', args.binary), ('financial-owner-client', args.owner_client)]:
            records = [r for r in build['link'] if r['binary'] == name]
            need(len(records) == 1 and records[0]['sha256'] == digest(path), 'financial executable changed')
        for artifact in build['vendor_artifacts']:
            need(digest(Path(artifact['path'])) == artifact['sha256'], 'financial vendor changed')
        need(digest(args.model / 'model.meta') == MODEL and digest(args.verifier) == VERIFIER,
             'financial model or independent verifier changed')
        transport = json.loads((args.model / 'TRANSPORT.json').read_text())
        need(transport['metadata_sha256'] == MODEL and transport['source_sha256'] == SOURCE_SHA,
             'financial transport root changed')
        self.transport = transport
        # Exact public transport hashes are rechecked before sealing/mounting,
        # and every role independently admits canonical decoded bytes/points.
        self.artifacts = [(args.model / 'model.meta', MODEL),
            (Path(transport['stock_vk']['path']), VK),
            (args.trace / 'trace.txt.gz', '0edbd4f22706d54a56ec5a670a2cf89f7075dd286130b3f64dbc73767cdef95c'),
            (args.trace / 'layout.txt.gz', 'b69d19619ebe92e5512ad268b6ba299f2e04255d504aeac1a2d3cca55ef68942'),
            (args.trace / 'PREFIX-RECIPE.bin', 'ef6279fa5633c77230a8a8b8ae9b70a58770a30e6c6f5e0bcf97edba0d0e0edb')]
        for axis in transport['axes']:
            self.artifacts.append((Path(axis['path']), axis['compressed_sha256']))
        for path, expected in self.artifacts:
            need(digest(path) == expected, 'selected financial public artifact changed')
        need(digest(args.native_parameters) == '3f9f2f294c8203c8fc99ba66e1a78e769a1eecc4ecc5cf8f8b631eea28138751',
             'fixed native PARAMETERS identity')
        tail = (args.native_parameters.parent / 'IMMUTABLE-TAIL.bin').read_bytes()
        need(hashlib.sha256(tail).hexdigest() == '4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d',
             'selected native tail bytes')
        (self.public / 'native-tail.bin').write_bytes(tail)
        head_path = Path('/run/user/1000/kpb-unfunded-batch-components-20261028-05/PUBLIC-GENESIS-HEAD.json')
        need(digest(head_path) == '910c09f5ea30ece29b36b1d0428a7c04c10e3b2e7f6ab65457c248b45c6cddf9',
             'fixed unfunded public head')
        head = json.loads(head_path.read_text())
        need(hashlib.sha256(bytes.fromhex(head['context_hex276'])).hexdigest() ==
             '6efa0e97ae8868b12743d72d45dcd46e858214e3413a1c63c1dee1ab56aacdc0', 'fixed public context')
        unified = [line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                   if line.startswith('0::')]
        need(len(unified) == 1 and 'kpi-financial-' + args.run_id + '.scope' in unified[0], 'financial resource scope absent')
        scope = Path('/sys/fs/cgroup') / unified[0].lstrip('/')
        resources = {'memory_max': (scope / 'memory.max').read_text().strip(),
                     'cpu_max': (scope / 'cpu.max').read_text().strip()}
        freeze = {'schema': 'kpi-financial-qualification-freeze/v1', 'scope': SCOPE, 'run_id': args.run_id,
            'source_sha256': build['source_sha256'], 'vendor_artifacts': build['vendor_artifacts'],
            'binary_sha256': digest(args.binary), 'owner_client_sha256': digest(args.owner_client),
            'verifier_sha256': VERIFIER, 'model_sha256': MODEL, 'trace_sha256': TRACE,
            'layout_sha256': LAYOUT, 'transport_sha256': digest(args.model / 'TRANSPORT.json'),
            'trace_manifest_sha256': digest(args.trace / 'PUBLIC-TRACE-MANIFEST.json'),
            'native_parameters_file_sha256': digest(args.native_parameters), 'resources': resources,
            'public_head_sha256': digest(head_path),
            'public_context_sha256': '6efa0e97ae8868b12743d72d45dcd46e858214e3413a1c63c1dee1ab56aacdc0',
            'registered_financial_service': False, 'private_owner_files_or_keys_read_or_hashed': False,
            'raw_party_diagnostics_read': False, 'native_settlement_performed': False}
        base.write_json(self.public / 'SOURCE-AND-CONTROL-FREEZE.json', freeze)
        self.freeze_receipt = freeze
        return freeze

    def certificates(self):
        keys, certs, pins = super().certificates()
        role = 'C2'
        extension = certs / (role + '.ext')
        extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
            'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:C2\n')
        self.command(role + '-csr', ['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(keys / 'C2.key'), '-out', str(certs / 'C2.csr'), '-subj', '/CN=C2'])
        self.command(role + '-certificate', ['openssl', 'x509', '-req', '-in', str(certs / 'C2.csr'),
            '-CA', str(certs / 'ca.pem'), '-CAkey', str(keys / 'ca.key'), '-CAcreateserial', '-days', '1',
            '-out', str(certs / 'C2.pem'), '-extfile', str(extension)])
        der = self.command(role + '-public-DER', ['openssl', 'x509', '-in', str(certs / 'C2.pem'),
                           '-outform', 'DER'], capture_public=True)
        pins[role] = hashlib.sha256(der).hexdigest()
        need(len(set(pins.values())) == 6, 'six distinct public certificate pins')
        return keys, certs, pins

    def contracts(self, pins, freeze):
        cohort = hashlib.sha256(json.dumps({'run': self.args.run_id, 'pins': pins, 'freeze': freeze},
                                           sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        paths = []
        for owner in range(3):
            body = ('KPI_OWNER_CONTRACT_V2\nrun_nonce ' + self.args.run_id + '\nmodel ' + MODEL +
                '\nsource ' + SOURCE_SHA + '\npk ' + PK + '\nvk ' + VK + '\ntrace ' + TRACE +
                '\nlayout ' + LAYOUT + '\ncohort ' + cohort + '\nowner_id ' + str(owner) + '\ninput_count 2635409\n')
            for party in range(3):
                body += 'server_certificate_' + str(party) + ' ' + pins['P' + str(party)] + '\n'
            body += 'owner_certificate ' + pins['C' + str(owner)] + '\nEND\n'
            path = self.public / ('owner-' + str(owner) + '.contract')
            path.write_text(body); paths.append(path)
        return paths

    def contract_controls(self, contracts):
        original = contracts[0].read_text()
        cases = [('positive', original, 0)]
        for field, value in [('run_nonce', self.args.run_id), ('model', MODEL), ('source', SOURCE_SHA),
                             ('pk', PK), ('vk', VK), ('trace', TRACE), ('layout', LAYOUT)]:
            cases.append(('wrong-' + field, original.replace(field + ' ' + value, field + ' ' + '0' * 64), 1))
        cases.extend([('wrong-count', original.replace('input_count 2635409', 'input_count 2635408'), 1),
                      ('wrong-role', original.replace('owner_id 0', 'owner_id 1'), 1)])
        results = []
        for name, text, expected in cases:
            path = self.public / ('control-' + name + '.contract'); path.write_text(text)
            with (self.private / (name + '.stdout')).open('xb') as out, (self.private / (name + '.stderr')).open('xb') as err:
                code = subprocess.run([str(self.args.binary), 'check-contracts', str(path),
                    str(contracts[1]), str(contracts[2])], stdout=out, stderr=err).returncode
            need(code == expected, 'financial preinput contract control: ' + name)
            results.append({'case': name, 'exit': code, 'before_network_or_owner_input': True})
        base.write_json(self.public / 'CONTRACT-CONTROLS.json', results)

    def seal_public_pk(self):
        path = Path(self.transport['stock_pk_gzip']['path'])
        source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        target = os.memfd_create('kpb-public-stock-PK-gzip', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        try:
            before = os.fstat(source_fd)
            need(stat.S_ISREG(before.st_mode) and before.st_size == 1749414110, 'public PK transport size')
            sha = hashlib.sha256()
            while block := os.read(source_fd, 4 * 1024**2):
                sha.update(block)
                offset = 0
                while offset < len(block):
                    offset += os.write(target, block[offset:])
            after = os.fstat(source_fd)
            need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                 and sha.hexdigest() == PK_GZ, 'selected immutable public PK bytes')
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            fcntl.fcntl(target, fcntl.F_ADD_SEALS, seals)
            need(fcntl.fcntl(target, fcntl.F_GET_SEALS) & seals == seals, 'public PK kernel sealing')
            self.pk_fd = target
            base.write_json(self.public / 'SHARED-PUBLIC-PK.json', {'schema': 'kpi-shared-sealed-public-pk/v1',
                'container_sha256': PK_GZ, 'container_bytes': before.st_size,
                'kernel_seals': seals, 'physical_sealed_copies': 1, 'private_data': False})
        except BaseException:
            os.close(target); raise
        finally:
            os.close(source_fd)

    def serve_public_pk(self):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        # Abstract Unix addresses avoid filesystem pathname limits and expire
        # with this listener. Only the already shared network namespace is used.
        listener.bind('\0kpb-public-pk-' + self.args.run_id)
        listener.listen(3)
        self.transport_listener = listener
        self.transport_errors = []
        def send_references():
            try:
                roles = set()
                while len(roles) < 3:
                    channel, _ = listener.accept()
                    with channel:
                        role = channel.recv(2)
                        need(role in (b'0', b'1', b'2') and role not in roles, 'public PK descriptor role')
                        need(channel.sendmsg([b'P'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                             array.array('i', [self.pk_fd]))]) == 1, 'public PK descriptor transfer')
                        roles.add(role)
            except BaseException as error:
                self.transport_errors.append(str(error))
        self.transport_thread = threading.Thread(target=send_references, daemon=True)
        self.transport_thread.start()

    def bootstrap(self, pins):
        root = self.root / 'unregistered-history'
        command = [sys.executable, str(SOURCE / 'history/qualification_bootstrap.py'), '--output', str(root)]
        for party in range(3):
            command += ['--server-certificate-sha256', pins['P' + str(party)]]
        self.command('fixed-unfunded-history-bootstrap', command)
        registration = root / 'qualification/REGISTRATION.json'
        document = json.loads(registration.read_text())
        need(document['registration']['scope'] == SCOPE and
             document['registration']['registered_financial_service'] is False, 'qualification scope')
        self.registration = registration
        self.history_roles = document['registration']['roles']
        need(len(self.history_roles) == 3, 'three existing qualification journals')

    def role_command(self, role, keys, certs, command):
        work = self.root / role; work.mkdir(mode=0o700)
        data = work / 'Player-Data'; data.mkdir(mode=0o700)
        for certificate in certs.glob('*.pem'):
            shutil.copyfile(certificate, data / certificate.name)
        self.command(role + '-public-trust-links', ['openssl', 'rehash', str(data)])
        (data / (role + '.key')).touch(mode=0o600)
        vendor = self.args.vendor_root
        argv = ['bwrap', '--unshare-all', '--share-net', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
            '--dir', '/etc', '--dir', '/etc/ssl', '--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs',
            '--ro-bind', '/etc/hosts', '/etc/hosts', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/app',
            '--ro-bind', str(self.args.binary), '/app/mpc-financial',
            '--ro-bind', str(self.args.owner_client), '/app/financial-owner-client',
            '--ro-bind', str(self.args.verifier), '/app/verifier',
            '--ro-bind', str(vendor / 'MP-SPDZ/libSPDZ.so'), '/app/libSPDZ.so',
            '--ro-bind', str(vendor / 'prefix/usr/lib/x86_64-linux-gnu'), '/app/prefix-libs',
            '--ro-bind', str(self.decoder), '/app/libz.so.1', '--ro-bind', str(self.public), '/public',
            '--bind', str(work), '/work', '--ro-bind', str(keys / (role + '.key')), '/work/Player-Data/' + role + '.key']
        if role.startswith('P'):
            party = int(role[1:]); record = self.history_roles[party]
            need(record['party_id'] == party, 'history role ordering')
            argv += ['--ro-bind', str(self.args.model), '/app/model',
                '--ro-bind', str(self.args.trace / 'trace.txt.gz'), '/app/trace.txt.gz',
                '--ro-bind', str(self.args.trace / 'layout.txt.gz'), '/app/layout.txt.gz',
                '--ro-bind', str(self.args.trace / 'PREFIX-RECIPE.bin'), '/app/PREFIX-RECIPE.bin',
                '--ro-bind', str(self.public / 'native-tail.bin'), '/app/native-tail.bin',
                '--ro-bind', self.transport['stock_vk']['path'], '/app/vk.bin',
                '--ro-bind', str(self.registration), str(self.registration),
                '--ro-bind', record['role_spec'], record['role_spec'],
                '--bind', record['local_directory'], record['local_directory'],
                '--bind', record['trusted_anchor_directory'], record['trusted_anchor_directory']]
            for axis in self.transport['axes']:
                argv += ['--ro-bind', axis['path'], '/app/rows/' + 'ABC'[axis['axis']] + '.r1cs.bin.gz']
        else:
            # Pass a PATH/mount only. Cn alone opens/parses its own file using
            # the source-reviewed strict format and unchanged V2 TLS protocol.
            argv += ['--ro-bind', str(self.args.owner_input_file[int(role[1:])]), '/owner/OWNER-PRIVATE-INPUT-V2.bin']
        argv += ['--chdir', '/work', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LD_LIBRARY_PATH', '/app:/app/prefix-libs',
            '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'HOME', '/nonexistent', '--setenv', 'TMPDIR', '/tmp', *command]
        return argv, work

    def launch(self, role, argv, work):
        out = (self.private / (role + '.stdout')).open('xb'); err = (self.private / (role + '.stderr')).open('xb')
        self.streams += [out, err]
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
            start_new_session=True)
        self.processes[role] = process
        self.commands.append({'role': role, 'argv': argv, 'pid': process.pid})
        self.stage_paths[role] = work / 'result/PUBLIC-STAGE.json'

    def wait_phase(self, target):
        # Stages are fixed public metadata. Remember reaching a stage so that
        # a quick later transition cannot make the supervisor wait forever.
        reached = set()
        last = {}
        while len(reached) < 3:
            need(not self.transport_errors, 'public PK descriptor transfer refused')
            for role, process in self.processes.items():
                if process.poll() not in (None, 0):
                    raise RuntimeError('financial role exited without successful result: ' + role)
                if not role.startswith('P'): continue
                try: status = json.loads(self.stage_paths[role].read_text())
                except (FileNotFoundError, json.JSONDecodeError): continue
                need(status.get('schema') == 'kpi-mascot-public-stage/v1', 'typed financial stage schema')
                need(status.get('status') not in ('refused', 'mac-refused'), 'financial role typed refusal: ' + role)
                phase = status.get('phase')
                if last.get(role) != phase:
                    print(json.dumps({'role': role, 'stage': phase, 'run_id': self.args.run_id}), flush=True)
                    last[role] = phase
                if phase == target: reached.add(role)
                history = self.stage_paths[role].with_name('PUBLIC-STAGES.jsonl')
                if history.exists():
                    for line in history.read_text().splitlines():
                        try: prior = json.loads(line)
                        except json.JSONDecodeError: continue
                        if prior.get('schema') == 'kpi-mascot-public-stage/v1' and prior.get('phase') == target:
                            reached.add(role)
            time.sleep(0.2)

    def execute(self):
        freeze = self.freeze()
        keys, certs, pins = self.certificates()
        contracts = self.contracts(pins, freeze)
        self.contract_controls(contracts)
        self.bootstrap(pins)
        self.seal_public_pk()
        self.serve_public_pk()
        dependencies = hashlib.sha256(json.dumps({'freeze': freeze,
            'registration_file_sha256': digest(self.registration)}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        network, owner_port = base.port_block(), base.port_block()
        while abs(network - owner_port) < 4: owner_port = base.port_block()
        for party in range(3):
            command = ['/app/mpc-financial', 'qualify', str(party), str(network), str(owner_port),
                self.history_roles[party]['role_spec'], *['/public/' + path.name for path in contracts],
                dependencies, '/work/result']
            argv, work = self.role_command('P' + str(party), keys, certs, command)
            self.launch('P' + str(party), argv, work)
        self.wait_phase('owner-listeners-ready')
        for owner in range(3):
            command = ['/app/financial-owner-client', '/public/' + contracts[owner].name, str(owner_port),
                '127.0.0.1', '127.0.0.1', '127.0.0.1', '/owner/OWNER-PRIVATE-INPUT-V2.bin']
            argv, work = self.role_command('C' + str(owner), keys, certs, command)
            self.launch('C' + str(owner), argv, work)
            self.wait_phase(['first-owner-input-received', 'second-owner-input-received',
                             'third-owner-input-received'][owner])
        self.wait_phase('complete')
        for process in self.processes.values(): need(process.wait() == 0, 'financial completed role exit')
        parties = [json.loads((self.root / f'P{i}/result/PUBLIC-RESULT.json').read_text()) for i in range(3)]
        for i, result in enumerate(parties):
            need(result.get('schema') == 'kpi-financial-qualification-party/v1' and result.get('party') == i and
                 result.get('scope') == SCOPE and result.get('registered_financial_service') is False and
                 result.get('status') == 'VERIFIED_AND_DURABLE_EGRESS' and result.get('model_sha256') == MODEL and
                 result.get('trace_sha256') == TRACE and result.get('payment_privacy_qualified') is False and
                 result.get('native_settlement_performed') is False and result.get('residual_count') == 13127204 and
                 result.get('actual_R1CS_rows') == 13093029 and result.get('trace_assertions') == 33896 and
                 result.get('context_byte_assertions') == 276 and result.get('historical_NF_assertions') == 0,
                 'financial typed completion')
            coin = result.get('public_challenge')
            need(isinstance(coin, str) and coin.isdecimal() and str(int(coin)) == coin and
                 0 <= int(coin) < 21888242871839275222246405745257275088548364400416034343698204186575808495617,
                 'canonical checked public Fr challenge')
        for key in ('construction_sha256', 'validation_sha256', 'residual_count', 'public_challenge',
                    'effects_sha256', 'core_sha256', 'proof_sha256', 'projection_sha256', 'egress_binding_sha256'):
            need(len({p[key] for p in parties}) == 1, 'financial party disagreement: ' + key)
        for name, size, key in [('released-core.bin', 10364, 'core_sha256'), ('released-proof.bin', 128, 'proof_sha256'),
                                ('released-projection.bin', 10685, 'projection_sha256')]:
            for party in range(3):
                path = self.root / f'P{party}/result' / name
                need(path.stat().st_size == size and digest(path) == parties[party][key], 'released public artifact identity')
            shutil.copyfile(self.root / 'P0/result' / name, self.public / name)
        core = (self.public / 'released-core.bin').read_bytes()
        effects = hashlib.sha256(core).digest()
        need(effects.hex() == parties[0]['effects_sha256'], 'released core SHA digest')
        prefix = [str(int.from_bytes(effects[i:i+16], 'little')) for i in (0, 16)]
        checks = []
        for changed in (False, True):
            chosen = prefix[:]
            if changed: chosen[0] = str(int(chosen[0]) + 1)
            with (self.private / f'Verify-{changed}.stdout').open('xb') as out, (self.private / f'Verify-{changed}.stderr').open('xb') as err:
                code = subprocess.run([str(self.args.verifier), 'verify-packed', str(self.args.model / 'model.meta'),
                    self.transport['stock_vk']['path'], str(self.public / 'released-proof.bin'), ','.join(chosen), MODEL],
                    stdout=out, stderr=err).returncode
            need(code == int(changed), 'independent financial digest verifier control')
            checks.append({'changed_digest_limb': changed, 'exit': code})
        for name, expected in freeze['source_sha256'].items(): need(digest(SOURCE / name) == expected, 'source changed during run')
        for artifact in freeze['vendor_artifacts']: need(digest(Path(artifact['path'])) == artifact['sha256'], 'vendor changed during run')
        for path, expected in self.artifacts: need(digest(path) == expected, 'public artifact changed during run')
        need(digest(self.args.binary) == freeze['binary_sha256'] and
             digest(self.args.owner_client) == freeze['owner_client_sha256'] and
             digest(self.args.verifier) == freeze['verifier_sha256'], 'executable changed during run')
        result = {'schema': 'kpi-financial-qualification-run/v1', 'run_id': self.args.run_id, 'status': 'VERIFIED_AND_DURABLE_EGRESS',
            'scope': SCOPE, 'parties': parties, 'independent_digest_verifier_controls': checks,
            'registered_financial_service': False, 'payment_privacy_qualified': False, 'native_settlement_performed': False,
            'private_owner_files_or_keys_read_or_hashed': False, 'raw_party_diagnostics_read': False}
        base.write_json(self.public / 'RESULT.json', result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'owner-client', 'verifier', 'model', 'trace', 'native-parameters', 'vendor-root', 'output-parent'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--owner-input-file', required=True, action='append', type=Path)
    parser.add_argument('--run-id', default=secrets.token_hex(32))
    parser.add_argument('--memory-gib', type=int, default=18)
    parser.add_argument('--cpu-cores', type=int, default=8)
    parser.add_argument('--inside-scope', action='store_true')
    args = parser.parse_args()
    need(len(args.run_id) == 64 and all(c in '0123456789abcdef' for c in args.run_id), 'fresh canonical financial identity')
    need(len(args.owner_input_file) == 3 and args.memory_gib > 0 and args.cpu_cores > 0, 'three owner paths and positive resources')
    for name in ('binary', 'owner_client', 'verifier', 'model', 'trace', 'native_parameters', 'vendor_root', 'output_parent'):
        setattr(args, name, getattr(args, name).resolve())
    # Path normalization only; do not resolve/stat/open/hash owner bodies here.
    args.owner_input_file = [Path(os.path.abspath(path)) for path in args.owner_input_file]
    need(args.owner_input_file == [Path('/run/user/1000/kpb-unfunded-batch-components-20261028-05/owners') /
        str(i) / 'OWNER-PRIVATE-INPUT-V2.bin' for i in range(3)], 'fixed ordered unfunded owner paths only')
    if not args.inside_scope:
        command = ['systemd-run', '--user', '--scope', '--quiet', '--collect', '--unit', 'kpi-financial-' + args.run_id,
            '-p', 'MemoryMax=' + str(args.memory_gib) + 'G', '-p', 'CPUQuota=' + str(args.cpu_cores * 100) + '%',
            sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], '--run-id', args.run_id, '--inside-scope']
        raise SystemExit(subprocess.run(command).returncode)
    attempt = FinancialAttempt(args)
    try:
        print(json.dumps(attempt.execute(), indent=2), flush=True)
    except BaseException as error:
        base.write_json(attempt.public / 'FAILED.json', {'schema': 'kpi-financial-qualification-failure/v1',
            'run_id': args.run_id, 'controller_error': str(error), 'raw_logs_read': False,
            'role_exit_codes': {role: process.poll() for role, process in attempt.processes.items()}})
        raise
    finally:
        attempt.stop_owned()
        if hasattr(attempt, 'transport_listener'): attempt.transport_listener.close()
        if hasattr(attempt, 'pk_fd'): os.close(attempt.pk_fd)


if __name__ == '__main__':
    main()
