#!/usr/bin/env python3
"""Fresh isolated PUBLIC abc trace/proof control; never reads role diagnostics."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('isolated_fixture', SOURCE / 'run_toy.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class TraceAttempt(base.Attempt):
    def freeze(self):
        args = self.args
        build = json.loads((args.binary.parent / 'BUILD-RESULT.json').read_text())
        manifest = json.loads((args.fixture / 'manifest.json').read_text())
        if not build['success']:
            raise RuntimeError('trace build not qualified')
        self.decoder_library = Path(build['zlib_binary']['path'])
        for name, expected in build['source_sha256'].items():
            if base.digest(SOURCE / name) != expected:
                raise RuntimeError('selected trace source changed')
        for name, path in [('mpc-trace-gate', args.binary), ('owner-client', args.owner_client)]:
            records = [r for r in build['link'] if r['binary'] == name]
            if len(records) != 1 or records[0]['sha256'] != base.digest(path):
                raise RuntimeError('selected trace executable changed')
        for artifact in build['vendor_artifacts']:
            if base.digest(Path(artifact['path'])) != artifact['sha256']:
                raise RuntimeError('selected trace vendor changed')
        selected = {'public_model.txt': args.expected_model_sha256,
                    'trace.txt': manifest['trace_sha256'], 'layout.txt': manifest['layout_sha256']}
        for name, expected in selected.items():
            if base.digest(args.fixture / name) != expected:
                raise RuntimeError('selected trace public artifact changed')
        if base.digest(args.verifier) != args.expected_verifier_sha256:
            raise RuntimeError('selected independent verifier changed')
        unified = [line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                   if line.startswith('0::')]
        if len(unified) != 1 or 'kpi-mascot-trace-' + args.run_id + '.scope' not in unified[0]:
            raise RuntimeError('trace resource scope absent')
        scope = Path('/sys/fs/cgroup') / unified[0].lstrip('/')
        memory, cpu = (scope / 'memory.max').read_text().strip(), (scope / 'cpu.max').read_text().strip()
        quota, period = cpu.split()
        if memory != str(6 * 1024**3) or quota == 'max' or int(quota) > 4 * int(period):
            raise RuntimeError('trace resource scope changed')
        sources = [{'path': str(SOURCE / n), 'sha256': h} for n, h in build['source_sha256'].items()]
        freeze = {'schema': 'kpi-public-sha-trace-freeze/v1', 'run_id': args.run_id,
            'control': args.control, 'public_sources': sources, 'vendor_artifacts': build['vendor_artifacts'],
            'model_sha256': args.expected_model_sha256, 'verifier_sha256': args.expected_verifier_sha256,
            'binary_sha256': base.digest(args.binary), 'owner_client_sha256': base.digest(args.owner_client),
            'trace_sha256': manifest['trace_sha256'], 'layout_sha256': manifest['layout_sha256'],
            'public_input_file_sha256': base.digest(args.fixture / 'public-inputs.txt'),
            'public_manifest_sha256': base.digest(args.fixture / 'manifest.json'),
            'resources': {'memory_max_bytes': int(memory), 'cpu_max': cpu},
            'scope': 'PUBLIC abc owner-input/trace/proof functional gate; no payment/native/privacy qualification',
            'private_keys_or_raw_diagnostics_read_or_hashed': False}
        base.write_json(self.public / 'SOURCE-AND-CONTROL-FREEZE.json', freeze)
        self.manifest = manifest
        return freeze

    def contracts(self, pins, freeze):
        fields = base.public_fields(self.args.model)
        cohort = hashlib.sha256(json.dumps({'run': self.args.run_id, 'pins': pins,
            'source_freeze': freeze}, sort_keys=True).encode()).hexdigest()
        paths = []
        for owner in range(2):
            body = ('KPI_OWNER_CONTRACT_V2\nrun_nonce ' + self.args.run_id +
                '\nmodel ' + self.args.expected_model_sha256 + '\nsource ' + fields['source'] +
                '\npk ' + fields['pk_sha256'] + '\nvk ' + fields['vk_sha256'] +
                '\ntrace ' + self.manifest['trace_sha256'] + '\nlayout ' + self.manifest['layout_sha256'] +
                '\ncohort ' + cohort + '\nowner_id ' + str(owner) + '\ninput_count 12\n')
            for party in range(3):
                body += 'server_certificate_' + str(party) + ' ' + pins['P' + str(party)] + '\n'
            body += 'owner_certificate ' + pins['C' + str(owner)] + '\nEND\n'
            path = self.public / ('owner-' + str(owner) + '.contract')
            path.write_text(body)
            paths.append(path)
        return paths

    def role_command(self, role, keys, certs, command):
        argv, work = super().role_command(role, keys, certs, command)
        location = argv.index('--chdir')
        argv[location:location] = ['--ro-bind', str(self.args.fixture / 'trace.txt'), '/app/trace.txt',
            '--ro-bind', str(self.args.fixture / 'layout.txt'), '/app/layout.txt',
            '--ro-bind', str(self.decoder_library), '/app/libz.so.1']
        return argv, work

    def serve_command(self, party, network, owner, contracts, output='/work/result'):
        return ['/app/mpc-fullproof', 'serve', str(party), str(network), str(owner),
            '/app/model.txt', self.args.expected_model_sha256, '/app/trace.txt',
            self.manifest['trace_sha256'], '/app/layout.txt', self.manifest['layout_sha256'],
            '/public/' + contracts[0].name, '/public/' + contracts[1].name,
            '/app/verifier', self.args.expected_verifier_sha256, output, self.args.control]

    def preinput_controls(self, contracts):
        original = contracts[0].read_text()
        cases = [('wrong-trace', original.replace(self.manifest['trace_sha256'], '0' * 64)),
                 ('wrong-layout', original.replace(self.manifest['layout_sha256'], '0' * 64)),
                 ('wrong-count', original.replace('input_count 12', 'input_count 11')),
                 ('wrong-role', original.replace('owner_id 0', 'owner_id 1')),
                 ('downgrade-v1', original.replace('KPI_OWNER_CONTRACT_V2', 'KPI_OWNER_CONTRACT_V1')
                    .replace('trace ' + self.manifest['trace_sha256'] + '\n', '')
                    .replace('layout ' + self.manifest['layout_sha256'] + '\n', ''))]
        records = []
        for name, text in cases:
            changed = self.public / ('bad-' + name + '.contract')
            changed.write_text(text)
            output = self.public / ('unexpected-' + name)
            command = [str(self.args.binary), 'serve', '0', '59000', '59010',
                str(self.args.model), self.args.expected_model_sha256, str(self.args.fixture / 'trace.txt'),
                self.manifest['trace_sha256'], str(self.args.fixture / 'layout.txt'),
                self.manifest['layout_sha256'], str(changed), str(contracts[1]),
                str(self.args.verifier), self.args.expected_verifier_sha256, str(output), 'positive']
            with (self.private / (name + '.stdout')).open('xb') as out, \
                 (self.private / (name + '.stderr')).open('xb') as err:
                code = subprocess.run(command, stdout=out, stderr=err).returncode
            passed = code == 1 and not output.exists()
            records.append({'case': name, 'exit': code, 'refused_before_network_and_masks': passed})
            if not passed:
                raise RuntimeError('trace preinput contract control failed')
        base.write_json(self.public / 'CONTRACT-CONTROLS.json', records)

    def execute(self):
        freeze = self.freeze()
        command = [str(self.args.binary), 'preflight', str(self.args.model), self.args.expected_model_sha256,
            str(self.args.fixture / 'trace.txt'), self.manifest['trace_sha256'],
            str(self.args.fixture / 'layout.txt'), self.manifest['layout_sha256']]
        self.command('preflight', command)
        keys, certs, pins = self.certificates()
        contracts = self.contracts(pins, freeze)
        self.preinput_controls(contracts)
        network, owner = base.port_block(), base.port_block()
        while abs(network - owner) < 4: owner = base.port_block()
        for party in range(3):
            argv, work = self.role_command('P' + str(party), keys, certs,
                self.serve_command(party, network, owner, contracts))
            self.launch('P' + str(party), argv, work)
        self.wait_stage('owner-listeners-ready')
        # This controller handles PUBLIC abc fixture bits only. Financial owner
        # auxiliaries must be loaded by separate isolated owner-local workers.
        inputs = (self.args.fixture / 'public-inputs.txt').read_text().splitlines()
        if inputs[0] != 'PUBLIC_FIXTURE_INPUTS_V1 24':
            raise RuntimeError('public abc fixture input shape')
        values = [line.split()[1] for line in inputs[1:]]
        if len(values) != 24 or [line.split()[0] for line in inputs[1:]] != list(map(str, range(3, 27))) or \
           any(value not in ('0', '1') for value in values):
            raise RuntimeError('public abc fixture bit columns')
        for role in range(2):
            command = ['/app/owner-client', '/public/' + contracts[role].name,
                str(owner), '127.0.0.1', '127.0.0.1', '127.0.0.1']
            argv, work = self.role_command('C' + str(role), keys, certs, command)
            self.launch('C' + str(role), argv, work,
                private_input=('\n'.join(values[12 * role:12 * (role + 1)]) + '\n').encode())
            if role == 0: self.wait_stage('first-owner-input-received')
        expected = 'invalid-assignment-refused' if self.args.control == 'invalid-assignment' else 'mac-refused'
        expected_phase = 'batched-coin-agreed' if self.args.control == 'invalid-assignment' else 'batched-residuals-frozen'
        while True:
            stages = []
            for party in range(3):
                path = self.root / f'P{party}/result/PUBLIC-STAGE.json'
                try: stages.append(json.loads(path.read_text()))
                except (FileNotFoundError, json.JSONDecodeError): stages.append({})
            if self.args.control == 'positive':
                if any(s.get('status', '').endswith('refused') for s in stages):
                    raise RuntimeError('actual trace role refused')
                if all(s.get('status') == 'verified' and s.get('phase') == 'complete' for s in stages): break
            elif all(s.get('status') == expected and s.get('phase') == expected_phase for s in stages): break
            elif any(s.get('status', '').endswith('refused') for s in stages):
                if any(s.get('status', '').endswith('refused') and
                    (s.get('status') != expected or s.get('phase') != expected_phase) for s in stages):
                    raise RuntimeError('actual trace negative refused in wrong class or phase')
            if any(p.poll() not in (None, 0) and (not role.startswith('P') or
                stages[int(role[1:])].get('status') != expected or
                stages[int(role[1:])].get('phase') != expected_phase)
                for role, p in self.processes.items()):
                raise RuntimeError('actual trace process exited without typed result')
            time.sleep(0.1)
        if self.args.control != 'positive':
            self.stop_owned()
            if any((self.root / f'P{i}/result'/name).exists() for i in range(3)
                   for name in ['PUBLIC-RESULT.json', 'candidate-proof.bin']):
                raise RuntimeError('actual trace negative released proof')
            result = {'status': 'EXPECTED_REFUSAL', 'typed_stages': stages, 'any_public_proof_result': False}
        else:
            for process in self.processes.values():
                if process.wait() != 0: raise RuntimeError('actual trace completed role failed')
            results = [json.loads((self.root / f'P{i}/result/PUBLIC-RESULT.json').read_text()) for i in range(3)]
            if any(r.get('schema') != 'kpi-mascot-trace-party/v1' or r.get('party') != i or
                r.get('status') != 'VERIFIED' or r.get('model_sha256') != self.args.expected_model_sha256 or
                r.get('trace_sha256') != self.manifest['trace_sha256'] or
                r.get('payment_privacy_qualified') is not False for i, r in enumerate(results)):
                raise RuntimeError('actual trace typed proof result mismatch')
            if len({r['proof_hex'] for r in results}) != 1: raise RuntimeError('actual trace proof disagreement')
            proof = bytes.fromhex(results[0]['proof_hex'])
            if len(proof) != 128 or any(hashlib.sha256(proof).hexdigest() != r['proof_sha256'] for r in results):
                raise RuntimeError('actual trace proof encoding')
            proof_path = self.public / 'completed-proof.bin'; proof_path.write_bytes(proof)
            prefix = self.manifest['public_inputs_decimal'][1:]
            checks = []
            for changed in (False, True):
                selected = list(prefix)
                if changed: selected[0] = str(int(selected[0]) + 1)
                with (self.private / f'verify-{changed}.stdout').open('xb') as out, \
                     (self.private / f'verify-{changed}.stderr').open('xb') as err:
                    code = subprocess.run([str(self.args.verifier), 'verify', str(self.args.model),
                        str(proof_path), ','.join(selected), self.args.expected_model_sha256], stdout=out, stderr=err).returncode
                if code != int(changed): raise RuntimeError('independent trace verifier control')
                checks.append({'changed_public_digest': changed, 'exit': code})
            result = {'status': 'VERIFIED', 'parties': results, 'public_verifier_controls': checks}
        validation = []
        for party in range(3):
            path = self.root / f'P{party}/result/PUBLIC-VALIDATION.json'
            if path.exists():
                receipt = json.loads(path.read_text())
                if receipt.get('schema') != 'kpi-batched-validation-public/v1' or \
                   receipt.get('attempt') != self.args.run_id or \
                   receipt.get('private_residuals_or_Z_or_shares_exported') is not False:
                    raise RuntimeError('invalid public validation receipt')
                validation.append(receipt)
                base.write_json(self.public / f'P{party}-PUBLIC-VALIDATION.json', receipt)
        if self.args.control == 'positive':
            if len(validation) != 3 or any(r.get('state') != 'PrivateZeroTestPassed' or
                r.get('residual_count') != 28852 for r in validation) or \
               len({r['binding_sha256'] for r in validation}) != 1 or \
               len({r['public_challenge'] for r in validation}) != 1:
                raise RuntimeError('actual trace public validation agreement')
        else:
            if len(validation) != 3 or any(r.get('state') != 'Aborted' or
                r.get('residual_count') != 28852 for r in validation):
                raise RuntimeError('negative trace validation did not reach the selected residual set')
            coins = [r.get('public_challenge') for r in validation]
            if self.args.control == 'invalid-assignment':
                modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617
                if any(not isinstance(c, str) or not c.isdecimal() or str(int(c)) != c or
                       not 0 <= int(c) < modulus for c in coins) or len(set(coins)) != 1:
                    raise RuntimeError('negative assignment check lacks the agreed canonical public coin')
            elif coins != ['', '', '']:
                raise RuntimeError('negative MAC control reached coin generation')
        result['public_validation_receipts'] = validation
        for entry in freeze['public_sources'] + freeze['vendor_artifacts']:
            if base.digest(Path(entry['path'])) != entry['sha256']:
                raise RuntimeError('trace selected source or vendor changed during run')
        for path, key in [(self.args.binary, 'binary_sha256'), (self.args.owner_client, 'owner_client_sha256'),
                          (self.args.verifier, 'verifier_sha256'), (self.args.model, 'model_sha256'),
                          (self.args.fixture / 'trace.txt', 'trace_sha256'),
                          (self.args.fixture / 'layout.txt', 'layout_sha256')]:
            if base.digest(path) != freeze[key]: raise RuntimeError('trace artifact changed during run')
        for name, key in [('public-inputs.txt', 'public_input_file_sha256'),
                          ('manifest.json', 'public_manifest_sha256')]:
            if base.digest(self.args.fixture / name) != freeze[key]:
                raise RuntimeError('public trace fixture changed during run')
        result.update(schema='kpi-public-sha-trace-run/v1', run_id=self.args.run_id, control=self.args.control,
            payment_privacy_qualified=False, private_keys_or_raw_diagnostics_read_or_hashed=False)
        base.write_json(self.public / 'RESULT.json', result)
        return result


def main():
    parser = argparse.ArgumentParser()
    for name in ['binary', 'owner-client', 'verifier', 'fixture', 'vendor-root', 'output-parent']:
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--expected-model-sha256', required=True)
    parser.add_argument('--expected-verifier-sha256', required=True)
    parser.add_argument('--control', choices=['positive', 'invalid-assignment', 'tamper-mac'], default='positive')
    parser.add_argument('--run-id', default=secrets.token_hex(32))
    parser.add_argument('--inside-scope', action='store_true')
    args = parser.parse_args()
    if len(args.run_id) != 64 or any(c not in '0123456789abcdef' for c in args.run_id):
        raise SystemExit('fresh canonical trace identity required')
    for name in ['binary', 'owner_client', 'verifier', 'fixture', 'vendor_root', 'output_parent']:
        setattr(args, name, getattr(args, name).resolve())
    args.model = args.fixture / 'public_model.txt'
    if not args.inside_scope:
        command = ['systemd-run', '--user', '--scope', '--quiet', '--collect',
            '--unit', 'kpi-mascot-trace-' + args.run_id, '-p', 'MemoryMax=6G', '-p', 'CPUQuota=400%',
            sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], '--run-id', args.run_id, '--inside-scope']
        raise SystemExit(subprocess.run(command).returncode)
    attempt = TraceAttempt(args)
    try:
        print(json.dumps(attempt.execute(), indent=2), flush=True)
    except Exception as error:
        base.write_json(attempt.public / 'FAILED.json', {'schema': 'kpi-public-sha-trace-failure/v1',
            'run_id': args.run_id, 'controller_error': str(error), 'raw_logs_read': False,
            'role_exit_codes': {role: process.poll() for role, process in attempt.processes.items()}})
        raise
    finally:
        attempt.stop_owned()


if __name__ == '__main__': main()
