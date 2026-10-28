#!/usr/bin/env python3
"""Fresh isolated three-party PUBLIC-fixture capability controls.

Only typed public sidecars and selected public build inputs are read. Worker
stdout/stderr, private keys, preprocessing files and worker proof files remain
unread and unhashed. This is not an owner-input or financial qualification.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('isolated_fixture', SOURCE / 'run_toy.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
CASES = ('valid', 'caller-mutation', 'reuse', 'different-context-generation',
    'poisoned-context', 'post-validation-MAC-failure', 'skipped-assertion',
    'extra-assertion', 'bad-assertion', 'bad-ONE', 'bad-prefix', 'bad-witness',
    'wrong-model', 'wrong-source', 'wrong-matrix', 'wrong-trace', 'wrong-layout',
    'wrong-input-map', 'wrong-attempt', 'wrong-history', 'wrong-context',
    'wrong-dependency', 'wrong-service', 'wrong-assertion-count',
    'malformed-contribution', 'commitment-mismatch', 'repeat-validation-attempt',
    'repeat-after-invalid')
PROOF_CASES = {'valid', 'caller-mutation', 'reuse'}
SHAPE_CASES = {'skipped-assertion', 'extra-assertion'}
INVALID_CASES = {'bad-assertion', 'bad-ONE', 'bad-prefix', 'bad-witness', 'repeat-after-invalid'}
COIN_FAULT_CASES = {'malformed-contribution', 'commitment-mismatch'}
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def port_block():
    for _ in range(1000):
        selected = 20000 + secrets.randbelow(30000)
        channels = []
        try:
            for offset in range(11):
                channel = socket.socket()
                channels.append(channel)
                channel.bind(('127.0.0.1', selected + offset))
            return selected
        except OSError:
            pass
        finally:
            for channel in channels:
                channel.close()
    raise RuntimeError('no free control port block')


def canonical_coin(value):
    return isinstance(value, str) and value.isascii() and value.isdigit() and \
        str(int(value)) == value and int(value) < P


class Attempt(base.Attempt):
    def freeze(self):
        args = self.args
        build = json.loads((args.binary.parent / 'BUILD-RESULT.json').read_text())
        if build.get('success') is not True or base.digest(args.binary) != build['link']['sha256']:
            raise RuntimeError('selected control build is not qualified')
        for name, expected in build['source_sha256'].items():
            if base.digest(SOURCE / name) != expected:
                raise RuntimeError('selected control source changed')
        for artifact in build['vendor_artifacts'] + build['reused_objects']:
            if base.digest(Path(artifact['path'])) != artifact['sha256']:
                raise RuntimeError('selected control artifact changed')
        if base.digest(args.owner_client) != build['owner_client']['sha256']:
            raise RuntimeError('selected owner helper changed')
        for path, expected in [(args.model, args.expected_model_sha256),
                               (args.verifier, args.expected_verifier_sha256)]:
            if base.digest(path) != expected:
                raise RuntimeError('selected public runtime changed')
        unified = [line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                   if line.startswith('0::')]
        if len(unified) != 1 or 'kpi-batched-capability-' + args.run_id + '.scope' not in unified[0]:
            raise RuntimeError('selected shared control resource scope is absent')
        scope = Path('/sys/fs/cgroup') / unified[0].lstrip('/')
        memory, cpu = (scope / 'memory.max').read_text().strip(), (scope / 'cpu.max').read_text().strip()
        quota, period = cpu.split()
        if memory != str(6 * 1024**3) or quota == 'max' or int(quota) > 4 * int(period):
            raise RuntimeError('selected shared control window changed')
        result = {'schema': 'kpi-batched-capability-control-freeze/v1',
            'run_id': args.run_id, 'case': args.case, 'source_sha256': build['source_sha256'],
            'vendor_artifacts': build['vendor_artifacts'], 'reused_objects': build['reused_objects'],
            'binary_sha256': base.digest(args.binary), 'model_sha256': args.expected_model_sha256,
            'verifier_sha256': args.expected_verifier_sha256,
            'owner_helper_sha256': build['owner_client']['sha256'],
            'resources': {'memory_max_bytes': int(memory), 'cpu_max': cpu},
            'public_fixture_assignment': [1, 128, 3, 5, 15], 'trace_assertions': 2,
            'scope': 'PUBLIC synthetic capability lifecycle controls; no owner-input/payment/privacy claim',
            'raw_diagnostics_or_TLS_private_keys_read_or_hashed': False}
        base.write_json(self.public / 'SOURCE-AND-CONTROL-FREEZE.json', result)
        return result

    def execute(self):
        freeze = self.freeze()
        keys, certificates, _ = self.certificates()
        network = port_block()
        for party in range(3):
            command = ['/app/mpc-fullproof', 'control', str(party), str(network),
                '/app/model.txt', self.args.expected_model_sha256, self.args.case,
                self.args.run_id, '/app/verifier', self.args.expected_verifier_sha256, '/work/result']
            argv, work = self.role_command('P' + str(party), keys, certificates, command)
            self.launch('P' + str(party), argv, work)
        while True:
            results = []
            for party in range(3):
                path = self.root / f'P{party}/result/PUBLIC-RESULT.json'
                try:
                    results.append(json.loads(path.read_text()))
                except (FileNotFoundError, json.JSONDecodeError):
                    results.append(None)
            if any(result is not None and result.get('status') != 'PASS' for result in results):
                raise RuntimeError('actual capability control reported failure')
            if any(process.poll() not in (None, 0) for process in self.processes.values()):
                raise RuntimeError('actual capability control exited without successful typed result')
            if all(results):
                break
            if all(process.poll() is not None for process in self.processes.values()):
                raise RuntimeError('actual capability control finished without every typed result')
            time.sleep(0.1)
        for process in self.processes.values():
            if process.wait() != 0:
                raise RuntimeError('typed control result followed by process failure')
        expected_proof = self.args.case in PROOF_CASES
        expected_issued = self.args.case not in SHAPE_CASES | INVALID_CASES | COIN_FAULT_CASES
        expected_epoch = 0 if self.args.case in {'valid', 'caller-mutation'} else 1
        for party, result in enumerate(results):
            category = 'expected-case-complete'
            if self.args.case in COIN_FAULT_CASES:
                category = 'malicious-role-sent' if party == 0 else (
                    'canonical-peer-contribution-refused' if self.args.case == 'malformed-contribution'
                    else 'commitment-opening-refused')
            if result.get('schema') != 'kpi-batched-capability-control/v1' or \
               result.get('party') != party or result.get('case') != self.args.case or \
               result.get('status') != 'PASS' or result.get('category') != category or \
               result.get('capability_issued') is not expected_issued or \
               result.get('independent_proof_verified') is not expected_proof or \
               result.get('owner_input_or_financial_claim') is not False or \
               result.get('raw_diagnostics_or_TLS_private_keys_read') is not False or \
               result.get('failure_epoch') != expected_epoch:
                raise RuntimeError('actual capability control typed contract mismatch')
            expected_events = int(expected_proof)
            for event in ['authenticated-H-map-started', 'masked-A-and-B1-MAC-checked',
                          'final-B2-and-C-MAC-checked']:
                if result['events'].get(event, 0) != expected_events:
                    raise RuntimeError('capability refusal had unexpected H/proof events')
            if self.args.case == 'different-context-generation' and \
               result['context_generation_before'] == result['context_generation_after']:
                raise RuntimeError('context reuse did not get a fresh generation')
            if expected_proof and result['check_counter_after'] <= result['check_counter_before']:
                raise RuntimeError('healthy proof checks did not advance')
            if not expected_proof and result['proof_hex']:
                raise RuntimeError('non-proof control exported a proof')
        validations = []
        for party in range(3):
            path = self.root / f'P{party}/result/PUBLIC-VALIDATION.json'
            if self.args.case in COIN_FAULT_CASES:
                if path.exists() or results[party]['events'].get('batched-coin-agreed', 0) != 0 or \
                   results[party]['events'].get('fault-test-coin-started', 0) != 1:
                    raise RuntimeError('coin fault reached production validation or lacked fault phase')
                continue
            receipt = json.loads(path.read_text())
            shape = self.args.case in SHAPE_CASES
            invalid = self.args.case in INVALID_CASES
            state = 'Aborted' if shape or invalid else 'PrivateZeroTestPassed'
            if receipt.get('schema') != 'kpi-batched-validation-public/v1' or \
               receipt.get('attempt') != self.args.run_id or receipt.get('state') != state or \
               receipt.get('residual_count') != (0 if shape else 6) or \
               receipt.get('private_residuals_or_Z_or_shares_exported') is not False or \
               (shape and receipt.get('public_challenge') != '') or \
               (not shape and not canonical_coin(receipt.get('public_challenge'))):
                raise RuntimeError('capability control validation receipt mismatch')
            validations.append(receipt)
            base.write_json(self.public / f'P{party}-PUBLIC-VALIDATION.json', receipt)
        if validations and (len({v['public_challenge'] for v in validations}) != 1 or \
           len({v['binding_sha256'] for v in validations}) != 1):
            raise RuntimeError('capability control validation parties disagree')
        if self.args.case == 'repeat-validation-attempt':
            for party in range(3):
                path = self.root / f'P{party}/result/PUBLIC-REPEATED-VALIDATION.json'
                repeated = json.loads(path.read_text())
                if repeated.get('schema') != 'kpi-batched-validation-public/v1' or \
                   repeated.get('state') != 'Aborted' or repeated.get('attempt') != self.args.run_id or \
                   repeated.get('residual_count') != 0 or repeated.get('public_challenge') != '' or \
                   repeated.get('private_residuals_or_Z_or_shares_exported') is not False:
                    raise RuntimeError('repeated attempt did not abort before a new coin')
                base.write_json(self.public / f'P{party}-PUBLIC-REPEATED-VALIDATION.json', repeated)
        verifier_checks = []
        if expected_proof:
            if len({result['proof_hex'] for result in results}) != 1:
                raise RuntimeError('capability control complete proofs disagree')
            proof = bytes.fromhex(results[0]['proof_hex'])
            if len(proof) != 128:
                raise RuntimeError('capability control proof is not Native128')
            public_proof = self.public / 'completed-proof.bin'
            public_proof.write_bytes(proof)
            for value, expected in [('128', 0), ('129', 1)]:
                with (self.private / ('verify-' + value + '.stdout')).open('xb') as out, \
                     (self.private / ('verify-' + value + '.stderr')).open('xb') as err:
                    code = subprocess.run([str(self.args.verifier), 'verify', str(self.args.model),
                        str(public_proof), value, self.args.expected_model_sha256], stdout=out, stderr=err).returncode
                verifier_checks.append({'public_input': value, 'exit': code, 'expected_exit': expected})
                if code != expected:
                    raise RuntimeError('capability control independent verifier mismatch')
        elif any((self.root / f'P{i}/result/verified-control-proof.bin').exists() for i in range(3)):
            raise RuntimeError('non-proof control created a proof candidate')
        for name, expected in freeze['source_sha256'].items():
            if base.digest(SOURCE / name) != expected:
                raise RuntimeError('selected control source changed during run')
        for artifact in freeze['vendor_artifacts'] + freeze['reused_objects']:
            if base.digest(Path(artifact['path'])) != artifact['sha256']:
                raise RuntimeError('selected control artifact changed during run')
        for path, key in [(self.args.binary, 'binary_sha256'), (self.args.model, 'model_sha256'),
                          (self.args.verifier, 'verifier_sha256'), (self.args.owner_client, 'owner_helper_sha256')]:
            if base.digest(path) != freeze[key]:
                raise RuntimeError('selected control runtime changed during run')
        result = {'schema': 'kpi-batched-capability-control-run/v1', 'status': 'PASS',
            'run_id': self.args.run_id, 'case': self.args.case, 'parties': results,
            'public_validation_receipts': validations, 'independent_verifier_controls': verifier_checks,
            'public_fixture_only': True, 'owner_input_or_financial_claim': False,
            'raw_diagnostics_or_TLS_private_keys_read_or_hashed': False}
        base.write_json(self.public / 'RESULT.json', result)
        return result


def main():
    parser = argparse.ArgumentParser()
    for name in ['binary', 'verifier', 'model', 'vendor-root', 'output-parent']:
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--expected-model-sha256', required=True)
    parser.add_argument('--expected-verifier-sha256', required=True)
    parser.add_argument('--case', required=True, choices=CASES)
    parser.add_argument('--run-id')
    parser.add_argument('--inside-scope', action='store_true')
    args = parser.parse_args()
    args.run_id = args.run_id or secrets.token_hex(32)
    if len(args.run_id) != 64 or any(c not in '0123456789abcdef' for c in args.run_id):
        raise SystemExit('fresh canonical run identity required')
    for name in ['binary', 'verifier', 'model', 'vendor_root', 'output_parent']:
        setattr(args, name, getattr(args, name).resolve())
    build = json.loads((args.binary.parent / 'BUILD-RESULT.json').read_text())
    args.owner_client = Path(build['owner_client']['path'])
    if not args.inside_scope:
        command = ['systemd-run', '--user', '--scope', '--quiet', '--collect',
            '--unit', 'kpi-batched-capability-' + args.run_id,
            '-p', 'MemoryMax=6G', '-p', 'CPUQuota=400%', sys.executable,
            str(Path(__file__).resolve()), *sys.argv[1:], '--run-id', args.run_id, '--inside-scope']
        raise SystemExit(subprocess.run(command).returncode)
    os.umask(0o077)
    attempt = Attempt(args)
    try:
        result = attempt.execute()
        print(json.dumps({'run_id': args.run_id, 'case': args.case, 'status': result['status'],
                          'public_result': str(attempt.public / 'RESULT.json')}), flush=True)
    except BaseException as error:
        base.write_json(attempt.public / 'FAILED.json', {'schema': 'kpi-batched-capability-control-failure/v1',
            'run_id': args.run_id, 'case': args.case, 'controller_error': str(error),
            'role_exit_statuses_before_cleanup': {name: process.poll() for name, process in attempt.processes.items()},
            'raw_diagnostics_or_TLS_private_keys_read_or_hashed': False})
        raise
    finally:
        attempt.stop_owned()
        base.write_json(attempt.public / 'COMMANDS.json', attempt.commands)


if __name__ == '__main__':
    main()
