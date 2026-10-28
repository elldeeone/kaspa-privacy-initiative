#!/usr/bin/env python3
"""One isolated actual-MPC PUBLIC-fixture H-map/packed proof differential.

Reads only typed sidecars and explicitly public build/fixture/codec artifacts.
Never reads or hashes worker diagnostics, private TLS keys or private inputs.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('packed_isolated_base', SOURCE / 'run_toy.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class Attempt(base.Attempt):
    def execute(self):
        args = self.args
        build_path = args.binary.parent / 'BUILD-RESULT.json'
        build = json.loads(build_path.read_text())
        if not build['success'] or base.digest(args.binary) != build['binary_sha256']:
            raise RuntimeError('selected packed differential build mismatch')
        selected = [(SOURCE / name, expected) for name, expected in build['source_sha256'].items()]
        selected += [(Path(item['path']), item['sha256']) for item in build['vendor_artifacts']]
        selected += [(Path(item['path']), item['sha256']) for item in build['reused_objects']]
        for name, expected in build['fixture_sha256'].items():
            selected.append((args.packed / name, expected))
        selected += [(args.verifier, args.expected_verifier_sha256),
                     (args.model, args.expected_model_sha256)]
        for path, expected in selected:
            if base.digest(path) != expected:
                raise RuntimeError('selected public differential source/artifact changed')
        freeze = {'schema': 'kpi-packed-witness-map-control-freeze/v1',
            'run_id': args.run_id, 'build_sha256': base.digest(build_path),
            'resources': base.selected_resources(args.run_id),
            'source_sha256': build['source_sha256'], 'fixture_sha256': build['fixture_sha256'],
            'known_public_assignment': [1, 128, 3, 5, 15],
            'actual_secret_owner_inputs': False, 'financial_qualification': False}
        base.write_json(self.public / 'FREEZE.json', freeze)
        keys, certificates, _ = self.certificates()
        network = base.port_block()
        for party in range(3):
            command = ['/app/mpc-fullproof', 'control', str(party), str(network), '/app/model.txt',
                args.expected_model_sha256, 'valid', args.run_id, '/app/verifier',
                args.expected_verifier_sha256, '/work/result']
            argv, work = self.role_command('P' + str(party), keys, certificates, command)
            argv[-len(command):-len(command)] = ['--ro-bind', str(args.packed), '/app/packed']
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
                raise RuntimeError('typed packed witness-map control refused')
            if any(process.poll() not in (None, 0) for process in self.processes.values()):
                raise RuntimeError('packed witness-map role exited without successful typed result')
            if all(results):
                break
            if all(process.poll() is not None for process in self.processes.values()):
                raise RuntimeError('packed witness-map role omitted typed result')
            time.sleep(0.1)
        for process in self.processes.values():
            if process.wait() != 0:
                raise RuntimeError('typed control followed by process failure')
        for party, result in enumerate(results):
            if result.get('schema') != 'kpi-packed-witness-map-control/v1' or \
               result.get('party') != party or result.get('attempt') != args.run_id or \
               result.get('H_coefficients_checked') != 4 or result.get('H_exact_Ark_match') is not True or \
               result.get('proof_bytes') != 128 or result.get('residuals') != 6 or \
               result.get('nonempty_private_assertion_count') != 2 or \
               result.get('group_MAC_opening_pairs') != 2 or \
               result.get('all_public_fixture_only') is not True or \
               result.get('private_owner_input_read') is not False or result.get('financial_qualified') is not False:
                raise RuntimeError('packed differential typed control contract mismatch')
            base.write_json(self.public / f'P{party}-PUBLIC-RESULT.json', result)
        if len({result['complete_proof_hex'] for result in results}) != 1:
            raise RuntimeError('packed differential proofs disagree')
        proof = bytes.fromhex(results[0]['complete_proof_hex'])
        if len(proof) != 128:
            raise RuntimeError('packed differential proof width')
        proof_path = self.public / 'completed-proof.bin'
        proof_path.write_bytes(proof)
        checks = []
        for value, expected in [('128', 0), ('129', 1)]:
            with (self.private / ('verify-' + value + '.stdout')).open('xb') as out, \
                 (self.private / ('verify-' + value + '.stderr')).open('xb') as err:
                code = subprocess.run([str(args.verifier), 'verify', str(args.model), str(proof_path),
                    value, args.expected_model_sha256], stdout=out, stderr=err).returncode
            if code != expected:
                raise RuntimeError('packed differential independent Ark proof check failed')
            checks.append({'public_input': value, 'exit': code, 'expected_exit': expected})
        for path, expected in selected:
            if base.digest(path) != expected:
                raise RuntimeError('selected differential source/artifact changed during execution')
        result = {'schema': 'kpi-packed-witness-map-control-run/v1', 'status': 'PASS',
            'run_id': args.run_id, 'parties': results, 'independent_Ark_controls': checks,
            'proof_sha256': base.digest(proof_path), 'financial_qualified': False,
            'raw_worker_diagnostics_or_private_TLS_keys_read_or_hashed': False}
        base.write_json(self.public / 'RESULT.json', result)
        return result


def main():
    parser = argparse.ArgumentParser()
    for name in ['binary', 'verifier', 'model', 'vendor-root', 'output-parent', 'packed']:
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--expected-model-sha256', required=True)
    parser.add_argument('--expected-verifier-sha256', required=True)
    parser.add_argument('--run-id')
    parser.add_argument('--inside-scope', action='store_true')
    args = parser.parse_args()
    args.run_id = args.run_id or secrets.token_hex(32)
    if len(args.run_id) != 64 or any(c not in '0123456789abcdef' for c in args.run_id):
        raise SystemExit('fresh canonical run identity required')
    for name in ['binary', 'verifier', 'model', 'vendor_root', 'output_parent', 'packed']:
        setattr(args, name, getattr(args, name).resolve())
    build = json.loads((args.binary.parent / 'BUILD-RESULT.json').read_text())
    args.owner_client = Path(build['owner_client']['path'])
    if not args.inside_scope:
        command = ['systemd-run', '--user', '--scope', '--quiet', '--collect',
            '--unit', 'kpi-mascot-toy-' + args.run_id, '-p', 'MemoryMax=6G', '-p', 'CPUQuota=400%',
            sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], '--run-id', args.run_id, '--inside-scope']
        raise SystemExit(subprocess.run(command).returncode)
    os.umask(0o077)
    attempt = Attempt(args)
    try:
        result = attempt.execute()
        print(json.dumps({'status': result['status'], 'run_id': args.run_id,
            'public_result': str(attempt.public / 'RESULT.json')}), flush=True)
    except BaseException:
        base.write_json(attempt.public / 'FAILED.json', {'schema': 'kpi-packed-witness-map-failure/v1',
            'run_id': args.run_id, 'role_exit_codes': {k: p.poll() for k, p in attempt.processes.items()},
            'raw_worker_diagnostics_or_private_TLS_keys_read_or_hashed': False})
        raise
    finally:
        attempt.stop_owned()
        base.write_json(attempt.public / 'COMMANDS.json', attempt.commands)


if __name__ == '__main__':
    main()
