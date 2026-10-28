#!/usr/bin/env python3
"""Independent public proof/native checks for released METHOD02 projections.

No private filesystem, Original, invoice, witness or proving key enters a tool
namespace. Fee1 is retained exactly; this does not claim relay-fee adequacy,
accepted UTXOs, GEN3 backing, settlement or financial readiness.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

from payout_linkage_guard import load_guard

read = load_guard()['read']

import exit_wire
import new_private_trial as bootstrap
import private_lifecycle as lifecycle
import private_worker as boundary
import payout_linkage_original as study


def canonical_hex(value, size):
    return (type(value) is str and len(value) == 2 * size
        and all(character in '0123456789abcdef' for character in value))


def canonical_uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def validate_exits(value):
    bootstrap.need(type(value) is dict and set(value) == {'schema', 'binding', 'arms'}
        and value['schema'] == 'kpb-method02-unlabelled-exits/v1', 'method02-exact-public-exits-schema')
    binding = value['binding']
    bootstrap.need(type(binding) is dict and set(binding) == {
        'method_sha256', 'selection_sha256', 'trial_id', 'phase', 'attempt_id'}
        and binding['method_sha256'] == study.METHOD_SHA
        and canonical_hex(binding['selection_sha256'], 32)
        and binding['phase'] == 'private-payout-linkage-02'
        and canonical_uuid(binding['trial_id']) and canonical_uuid(binding['attempt_id']),
        'method02-exact-canonical-public-binding')
    bootstrap.need(type(value['arms']) is dict and set(value['arms']) == {'A', 'B'}
        and all(type(rows) is list and len(rows) == 3 for rows in value['arms'].values()),
        'method02-six-explicit-public-exits')
    identifiers = []
    for arm in ('A', 'B'):
        for row in value['arms'][arm]:
            bootstrap.need(type(row) is dict and set(row) == {
                'projection_hex', 'proof_hex128', 'statement_hex152', 'exit_id'}
                and canonical_hex(row['projection_hex'], 1844)
                and canonical_hex(row['proof_hex128'], 128)
                and canonical_hex(row['statement_hex152'], 152)
                and canonical_hex(row['exit_id'], 32)
                and hashlib.sha256(bytes.fromhex(row['projection_hex'])).hexdigest() == row['exit_id'],
                'method02-exact-canonical-public-exit-row')
            identifiers.append(row['exit_id'])
    bootstrap.need(len(set(identifiers)) == 6, 'method02-six-distinct-public-exit-identifiers')


def without_caches(case):
    value = copy.deepcopy(case)
    for field in ('id', 'mass'):
        value['transaction'].pop(field, None)
    return value


def native_report_passed(report, returncode):
    return (returncode == 0 and type(report) is dict and report.get('isolation') == 'PASS'
        and type(report.get('Full')) is dict and report['Full'].get('accepted') is True
        and report.get('all_input_engines_accepted') is True
        and type(report.get('per_input_ScriptEngine')) is list
        and len(report['per_input_ScriptEngine']) == 1
        and all(type(item) is dict and item.get('accepted') is True
                for item in report['per_input_ScriptEngine']))


def tool(binary, payload=None, *, mounts=(), arguments=(), require_success=True):
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        '--ro-bind', str(binary), '/public/tool', *mounts, '--chdir', '/tmp',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '/public/tool', *arguments]
    result = subprocess.run(argv, input=None if payload is None else boundary.encoded(payload),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=bootstrap.CLEAN)
    if require_success:
        bootstrap.need(result.returncode == 0, 'method02-public-selected-tool-refused')
        return result.stdout
    return result


def verify(exits_path, exits_sha, output):
    value = boundary.parse(read(Path(exits_path).absolute(), exits_sha))
    validate_exits(value)
    output = bootstrap.checked(output)
    bootstrap.need(not output.exists(), 'method02-fresh-public-native-directory')
    output.mkdir(mode=0o700, parents=True)
    for binary, pin in ((study.CODEC, study.CODEC_SHA), (study.NATIVE, study.NATIVE_SHA),
                        (bootstrap.BINARY, bootstrap.BINARY_SHA)):
        read(binary, pin)
    parameters = boundary.parse(read(study.PARAMETERS, study.PARAMETERS_SHA))
    tail = read(study.TAIL, study.TAIL_SHA)
    manifest = lifecycle.EXIT_PARAMETERS / 'MANIFEST.json'
    read(manifest, lifecycle.EXIT_MANIFEST_SHA)
    records, spent = [], []
    for arm in ('A', 'B'):
        for row in value['arms'][arm]:
            projection = bytes.fromhex(row['projection_hex'])
            body = exit_wire.validate_public(projection)
            exit_wire.require_current_head(projection, body.context, tail)
            statement = exit_wire.statement(projection)
            bootstrap.need(row['exit_id'] == hashlib.sha256(projection).hexdigest()
                and statement.hex() == row['statement_hex152'] and len(bytes.fromhex(row['proof_hex128'])) == 128
                and body.fee == 1 and body.payout == 199_999_999 and body.context.reserve == 6_000_000_000
                and body.context.cm_count == 3 and body.context.nf_count == 1,
                'method02-exact-projection-statement-shape')
            spent.append(body.nf)
            proof_request = {'operation': 'verify', 'role': 'new-auth-exit',
                'profile': {'domain_hex32': body.context.domain.hex(), 'profile_id_hex32': body.context.profile.hex()},
                'statement_hex': statement.hex(), 'proof_hex128': row['proof_hex128'],
                'parameters': {'manifest': '/parameters/MANIFEST.json', 'manifest_sha256': lifecycle.EXIT_MANIFEST_SHA}}
            verified = boundary.parse(tool(bootstrap.BINARY, proof_request,
                mounts=['--ro-bind', str(manifest), '/parameters/MANIFEST.json']))
            bootstrap.need(verified['accepted'] is True, 'method02-independent-public-AuthExit-verifier')
            emitted = boundary.parse(tool(study.CODEC, {'operation': 'emit', 'parameters': parameters,
                                                       'state_hex112': body.context.state().hex()}))
            redeem = bytes.fromhex(emitted['redeem_hex'])
            bootstrap.need(redeem == b'\x4c\x70' + body.context.state() + tail, 'method02-exact-selected-redeem')
            script = b'\x4c\x80' + bytes.fromhex(row['proof_hex128']) + b'\x4d' + len(redeem).to_bytes(2, 'little') + redeem
            outputs = exit_wire.parse_projection(projection)[2]
            case = {'transaction': {'version': 1, 'id': '00' * 32,
                'inputs': [{'previousOutpoint': {'transactionId': body.context.point[:32].hex(),
                    'index': int.from_bytes(body.context.point[32:], 'little')},
                    'signatureScript': script.hex(), 'sequence': (1 << 64) - 1, 'computeBudget': 1800}],
                'outputs': [{'value': amount, 'scriptPublicKey': spk.hex(), 'covenant': None} for amount, spk in outputs],
                'lockTime': 0, 'subnetworkId': '00' * 20, 'gas': 0, 'payload': body.raw.hex(), 'mass': 0},
                'entries': [{'amount': body.context.reserve, 'scriptPublicKey': emitted['script_public_key'],
                    'blockDaaScore': 0, 'isCoinbase': False, 'covenantId': None}]}
            normalized = boundary.parse(tool(study.CODEC, {'operation': 'normalize', 'parameters': parameters, 'case': case}))
            bootstrap.need(normalized['financial_projection_hex'] == projection.hex()
                and normalized['exit_statement_hex152'] == statement.hex()
                and boundary.encoded(without_caches(normalized['case'])) == boundary.encoded(without_caches(case)),
                'method02-native-normalizer-only-cached-id-and-mass')
            destination = output / row['exit_id']; destination.mkdir(mode=0o700)
            case_path = destination / 'CASE.json'
            case_sha = bootstrap.save(case_path, normalized['case'])
            native_out = destination / 'actual-native'
            native_process = tool(study.NATIVE,
                mounts=['--ro-bind', str(case_path), str(case_path), '--bind', str(destination), str(destination)],
                arguments=['validate-transaction', str(case_path), str(native_out)], require_success=False)
            report_path = native_out / 'native-validation.json'
            report_raw = read(report_path) if report_path.exists() else None
            report, report_error = None, None
            if report_raw is None:
                report_error = 'selected-native-report-missing'
            else:
                try:
                    report = boundary.parse(report_raw)
                except (ValueError, TypeError):
                    report_error = 'selected-native-report-malformed'
            native_passed = native_report_passed(report, native_process.returncode)
            records.append({'arm': arm, 'exit_id': row['exit_id'], 'public_AuthExit_verified': True,
                'case': {'path': str(case_path), 'sha256': case_sha}, 'native_report': {'path': str(report_path),
                'sha256': None if report_raw is None else hashlib.sha256(report_raw).hexdigest(),
                'actual_result': report, 'report_error': report_error},
                'native_Full_all_input_engines': native_passed,
                'native_process': {'returncode': native_process.returncode,
                    'stdout_sha256': hashlib.sha256(native_process.stdout).hexdigest(),
                    'stderr_sha256': hashlib.sha256(native_process.stderr).hexdigest()},
                'mining_mass': normalized['metrics']['mining_mass'], 'fee_sompi': 1,
                'relay_fee_adequacy_claim': False})
    bootstrap.need(len(set(spent)) == 6, 'method02-independent-note-NFs-across-main-arms')
    passed = len(records) == 6 and all(row['native_Full_all_input_engines'] for row in records)
    result = {'schema': 'kpb-method02-public-native-verification/v1', 'binding': value['binding'],
        'exits_sha256': exits_sha, 'records': records, 'all_six_actual_checks_passed': passed,
        'classification': 'SIX_INDIVIDUAL_UNFUNDED_SUPPLIED_CONTEXTS_NOT_AN_ACCEPTED_LEDGER',
        'selected_native_parameters_sha256': study.PARAMETERS_SHA,
        'selected_AuthExit_manifest_sha256': lifecycle.EXIT_MANIFEST_SHA,
        'private_body_or_key_read': False, 'accepted_backing_chain_or_fee_adequacy': False}
    pin = bootstrap.save(output / 'RESULT.json', result)
    return {'result': str(output / 'RESULT.json'), 'sha256': pin,
        'actual_public_native_checks': len(records), 'actual_checks_passed': passed}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exits', required=True); parser.add_argument('--exits-sha256', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.exits, args.exits_sha256, args.output), sort_keys=True))


if __name__ == '__main__':
    main()
