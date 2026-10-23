#!/usr/bin/env python3
"""Execute reviewed, unfunded native bodies with already generated new proofs.

No proving key, setup, prover, node, broadcast interface or prior live identity.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

import assemble as a


def validate_freeze(args, proofs=False):
    freeze = a.load(args.freeze)
    if (freeze.get('classification') != a.CLASS or freeze.get('runtime_authorized') is not True
            or freeze.get('scope') != 'UNFUNDED_PRIVATE_EXIT_LIFECYCLE'):
        raise ValueError('reviewed source/input runtime release required')
    seen = set()
    for item in freeze['files']:
        path = Path(item['path'])
        path = path if path.is_absolute() else a.ROOT / path
        path = path.resolve(strict=True)
        raw = path.read_bytes()
        if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
            raise ValueError('frozen source or input changed: ' + str(path))
        seen.add(path)
    required = {Path(__file__).resolve(), Path(a.__file__).resolve(), args.native.resolve(),
                (args.prepared / 'MATERIALIZED.json').resolve(),
                (args.prepared / 'records.json').resolve()}
    required.update((args.prepared / (stage + '-native-vector.json')).resolve()
                    for stage in ('funding-prep', 'founding', 'admit', *a.STAGES))
    required.update((args.prepared / (stage + '-fixture.json')).resolve() for stage in a.STAGES)
    materialized = a.load(args.prepared / 'MATERIALIZED.json')
    for stage in materialized['stages']:
        directory = Path(stage['body_directory']).resolve()
        if args.prepared.resolve() not in directory.parents:
            raise ValueError('prepared unsigned body escaped selected materialization')
        required.update((directory / filename).resolve() for filename in
                        ('transaction.json', 'supplied-context.json', 'metrics.json', 'txid-raw.hex'))
    if proofs:
        required.add(args.crypto.resolve())
        required.add((args.prepared / 'PUBLIC-SYNTHETIC-backups.json').resolve())
        required.add(args.setup_report.resolve())
        required.add((args.prefix / 'PREFIX-RESULTS.json').resolve())
        for name in ('lib.rs', 'circuit.rs', 'exact_sha256.rs', 'fixture.rs', 'main.rs'):
            required.add((args.proof_source / name).resolve())
        for stage in ('funding-prep', 'founding', 'admit'):
            required.update((args.prefix / stage / filename).resolve() for filename in
                            ('transaction.json', 'supplied-context.json', 'native-validation.json'))
        for stage in a.STAGES:
            required.update((args.proof_root / stage / filename).resolve() for filename in
                            ('report.json', 'proof128.bin', 'verification-key.bin', 'authorization528.bin'))
    if not required <= seen:
        raise ValueError('freeze omitted required source/statement/proof artifact')
    return a.digest(args.freeze)


def prefix(args):
    frozen = validate_freeze(args)
    if args.output.exists():
        raise ValueError('fresh prefix output required')
    args.output.mkdir(parents=True)
    for stage in ('funding-prep', 'founding', 'admit'):
        vector = a.load(args.prepared / (stage + '-native-vector.json'))
        a.native_call(args.native, stage + '-run', vector, args.output / stage)
    links = [a.verify_link(args.output / 'funding-prep', args.output / 'founding'),
             a.verify_link(args.output / 'founding', args.output / 'admit'),
             a.verify_link(args.output / 'funding-prep', args.output / 'admit', 1, 1)]
    prepared = a.load(args.prepared / 'MATERIALIZED.json')
    if a.outpoint(args.output / 'admit') != a.outpoint(Path(prepared['admit_body_directory'])):
        raise ValueError('actual prefix differs from prepared proof prior outpoint')
    result = {'classification': a.CLASS, 'passed': True, 'native_Full_operations': 3,
              'source_input_freeze_sha256': frozen, 'links': links, 'accepted_chain_backing': False}
    a.save(args.output / 'PREFIX-RESULTS.json', result)
    validate_freeze(args)
    return result


def checked_setup(args, prepared):
    report = a.load(args.setup_report)
    source = report['source_identity']
    if (report.get('classification') != a.CLASS
            or report.get('schema') != 'kpx3-private-action-new-setup/v1'
            or report.get('existing_PK_or_matrix_loaded') is not False
            or source['domain_hex32'] != a.DOMAIN.hex()
            or report['vk_sha256'] != prepared['vk_sha256']
            or hashlib.sha256(a.exact(report['vk_hex328'], 328)).hexdigest() != prepared['vk_sha256']):
        raise ValueError('selected fresh setup/domain/VK identity mismatch')
    names = {'lib_rs_sha256': 'lib.rs', 'circuit_rs_sha256': 'circuit.rs',
             'exact_sha256_rs_sha256': 'exact_sha256.rs', 'fixture_rs_sha256': 'fixture.rs',
             'main_rs_sha256': 'main.rs'}
    for field, filename in names.items():
        if a.digest(args.proof_source / filename) != source[field]:
            raise ValueError('selected reviewed proof core source mismatch')
    return report


def checked_proof(prepared, proof_root, stage, vector, setup):
    directory = proof_root / stage
    report = a.load(directory / 'report.json')
    proof = (directory / 'proof128.bin').read_bytes()
    vk = (directory / 'verification-key.bin').read_bytes()
    auth = bytes.fromhex(a.load(prepared / (stage + '-fixture.json'))['auth_hex528'])
    if (len(proof) != 128 or len(vk) != 328 or report.get('genuine_Groth16_verified') is not True
            or report.get('existing_PK_or_matrix_loaded') is not False
            or report['source_identity'] != setup['source_identity']
            or report['fixture_sha256'] != a.digest(prepared / (stage + '-fixture.json'))
            or report['authorization_sha256'] != hashlib.sha256(auth).hexdigest()
            or report['proof_sha256'] != hashlib.sha256(proof).hexdigest()
            or report['vk_sha256'] != hashlib.sha256(vk).hexdigest()
            or vk.hex() != vector['vk_hex'] or auth.hex() != vector['auth_hex']
            or (directory / 'authorization528.bin').read_bytes() != auth):
        raise ValueError('genuine proof/Auth/fixture/new-domain/VK identity mismatch: ' + stage)
    return proof


def execute(args):
    frozen = validate_freeze(args, proofs=True)
    if args.output.exists():
        raise ValueError('fresh action execution output required')
    args.output.mkdir(parents=True)
    prepared = a.load(args.prepared / 'MATERIALIZED.json')
    setup = checked_setup(args, prepared)
    prefix_result = a.load(args.prefix / 'PREFIX-RESULTS.json')
    if prefix_result.get('passed') is not True or prefix_result['native_Full_operations'] != 3:
        raise ValueError('validated native prefix required')
    links = [a.verify_link(args.prefix / 'funding-prep', args.prefix / 'founding'),
             a.verify_link(args.prefix / 'founding', args.prefix / 'admit'),
             a.verify_link(args.prefix / 'funding-prep', args.prefix / 'admit', 1, 1)]
    if links != prefix_result['links']:
        raise ValueError('frozen prefix links differ from actual body/context files')
    for stage in ('funding-prep', 'founding', 'admit'):
        report = a.load(args.prefix / stage / 'native-validation.json')
        body = a.load(args.prefix / stage / 'transaction.json')
        entries = a.load(args.prefix / stage / 'supplied-context.json')
        engines = report.get('per_input_ScriptEngine', [])
        actual_fee = sum(row['amount_sompi'] for row in entries) - sum(row['value'] for row in body['outputs'])
        if (report['Full'].get('accepted') is not True
                or report['Full']['fee_sompi'] != actual_fee
                or prepared['fees_sompi'][stage] != actual_fee
                or report.get('all_input_engines_accepted') is not True
                or len(engines) != len(body['inputs'])
                or any(row.get('accepted') is not True for row in engines)):
            raise ValueError('frozen prefix Full/all-engine evidence mismatch')
    previous = args.prefix / 'admit'
    snapshots = a.load(args.prepared / 'records.json')
    snapshot_names = {'spend': 'after-spend', 'bob-partial': 'after-bob-partial',
                      'bob-full': 'after-bob-full', 'charlie-terminal': 'terminal'}
    payouts, stages = {}, []
    for stage, frozen_stage in zip(a.STAGES, prepared['stages']):
        if frozen_stage['stage'] != stage:
            raise ValueError('materialized action order')
        vector = a.load(args.prepared / (stage + '-native-vector.json'))
        proof = checked_proof(args.prepared, args.proof_root, stage, vector, setup)
        vector['proof_hex'] = proof.hex()
        directory = args.output / stage
        a.native_call(args.native, 'private-run', vector, directory)
        links.append(a.verify_link(previous, directory))
        expected = copy.deepcopy(a.load(Path(frozen_stage['body_directory']) / 'transaction.json'))
        script = bytes.fromhex(expected['inputs'][0]['signatureScript'])
        if script[:68] != b'\x41' + bytes(65) + b'\x4c\x80' or script[196] != 0x4d:
            raise ValueError('prepared private witness framing')
        expected['inputs'][0]['signatureScript'] = (script[:68] + proof + script[196:]).hex()
        actual = a.load(directory / 'transaction.json')
        if actual != expected:
            raise ValueError('genuine proof changed another authorized native body field')
        auth = bytes.fromhex(vector['auth_hex'])
        snapshot = a.parse_snapshot(snapshots[snapshot_names[stage]])
        if auth[364:476] != a.state(snapshot):
            raise ValueError('derived public successor state differs from proof authorization')
        remaining = int.from_bytes(auth[476:484], 'little')
        payout = int.from_bytes(auth[484:492], 'little')
        actual_fee = int.from_bytes(auth[196:204], 'little')
        if (prepared['fees_sompi'][stage] != actual_fee
                or frozen_stage['reserve_after_sompi'] != remaining
                or frozen_stage['payout_sompi'] != payout):
            raise ValueError('declared accounting differs from actual authorization')
        if remaining:
            if (actual['outputs'][0]['value'] != remaining
                    or a.exact((directory / 'successor-state.hex').read_text().strip(), 112) != a.state(snapshot)):
                raise ValueError('actual reserve successor mismatch')
        elif (directory / 'successor-state.hex').exists():
            raise ValueError('terminal emitted a stale successor-state file')
        if payout:
            index = 1 if remaining else 0
            output = actual['outputs'][index]
            if output['value'] != payout or output['scriptPublicKey'] != auth[492:528].hex():
                raise ValueError('actual native payout amount/destination mismatch')
            payouts[stage] = {'value_sompi': payout, 'transaction_id': actual['id'],
                              'index': index, 'script_public_key': output['scriptPublicKey']}
        if len(actual['outputs']) != (int(remaining > 0) + int(payout > 0)):
            raise ValueError('extra native output or terminal reserve survived')
        stages.append({'stage': stage, 'transaction_id': actual['id'], 'native_Full':
            a.load(directory / 'native-validation.json')['Full'], 'genuine_Groth16_verified': True,
            'reserve_after_sompi': remaining, 'payout_sompi': payout})
        previous = directory
    if stages[-1]['reserve_after_sompi'] != 0 or len(a.load(previous / 'transaction.json')['outputs']) != 1:
        raise ValueError('terminal reserve survived')
    terminal = a.parse_snapshot(snapshots['terminal'])
    crypto = a.Crypto(args.crypto)
    ws = a.wallets(crypto)
    owned = {label: a.recover(wallet, terminal.pin(a.DOMAIN), terminal).all_owned_unspent_sompi
             for label, wallet in ws.items()}
    if any(owned.values()):
        raise ValueError('recognized positive pool liability survived')
    source_change = a.load(args.prefix / 'funding-prep/transaction.json')['outputs'][2]['value']
    founding_change = a.load(args.prefix / 'founding/transaction.json')['outputs'][1]['value']
    fees = prepared['fees_sompi']
    if source_change + founding_change + sum(row['value_sompi'] for row in payouts.values()) + sum(fees.values()) != a.SOURCE_VALUE:
        raise ValueError('complete external source/change/payout/fee accounting mismatch')
    shared = sum(fees[stage] for stage in ('funding-prep', 'founding', 'admit', 'spend'))
    if shared % 2:
        raise ValueError('unexpected noninteger shared cost allocation')
    burdens = {'Bob': shared // 2 + fees['bob-partial'] + fees['bob-full'],
               'Charlie': shared // 2 + fees['charlie-terminal']}
    result = {'classification': a.CLASS, 'source_input_freeze_sha256': frozen,
        'complete_supplied_context_native_sequence_passed': True, 'native_Full_operations': 7,
        'genuine_private_proofs': 4, 'actual_prior_output_links_checked': len(links),
        'stages': stages, 'payouts': payouts, 'fees_sompi': fees, 'total_fees_sompi': sum(fees.values()),
        'source_sompi': a.SOURCE_VALUE, 'ordinary_source_change_sompi': source_change,
        'ordinary_founding_change_sompi': founding_change,
        'per_recipient_attributable_native_fee_sompi': burdens,
        'all_remaining_reserve_sompi': 0, 'all_remaining_positive_liability_sompi': 0,
        'recognized_owner_unspent_pool_sompi': owned, 'final_cm_count': len(terminal.deliveries),
        'final_nf_count': len(terminal.nullifiers), 'accepted_chain_backing': False,
        'testnet_broadcast_or_payout': False, 'privacy_qualified': False, 'fee_qualified': False,
        'p95_qualified': False, 'independent_recovery_demonstrated_here': False,
        'limits': ['Public synthetic secrets', 'Supplied funding/current-lineage/archive oracle',
                   'No independent network discovery or durable data proof', 'Direct verifier lifecycle fee gate fails']}
    a.save(args.output / 'actual-body-links.json', {'links': links})
    a.save(args.output / 'RESULTS.json', result)
    validate_freeze(args, proofs=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('prefix', 'execute'):
        p = sub.add_parser(name)
        p.add_argument('--native', type=Path, required=True)
        p.add_argument('--prepared', type=Path, required=True)
        p.add_argument('--freeze', type=Path, required=True)
        p.add_argument('--output', type=Path, required=True)
        if name == 'execute':
            p.add_argument('--prefix', type=Path, required=True)
            p.add_argument('--proof-root', type=Path, required=True)
            p.add_argument('--crypto', type=Path, required=True)
            p.add_argument('--setup-report', type=Path, required=True)
            p.add_argument('--proof-source', type=Path, required=True)
    args = parser.parse_args()
    result = prefix(args) if args.command == 'prefix' else execute(args)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
