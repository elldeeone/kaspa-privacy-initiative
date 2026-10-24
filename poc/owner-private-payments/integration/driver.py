#!/usr/bin/env python3
"""Trusted public-data glue. Owner files are metadata exclusions, never inputs.

This launcher is not the untrusted coordinator. The construction backend starts
that separate public-IPC-only namespace. Never publish invocation handles.
"""
import argparse
import importlib.util
from pathlib import Path
import secrets
import subprocess
import sys

from public import (CLASSIFICATION, DOMAIN, attach_spend_proofs, body_core, genesis,
                    hx, mixed_rows, need, parse_genesis, premix_context, project, sha, wire)

CONSTRUCTION = Path(__file__).resolve().parents[1] / 'construction'
sys.path.insert(0, str(CONSTRUCTION))
from backend import PublicGuard, fresh, write
from codec import Q, canonical_json, parse_json, session
from commands import isolated_assembly
from operations import created_public, invoke_construction, invoke_owner, native_projection


def read(guard, selector, json_value=True):
    raw = guard.read(selector[0], selector[1])
    return parse_json(raw) if json_value else raw


def save(root, name, raw):
    raw = canonical_json(raw) if type(raw) is dict else raw
    write(root / name, raw)
    return {'file': name, 'bytes': len(raw), 'sha256': sha(raw).hex()}


def initial_public(value, position):
    need(type(value) is dict and set(value) == {'schema', 'domain_hex32', 'participant_id_hex32',
         'initial_cm_hex32', 'initial_position', 'admission_sompi'} and
         value['schema'] == 'kpx7-unfunded-owner-public/v1' and value['domain_hex32'] == DOMAIN.hex()
         and type(value['initial_position']) is int and value['initial_position'] == position,
         'exact-public-owner-init-export')
    hx(value['participant_id_hex32'], 32); hx(value['initial_cm_hex32'], 32)
    need(type(value['admission_sompi']) is int and
         wire.NOTE_FLOOR <= value['admission_sompi'] <= wire.MAX_VALUE, 'public-admission-range')
    return value


def ready_public(value, owner, sid):
    keys = {'schema', 'participant_id_hex32', 'session_sha256', 'input_cm_hex32', 'nf_hex32',
            'cv_hex64', 'own_output_count', 'mpc_input_written', 'financial_authorization'}
    need(type(value) is dict and set(value) == keys and value['schema'] == 'kpx7-owner-input-ready/v1'
         and value['participant_id_hex32'] == owner['participant_id_hex32']
         and value['session_sha256'] == sid and value['input_cm_hex32'] == owner['initial_cm_hex32']
         and type(value['own_output_count']) is int and value['own_output_count'] == 2
         and value['mpc_input_written'] is True and value['financial_authorization'] is False,
         'exact-own-input-public-ready-export')
    return hx(value['nf_hex32'], 32), hx(value['cv_hex64'], 64)


def owners_public(value):
    need(type(value) is dict and set(value) == {'schema', 'owners', 'classification'} and
         value['schema'] == 'kpx7-public-owner-registry/v1' and value['classification'] == CLASSIFICATION
         and type(value['owners']) is list and len(value['owners']) == 3,
         'exact-public-owner-registry')
    rows = [initial_public(owner, i) for i, owner in enumerate(value['owners'])]
    need(len({row['participant_id_hex32'] for row in rows}) == 3, 'three-distinct-owner-identities')
    return rows


def authorize_public(value, projection, index):
    parsed = wire.validate_public(projection)
    body = wire.parse_projection(projection).body
    keys = {'schema', 'session_sha256', 'effects_digest_hex32', 'nf_hex32', 'cv_hex64',
            'statement_hex200', 'proof_hex128'}
    need(type(value) is dict and set(value) == keys and
         value['schema'] == 'kpx7-owner-spend-authorization/v1' and
         value['session_sha256'] == body.session.hex() and
         value['effects_digest_hex32'] == parsed['effects_digest_hex32'], 'exact-public-Spend-authorization')
    spend = body.spends[index]
    statement = (b'KPX7SP01' + DOMAIN + body.old_state.cm_root + spend.nf + spend.cv
                 + hx(parsed['effects_digest_hex32'], 32))
    need(hx(value['nf_hex32'], 32) == spend.nf and hx(value['cv_hex64'], 64) == spend.cv
         and hx(value['statement_hex200'], 200) == statement,
         'owner-Spend-proof-exact-complete-effects-statement')
    return hx(value['proof_hex128'], 128)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('op', choices=('genesis', 'context', 'session', 'build', 'project', 'native-project', 'finalize', 'verify',
                                      'owner-init', 'owner-prepare', 'owner-authorize', 'mpc-prepare', 'mpc-run'))
    parser.add_argument('--exclude-private-root', action='append', required=True)
    parser.add_argument('--exclude-owner-private-directory', action='append', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--owner-public', nargs=2, action='append')
    parser.add_argument('--owners', nargs=2); parser.add_argument('--genesis', nargs=2)
    parser.add_argument('--session', nargs=2); parser.add_argument('--mixed', nargs=2)
    parser.add_argument('--ready', nargs=2, action='append')
    parser.add_argument('--component-profile-sha256'); parser.add_argument('--effects-context-sha256')
    parser.add_argument('--program-sha256'); parser.add_argument('--session-id')
    parser.add_argument('--point-hex36'); parser.add_argument('--fee-sompi', type=int)
    parser.add_argument('--body', nargs=2); parser.add_argument('--projection', nargs=2)
    parser.add_argument('--input-spk-hex37'); parser.add_argument('--output-spk-hex37')
    parser.add_argument('--spend-public', nargs=2, action='append')
    parser.add_argument('--execute', action='store_true'); parser.add_argument('--party', type=int)
    parser.add_argument('--wallet-script-sha256'); parser.add_argument('--participant-id')
    parser.add_argument('--admission-sompi', type=int); parser.add_argument('--crypto', nargs=2)
    parser.add_argument('--assets', nargs=2); parser.add_argument('--context', nargs=2)
    parser.add_argument('--own-mpc-result'); parser.add_argument('--backend-sha256')
    parser.add_argument('--engine-root'); parser.add_argument('--codec-sha256')
    parser.add_argument('--party-sha256'); parser.add_argument('--coordinator-sha256')
    parser.add_argument('--prepared-root'); parser.add_argument('--prepared-sha256')
    parser.add_argument('--native-codec', nargs=2); parser.add_argument('--outer-image-hex32')
    parser.add_argument('--compute-budget', type=int)
    parser.add_argument('--native-tail-hex')
    parser.add_argument('--verifier-host', nargs=2)
    args = parser.parse_args()
    need(len(args.exclude_owner_private_directory) == 3, 'three-complete-party-private-exclusions')
    guard = PublicGuard(args.exclude_private_root, args.exclude_owner_private_directory)
    files, result = [], {'schema': 'kpx7-integration-phase/v1', 'phase': args.op,
                        'classification': CLASSIFICATION, 'g16_verified': False,
                        'native_VM_executed': False, 'accepted_backing_or_currentness': False,
                        'owner_private_files_opened': 0}
    # Read and validate every selected external public input before allocating
    # output. Never iterate/hash a directory or accept unlisted public payloads.
    if args.op.startswith('owner-'):
        invoke_owner(args, guard)
        # Refresh exclusions after the producer created fresh private files.
        guard = PublicGuard(args.exclude_private_root, args.exclude_owner_private_directory)
        raw = created_public(guard, Path(args.output) / 'public/PUBLIC.json')
        value = parse_json(raw)
        if args.op == 'owner-init':
            initial_public(value, args.party)
        elif args.op == 'owner-prepare':
            owners = owners_public(read(guard, args.owners)); specification = read(guard, args.session)
            _, sid = session(canonical_json(specification), specification['program_source_sha256'])
            ready_public(value, owners[args.party], sid)
        else:
            authorize_public(value, read(guard, args.projection, False), args.party)
        output = Path(args.output)
        files = [{'file': 'public/PUBLIC.json', 'bytes': len(raw), 'sha256': sha(raw).hex()}]
    elif args.op.startswith('mpc-'):
        invoke_construction(args, guard)
        guard = PublicGuard(args.exclude_private_root, args.exclude_owner_private_directory)
        output = Path(args.output)
        name = 'PREPARED.json' if args.op == 'mpc-prepare' else 'RESULTS.json'
        raw = created_public(guard, output / name)
        files = [{'file': name, 'bytes': len(raw), 'sha256': sha(raw).hex()}]
    elif args.op == 'verify':
        need(args.execute, 'scheduled-nine-proof-verification-explicit')
        guard.read(args.verifier_host[0], args.verifier_host[1])
        projection = read(guard, args.projection, False)
        wire.validate_public(projection)
        # This public binary has its selected component profile compiled in.
        # It checks all nine G16s and compares the accelerated pairing backend
        # with the independent Arkworks reference, not a caller validity flag.
        child = subprocess.run([args.verifier_host[0], 'cross-check', args.projection[0], args.output],
                               stdin=subprocess.DEVNULL, capture_output=True,
                               env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
        need(child.returncode == 0, 'genuine-nine-proof-reference-verification-refused')
        output = Path(args.output)
        raw = created_public(guard, output / 'report.json'); report = parse_json(raw)
        need(report['all_three_Spend_and_six_Output_G16_verified'] is True and
             report['independent_arkworks_pairing_reference_checked'] is True and
             report['public_state_native_effects_and_global_balance_verified'] is True and
             report['input_sha256'] == sha(projection).hex() and
             report['R0_or_native_VM_executed'] is False and report['accepted_chain_authority'] is False,
             'exact-genuine-nine-proof-verification-report')
        journal = created_public(guard, output / 'journal.bin')
        need(journal == b'KPX7JR01' + DOMAIN + hx(args.component_profile_sha256, 32) + sha(projection)
             and sha(journal).hex() == report['journal_sha256'], 'selected-component-profile-full-body-journal')
        result.update({'g16_verified': True, 'all_nine_g16_and_global_balance_verified': True,
                       'independent_pairing_reference_checked': True})
        files = [{'file': 'report.json', 'bytes': len(raw), 'sha256': sha(raw).hex()},
                 {'file': 'journal.bin', 'bytes': len(journal), 'sha256': sha(journal).hex()}]
    elif args.op == 'genesis':
        need(args.owner_public is not None and len(args.owner_public) == 3, 'three-public-init-selectors')
        owners = [initial_public(read(guard, selected), i) for i, selected in enumerate(args.owner_public)]
        registry = {'schema': 'kpx7-public-owner-registry/v1', 'owners': owners,
                    'classification': CLASSIFICATION}
        owners_public(registry)
        value = genesis([hx(owner['initial_cm_hex32'], 32) for owner in owners],
                        sum(owner['admission_sompi'] for owner in owners))
        output = fresh(args.output)
        files += [save(output, 'GENESIS.json', value), save(output, 'OWNERS.json', registry),
                  save(output, 'STATE.bin', hx(value['state_hex112'], 112))]
        for i, path in enumerate(value['membership_path_hex512']):
            files.append(save(output, f'CM-PATH-{i}.bin', hx(path, 512)))
    elif args.op == 'context':
        initial = parse_genesis(read(guard, args.genesis)); owners = owners_public(read(guard, args.owners))
        need(initial['initial_cm_hex32'] == [row['initial_cm_hex32'] for row in owners], 'context-genesis-owner-join')
        value = premix_context(initial, owners, args.component_profile_sha256,
                               args.point_hex36, args.fee_sompi, args.native_tail_hex)
        output = fresh(args.output); files.append(save(output, 'CONTEXT.json', value))
    elif args.op == 'session':
        value = parse_genesis(read(guard, args.genesis)); owners = owners_public(read(guard, args.owners))
        need(value['initial_cm_hex32'] == [row['initial_cm_hex32'] for row in owners], 'registry-genesis-CM-join')
        specification = {'schema': 'kpx7-private-construction-session/v1',
             'session_id': args.session_id or secrets.token_hex(32), 'domain_hex': DOMAIN.hex(),
             'prior_state_digest': sha(hx(value['state_hex112'], 112)).hex(),
             'circuit_profile_sha256': args.component_profile_sha256,
             'public_effects_context_sha256': args.effects_context_sha256,
             'roster': [row['participant_id_hex32'] for row in owners],
             'program_source_sha256': args.program_sha256, 'tuple_bytes': 520,
             'outputs_per_party': 2, 'mpc_prime': str(Q)}
        _, sid = session(canonical_json(specification), args.program_sha256)
        output = fresh(args.output); files.append(save(output, 'SESSION.json', specification))
        result['session_sha256'] = sid
    elif args.op == 'build':
        value = parse_genesis(read(guard, args.genesis)); owners = owners_public(read(guard, args.owners))
        specification = read(guard, args.session)
        _, sid = session(canonical_json(specification), specification['program_source_sha256'])
        need(specification['prior_state_digest'] == sha(hx(value['state_hex112'], 112)).hex()
             and specification['roster'] == [row['participant_id_hex32'] for row in owners],
             'selected-session-prior-and-roster')
        context = read(guard, args.context)
        need(args.context[1] == specification['public_effects_context_sha256'] and
             context == premix_context(value, owners, specification['circuit_profile_sha256'],
                         context['previous_outpoint_hex36'], context['fee_sompi'], context['native_tail_hex']),
             'exact-approved-public-pre-mix-policy')
        need((args.point_hex36 is None or args.point_hex36 == context['previous_outpoint_hex36']) and
             (args.fee_sompi is None or args.fee_sompi == context['fee_sompi']), 'no-unapproved-body-context-change')
        need(args.ready is not None and len(args.ready) == 3, 'three-completed-owner-public-exports')
        inputs = [ready_public(read(guard, selected), owners[i], sid) for i, selected in enumerate(args.ready)]
        rows, delta = mixed_rows(read(guard, args.mixed), sid)
        body = body_core(value, inputs, rows, delta, sid, specification['roster'],
                         hx(context['previous_outpoint_hex36'], 36), context['fee_sompi'])
        parsed = wire.parse_body(body)
        output = fresh(args.output)
        packet = {'schema': 'kpx7-public-assembly-ipc/v1', 'operation': 'build', 'genesis': value,
                  'inputs': [{'nf_hex32': nf.hex(), 'cv_hex64': cv.hex()} for nf, cv in inputs],
                  'rows_hex': [row.hex() for row in rows], 'delta_hex32': delta.hex(),
                  'session_sha256': sid, 'roster': specification['roster'],
                  'point_hex36': context['previous_outpoint_hex36'], 'fee_sompi': context['fee_sompi']}
        save(output, 'COORDINATOR-PUBLIC-IPC.json', packet)
        isolated_assembly(canonical_json(packet), output)
        for name, expected in [('BODY.bin', body), ('OLD-STATE.bin', parsed.old_state.raw),
                               ('NEW-STATE.bin', parsed.new_state.raw)]:
            raw = created_public(guard, output / name)
            need(raw == expected, 'public-assembler-exact-output')
            files.append({'file': name, 'bytes': len(raw), 'sha256': sha(raw).hex()})
        result.update({'session_sha256': sid, 'spend_proof_slots_are_zero': True})
    elif args.op == 'native-project':
        body = read(guard, args.body, False)
        case, projection, journal, report = native_projection(args, guard, body)
        result.update(wire.validate_public(projection)); output = fresh(args.output)
        files += [save(output, 'CASE.json', case), save(output, 'PROJECTION.bin', projection),
                  save(output, 'JOURNAL.bin', journal), save(output, 'NATIVE-CODEC.json', report),
                  save(output, 'EFFECTS.bin', wire.effects_digest(projection))]
    elif args.op == 'project':
        projection = project(read(guard, args.body, False), hx(args.input_spk_hex37, 37),
                             hx(args.output_spk_hex37, 37))
        result.update(wire.validate_public(projection)); output = fresh(args.output)
        files.append(save(output, 'PROJECTION.bin', projection))
        files.append(save(output, 'EFFECTS.bin', wire.effects_digest(projection)))
    else:
        projection = read(guard, args.projection, False)
        need(args.spend_public is not None and len(args.spend_public) == 3, 'three-owner-Spend-export-selectors')
        proofs = [authorize_public(read(guard, selected), projection, i)
                  for i, selected in enumerate(args.spend_public)]
        projection = attach_spend_proofs(projection, proofs)
        result.update(wire.validate_public(projection)); output = fresh(args.output)
        files += [save(output, 'PROJECTION.bin', projection), save(output, 'BODY.bin', projection[193:])]
    result['files'] = files
    save(output, 'INTEGRATION.json', result)
    print(canonical_json({'status': 'PUBLIC_PHASE_COMPLETE_NOT_FINANCIAL_ACCEPTANCE',
          'phase': args.op, 'result_sha256': sha(canonical_json(result)).hex()}).decode(), end='')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Do not relay malformed external bytes, private invocation handles,
        # argv or arbitrary producer diagnostics to a coordinator terminal.
        sys.stderr.write('KPX7_PUBLIC_INTEGRATION_INCOMPLETE\n')
        raise SystemExit(1)
