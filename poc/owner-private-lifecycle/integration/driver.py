#!/usr/bin/env python3
"""Pinned public-data phases for one integrated owner-private lifecycle.

This driver has no signing/funding/broadcast API. Genuine owner authorization,
financial verification, native Full, accepted replay and confirmations remain
separate mandatory execution stages, never caller-supplied acceptance booleans.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import secrets
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE / 'construction'))
from backend import PublicGuard, bubble, fresh, write
from codec import canonical_json, parse_json, session
from public import (DOMAIN, Q, amount, attach_spend_proofs, body_core, exit_body, extend,
                    fields, genesis, hx, load_wire, mixed_rows, need, premix_context, reconstruct, sha)

CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def read(guard, selector, *, json_value=True):
    need(type(selector) in (tuple, list) and len(selector) == 2, 'pinned-public-input-required')
    raw = guard.read(selector[0], selector[1])
    return parse_json(raw) if json_value else raw


def save(output, name, value):
    raw = canonical_json(value) if type(value) is dict else value
    write(output / name, raw)
    return {'file': name, 'bytes': len(raw), 'sha256': sha(raw).hex()}


def produced(guard, path):
    path, before = guard.metadata(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        need(all(getattr(before, key) == getattr(opened, key) for key in keys), 'stable-public-producer-open')
        raw = stream.read()
        after = os.fstat(stream.fileno())
    need(len(raw) == before.st_size and all(getattr(before, key) == getattr(after, key) for key in keys),
         'stable-public-producer-bytes')
    return raw


def native_module():
    name = 'kpx8_integration_native_case'
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, HERE.parent / 'verification/native_case.py')
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def native(args, guard):
    guard.read(args.native_codec[0], args.native_codec[1])
    exit_vk = read(guard, args.exit_vk, json_value=False)
    need(len(exit_vk) == 328, 'selected-exit-VK-width')
    return native_module(), native_module().NativeCodec(Path(args.native_codec[0]), args.native_codec[1]), (
        hx(args.outer_image_hex32, 32), hx(args.component_profile_sha256, 32), exit_vk)


def isolated(packet, output):
    mounts = [('coordinator.py', '/app/integration/coordinator.py'), ('public.py', '/app/integration/public.py'),
              ('trees.py', '/app/integration/trees.py'), ('construction/codec.py', '/app/integration/construction/codec.py')]
    command = bubble()
    for relative, target in mounts:
        command += ['--ro-bind', str(HERE / relative), target]
    command += ['--ro-bind', str(HERE.parent / 'verification/wire.py'), '/app/verification/wire.py',
        '--bind', str(output), '/out', '--chdir', '/app/integration', '/usr/bin/python3', '-B',
        '/app/integration/coordinator.py']
    child = subprocess.run(command, input=canonical_json(packet), capture_output=True, env=CLEAN)
    need(child.returncode == 0, 'isolated-public-assembler-incomplete')


def ready_public(value, participant, sid):
    fields(value, ('schema', 'participant_id_hex32', 'session_sha256', 'nf_hex32', 'cv_hex64',
        'own_output_count', 'mpc_input_written', 'financial_authorization'), 'exact-private-note-READY-public-fields')
    need(value['schema'] == 'kpx8-owner-input-ready/v1'
         and value['participant_id_hex32'] == participant and value['session_sha256'] == sid
         and type(value['own_output_count']) is int and value['own_output_count'] == 2
         and value['mpc_input_written'] is True and value['financial_authorization'] is False,
         'READY-participant-session-shape')
    return hx(value['nf_hex32'], 32), hx(value['cv_hex64'], 64)


def authorize_public(value, projection, index):
    wire = load_wire()
    body = wire.parse_projection(projection).body
    effects = wire.effects_digest(projection)
    fields(value, ('schema', 'session_sha256', 'effects_digest_hex32', 'nf_hex32', 'cv_hex64',
        'statement_hex200', 'proof_hex128'), 'exact-Spend-authorization-fields')
    spend = body.spends[index]
    statement = b'KPX8SP01' + DOMAIN + body.old_state.cm_root + spend.nf + spend.cv + effects
    need(value['schema'] == 'kpx8-owner-spend-authorization/v1'
         and value['session_sha256'] == body.session.hex() and value['effects_digest_hex32'] == effects.hex()
         and hx(value['nf_hex32'], 32) == spend.nf and hx(value['cv_hex64'], 64) == spend.cv
         and hx(value['statement_hex200'], 200) == statement, 'exact-entire-effects-Spend-authorization')
    return hx(value['proof_hex128'], 128)


def execute(args):
    need(Path('/var/tmp/kpi-owner-private-lifecycle-01/private') in
         [Path(value).absolute() for value in args.exclude_private_directory], 'whole-private-parent-excluded')
    guard = PublicGuard(args.exclude_private_root, (), args.exclude_private_directory)
    need(all(not Path(args.output).absolute().is_relative_to(directory)
             for directory in guard.directories), 'public-phase-output-outside-private')
    result = {'schema': 'kpx8-lifecycle-integration-phase/v1', 'phase': args.operation,
        'g16_verified': False, 'native_VM_executed': False, 'accepted_backing_or_currentness': False,
        'owner_private_contents_read': 0}
    files = []
    # Authenticate all explicit caller selections before creating output.
    if args.operation == 'genesis':
        case = read(guard, args.case)
        selection_raw = read(guard, args.founding_selection, json_value=False)
        sys.path.insert(0, str(HERE.parent / 'bootstrap'))
        import gn3, gn3_selection
        selection = gn3_selection.decode(selection_raw, args.founding_selection[1])
        # The accepted-history parser still does NOT establish inclusion. It
        # derives admission semantics only; actual Full replay is mandatory.
        derived = gn3.validate_accepted_genesis(case, selection, args.trial_id)
        payload = bytes.fromhex(case['transaction']['payload'])
        records = [payload[88 + 496 * i:88 + 496 * (i + 1)] for i in range(3)]
        history = genesis(records, derived['outpoint_hex36'])
        need(history['genesis']['state_hex112'] == derived['state_hex112']
             and history['genesis']['reserve_sompi'] == derived['reserve_sompi'], 'strict-GN3-history-admission-join')
        output = fresh(args.output)
        files += [save(output, 'HISTORY.json', history), save(output, 'CHECKPOINT.json', history['head']),
                  save(output, 'GN3-SEMANTICS.json', derived)]
    elif args.operation in ('context', 'session', 'build', 'exit-body'):
        history = read(guard, args.history)
        _, head = reconstruct(history)
        if args.operation == 'context':
            context = premix_context(history, args.component_profile_sha256, args.fee_sompi, args.native_tail_hex)
            output = fresh(args.output)
            files.append(save(output, 'CONTEXT.json', context))
        elif args.operation == 'session':
            context = read(guard, args.context)
            need(context == premix_context(history, context['component_profile_sha256'],
                context['fee_sompi'], context['native_tail_hex']), 'current-selected-premix-context')
            specification = {'schema': 'kpx8-private-construction-session/v1',
                'session_id': args.session_id or secrets.token_hex(32), 'domain_hex': DOMAIN.hex(),
                'prior_state_digest': sha(hx(head['state_hex112'], 112)).hex(),
                'circuit_profile_sha256': context['component_profile_sha256'],
                'public_effects_context_sha256': args.context[1], 'roster': args.participant_id,
                'program_source_sha256': args.program_sha256, 'tuple_bytes': 520,
                'outputs_per_party': 2, 'mpc_prime': str(Q)}
            _, sid = session(canonical_json(specification), args.program_sha256)
            result['session_sha256'] = sid
            output = fresh(args.output)
            files.append(save(output, 'SESSION.json', specification))
        elif args.operation == 'build':
            specification = read(guard, args.session)
            _, sid = session(canonical_json(specification), specification['program_source_sha256'])
            context = read(guard, args.context)
            need(args.context[1] == specification['public_effects_context_sha256']
                 and context == premix_context(history, specification['circuit_profile_sha256'],
                    context['fee_sompi'], context['native_tail_hex'])
                 and specification['prior_state_digest'] == sha(hx(head['state_hex112'], 112)).hex(),
                 'current-state-session-and-approved-context')
            need(type(args.ready) is list and len(args.ready) == 3, 'three-current-owner-READY-selectors')
            inputs = [ready_public(read(guard, selected), specification['roster'][i], sid)
                      for i, selected in enumerate(args.ready)]
            rows, delta = mixed_rows(read(guard, args.mixed), sid)
            body = body_core(history, inputs, rows, delta, sid, specification['roster'], context['fee_sompi'])
            packet = {'schema': 'kpx8-public-assembly-ipc/v1', 'operation': 'build', 'history': history,
                'inputs': [{'nf_hex32': nf.hex(), 'cv_hex64': cv.hex()} for nf, cv in inputs],
                'rows_hex': [row.hex() for row in rows], 'delta_hex32': delta.hex(),
                'session_sha256': sid, 'roster': specification['roster'], 'fee_sompi': context['fee_sompi']}
            output = fresh(args.output)
            files.append(save(output, 'COORDINATOR-PUBLIC-IPC.json', packet))
            isolated(packet, output)
            parsed = load_wire().parse_body(body)
            for name, expected in (('BODY.bin', body), ('OLD-STATE.bin', parsed.old_state.raw),
                                   ('NEW-STATE.bin', parsed.new_state.raw)):
                actual = produced(guard, output / name)
                need(actual == expected, 'isolated-assembler-exact-body')
                files.append({'file': name, 'bytes': len(actual), 'sha256': sha(actual).hex()})
        else:
            selected = read(guard, args.exit_ready)
            need(selected['schema'] == 'kpx8-owner-exit-ready/v1', 'selected-owner-exit-ready-schema')
            body = exit_body(history, hx(selected['nf_hex32'], 32), hx(selected['payout_spk_hex36'], 36),
                selected['gross_claim_sompi'], args.fee_sompi, args.session_id or secrets.token_hex(32))
            output = fresh(args.output)
            files.append(save(output, 'BODY.bin', body))
    elif args.operation == 'native-project':
        body = read(guard, args.body, json_value=False)
        module, codec, selected = native(args, guard)
        proof = bytes(128) if args.proof is None else read(guard, args.proof, json_value=False)
        case, projection, journal, report = module.make_case(codec, body, *selected, args.compute_budget,
            outer_proof=proof, block_daa_score=args.block_daa_score)
        output = fresh(args.output)
        effects = load_wire().effects_digest(projection) if body[:8] == b'KPX8PB01' else load_wire().exit_effects_digest(projection)
        files += [save(output, 'CASE.json', case), save(output, 'PROJECTION.bin', projection),
                  save(output, 'JOURNAL.bin', journal), save(output, 'EFFECTS.bin', effects),
                  save(output, 'NATIVE-CODEC.json', report)]
    elif args.operation == 'finalize':
        projection = read(guard, args.projection, json_value=False)
        need(type(args.spend_public) is list and len(args.spend_public) == 3, 'three-postmix-Spend-selectors')
        proofs = [authorize_public(read(guard, value), projection, i) for i, value in enumerate(args.spend_public)]
        final = attach_spend_proofs(projection, proofs)
        packet = {'schema': 'kpx8-public-assembly-ipc/v1', 'operation': 'finalize',
                  'projection_hex10973': projection.hex(), 'spend_proofs_hex128': [row.hex() for row in proofs]}
        output = fresh(args.output)
        isolated(packet, output)
        need(produced(guard, output / 'PROJECTION.bin') == final, 'isolated-finalization-exact-proof-attachment')
        for name, raw in (('BODY.bin', final[193:]), ('PROJECTION.bin', final)):
            files.append({'file': name, 'bytes': len(raw), 'sha256': sha(raw).hex()})
    elif args.operation == 'append':
        history = read(guard, args.history)
        projection = read(guard, args.projection, json_value=False)
        case = read(guard, args.case)
        module, codec, selected = native(args, guard)
        canonical_case, actual, _, report = module.project(codec, case, *selected)
        need(actual == projection and canonical_case == case, 'exact-canonical-case-history-projection')
        mixed = report['mode'] == 'mixed'
        body = (load_wire().parse_projection(projection) if mixed else load_wire().parse_exit_projection(projection)).body
        successor = case['transaction']['id'] + '00000000' if body.new_reserve else None
        transition = {'kind': 'batch' if mixed else 'exit', 'projection_hex': projection.hex(),
                      'successor_outpoint_hex36': successor}
        if mixed:
            transition['session'] = read(guard, args.session)
        else:
            frame = bytes.fromhex(case['transaction']['inputs'][0]['signatureScript'])
            need(frame[:2] == b'\x4c\x80', 'canonical-direct-exit-proof-witness')
            transition['proof_hex128'] = frame[2:130].hex()
        following = extend(history, transition)
        output = fresh(args.output)
        files += [save(output, 'HISTORY.json', following), save(output, 'CHECKPOINT.json', following['head'])]
    else:
        need(args.operation == 'verify', 'closed-integration-operation')
        projection = read(guard, args.projection, json_value=False)
        load_wire().validate_public(projection)
        guard.read(args.verifier_host[0], args.verifier_host[1])
        need(args.execute, 'explicit-genuine-financial-verification')
        child = subprocess.run([args.verifier_host[0], 'cross-check', args.projection[0], args.output],
            stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
        need(child.returncode == 0, 'genuine-nine-proof-reference-check-incomplete')
        output = Path(args.output)
        raw = produced(guard, output / 'report.json')
        report = parse_json(raw)
        need(report['all_three_Spend_and_six_Output_G16_verified'] is True
             and report['independent_arkworks_pairing_reference_checked'] is True
             and report['public_state_native_effects_and_global_balance_verified'] is True
             and report['input_sha256'] == sha(projection).hex(), 'joined-genuine-nine-proof-reference-report')
        result['g16_verified'] = True
        files += [{'file': 'report.json', 'bytes': len(raw), 'sha256': sha(raw).hex()}]
    result['files'] = files
    write(output / 'INTEGRATION.json', canonical_json(result))
    return result


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('genesis', 'context', 'session', 'build', 'native-project',
                                       'finalize', 'exit-body', 'append', 'verify'))
    p.add_argument('--exclude-private-root', action='append', required=True)
    p.add_argument('--exclude-private-directory', action='append', required=True)
    p.add_argument('--output', required=True)
    for name in ('case', 'founding-selection', 'history', 'context', 'session', 'mixed', 'body',
                 'projection', 'native-codec', 'exit-vk', 'proof', 'exit-ready', 'verifier-host'):
        p.add_argument('--' + name, nargs=2)
    p.add_argument('--ready', nargs=2, action='append')
    p.add_argument('--spend-public', nargs=2, action='append')
    for name in ('trial-id', 'component-profile-sha256', 'native-tail-hex', 'session-id',
                 'program-sha256', 'outer-image-hex32'):
        p.add_argument('--' + name)
    p.add_argument('--participant-id', action='append')
    p.add_argument('--fee-sompi', type=int)
    p.add_argument('--compute-budget', type=int)
    p.add_argument('--block-daa-score', type=int, default=0)
    p.add_argument('--execute', action='store_true')
    return p


def main():
    os.umask(0o077)
    try:
        value = execute(parser().parse_args())
        print(canonical_json(value).decode(), end='')
    except Exception:
        sys.stderr.write('KPX8_PUBLIC_INTEGRATION_INCOMPLETE\n')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
