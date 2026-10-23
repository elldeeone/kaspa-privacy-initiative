#!/usr/bin/env python3
"""PUBLIC DO_NOT_FUND same-note compact/wide/REVEAL competition controls.

Only this additive file is new. It reads the already selected deterministic
public wide canary, its public parameter manifests and selected new public
proofs. No main history, backup, wallet, private controller or PK is opened.
All nominal note secrets are public fixtures; the native signing scalar is1.
Fee1000 is deliberately retained: these are underpaid interoperability controls,
not fee qualification, accepted-chain races, privacy or live readiness.

Three genuine proofs suffice: two valid role alternatives spending the same two
notes, plus one private-SAT compact statement after REVEAL, whose current
occupied-NF witness the native layer must reject. Counterfactual duplicate trees
are constructed explicitly, never admitted as valid Snapshot values.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

from actions import Candidate, point_bytes
from canary_native import candidate as original_candidate
import history
from native_runtime import (DOMAIN, ROOT, Runtime, context, encoded, p2sh,
                            public_case, push, save, tx)
from primitives import (NFEntry, NOTE_FLOOR, Snapshot, SparseTree, ZERO, fixed,
                        fold_path, h, insert_nf, need, note_cm, parse, real_nf, u32, u64)
from synthetic import G, SCHEMA, box, note

PHASE = ROOT / 'research/next-session/compact-batch'
LABEL = 'PUBLIC_SAME_NOTE_COMPETITION_DO_NOT_FUND/v1'
FEE = 1_000
MANIFESTS = {
    'compact2': 'f27a806928b5c2409d4e4c5428a75deabef6ecf9601b60889667e90363f26043',
    'wide32': 'b1f0e93bf153c423c669524318efe276917a902d4e9e6b250fba564face94149'}
PUBLIC_SELECTION_SHA = '01bc2bbb54c42aadc8d37204ab0eefad6cf307931a7a57be0673d1e9a9beac3f'


def source_sha():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def fresh(output):
    from receiver import no_symlinks
    output = no_symlinks(output)
    need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-public-control-output-outside-Git')
    output.mkdir(parents=True, mode=0o700)
    return output


def public_parameters():
    manifests, keys = {}, {}
    for role, expected in MANIFESTS.items():
        raw = (PHASE / ('prover/parameters-' + role + '-01/public-parameters.json')).read_bytes()
        value = parse(raw)
        need(h(raw).hex() == expected and value['role'] == role
             and value['schema'] == 'kpx4-public-proving-parameters/v1'
             and value['domain_hex32'] == DOMAIN.hex(), 'already-selected-public-role-manifest')
        keys[role] = history.hexbytes(value['vk_hex328'], 328)
        need(value['vk_sha256'] == h(keys[role]).hex(), 'public-role-VK')
        manifests[role] = value
    return manifests, keys


def anchor():
    """Authenticate only exact files in the prior public canary selection."""
    manifest_path = PHASE / 'lifecycle/PUBLIC-SELECTION-01.json'
    raw = manifest_path.read_bytes()
    need(h(raw).hex() == PUBLIC_SELECTION_SHA, 'frozen-public-selection')
    selected = {row['path']: row for row in parse(raw)['files']}
    values = {}
    for name in ('validation-case.json', 'native-validation.json'):
        path = PHASE / 'lifecycle/public-native-canaries-01/wide32' / name
        value = path.read_bytes()
        pin = selected[str(path.relative_to(ROOT))]
        need(len(value) == pin['bytes'] and h(value).hex() == pin['sha256'], 'selected-public-anchor-bytes')
        values[name] = parse(value)
    case, report = values['validation-case.json'], values['native-validation.json']
    need(report['Full']['accepted'] is True and report['all_input_engines_accepted'] is True,
         'retained-public-anchor-Native-Full-report')
    original = original_candidate('wide32')
    body = case['transaction']
    need(history.hexbytes(body['payload']) == original.payload()
         and len(body['outputs']) == 1 and body['outputs'][0]['value'] == 32_000_000_000
         and original.after.cm_cursor == 64 and len(original.after.nullifiers) == 3,
         'original-wide-public-post-state')
    snapshot = original.after
    inputs = []
    cm, _ = snapshot.roots()
    for slot in (0, 1):
        raw_note, s, k = note('wide32/output/' + str(slot), 1_000_000_000)
        position = 32 + slot
        delivery = next(row for row in snapshot.deliveries if row.position == position)
        need(delivery.cm == note_cm(DOMAIN, raw_note) and raw_note[-32:] == G,
             'same-two-actual-public-wide-output-notes')
        inputs.append({'real': True, 'note_hex168': raw_note.hex(), 's_hex32': s.hex(),
            'k_hex32': k.hex(), 'position': position,
            'cm_path_hex': [part.hex() for part in cm.path(position)],
            'dummy_key_hex32': ZERO.hex(), 'dummy_seed_hex32': ZERO.hex()})
    return snapshot, {'transactionId': body['id'], 'index': 0}, 32_000_000_000, tuple(inputs)


def nf_tree(rows):
    # Deliberately also supports an explicitly INVALID counterfactual duplicate
    # row list. Such a list is never passed through Snapshot.verify/replay.
    return SparseTree(17, {i: row.leaf() for i, row in enumerate(rows)},
                      b'KPX1NFN\0', h(b'KPX1NFE\0'))


def raw_insert(rows, value, duplicate=False):
    rows = list(rows)
    count, tree = len(rows), nf_tree(rows)
    occupied = [(i, row) for i, row in enumerate(rows) if row.value == value]
    if duplicate:
        need(len(occupied) == 1, 'one-actual-current-occupied-NF')
        index, pred = occupied[0]
        need(pred.value == value, 'negative-is-current-predecessor-equality')
    else:
        need(value != ZERO and not occupied, 'positive-NF-currently-unspent')
        scalar = int.from_bytes(value, 'little')
        intervals = [(i, row) for i, row in enumerate(rows)
            if int.from_bytes(row.value, 'little') < scalar
            and (row.next_value == ZERO or scalar < int.from_bytes(row.next_value, 'little'))]
        need(len(intervals) == 1, 'one-current-strict-predecessor-interval')
        index, pred = intervals[0]
    path = tree.path(index)
    need(fold_path(pred.leaf(), index, path, b'KPX1NFN\0') == tree.root,
         'current-predecessor-path-authenticated')
    middle = tree.with_leaf(index, NFEntry(pred.value, value, count).leaf())
    witness = (u32(index) + pred.value + pred.next_value + u32(pred.next_index)
               + b''.join(path) + b''.join(middle.path(count)))
    rows[index] = NFEntry(pred.value, value, count)
    rows.append(NFEntry(value, pred.next_value, pred.next_index))
    need(len(witness) == 1160, 'exact-current-NF-witness-width')
    return tuple(rows), witness, middle.root


def inputs_nfs(inputs):
    values = tuple(real_nf(DOMAIN, history.hexbytes(row['k_hex32'], 32),
                          note_cm(DOMAIN, history.hexbytes(row['note_hex168'], 168)), row['position'])
                   for row in inputs)
    need(len(values) == 2 and values[0] != values[1] and ZERO not in values,
         'two-distinct-original-real-NFs')
    return values


def private_candidate(role, snapshot, previous, reserve, inputs, duplicate_first=False):
    need(role in ('compact2', 'wide32') and (not duplicate_first or role == 'compact2'), 'public-role')
    arity = 2 if role == 'compact2' else 32
    values = [999_999_500] * 2 if arity == 2 else [62_499_968] * 31 + [62_499_992]
    need(sum(values) + FEE == 2_000_000_000 and min(values) >= NOTE_FLOOR
         and reserve >= 2_000_000_000, 'no-reserve-insufficiency-or-output-floor-confound')
    nfs = inputs_nfs(inputs)
    rows, first, _ = raw_insert(snapshot.nullifiers, nfs[0], duplicate_first)
    rows, second, _ = raw_insert(rows, nfs[1])
    notes = tuple(note(LABEL + '/' + role + '/output/' + str(i), value)[0]
                  for i, value in enumerate(values))
    ciphers = tuple(box(LABEL + '/' + role, i) for i in range(arity))
    if duplicate_first:
        # Compute correct CM append using the still-valid current snapshot,
        # then combine it with the explicitly invalid duplicate NF tree.
        cm_after, start, boundary = snapshot.append(DOMAIN, notes, ciphers)
        cm_root = cm_after.roots()[0].root
        next_state = (b'KPX2ST01' + DOMAIN + cm_root + u32(cm_after.cm_cursor)
                      + nf_tree(rows).root + u32(len(rows)))
        after = None
    else:
        nf_after = Snapshot(snapshot.cm_cursor, snapshot.deliveries, rows).verify()
        after, start, boundary = nf_after.append(DOMAIN, notes, ciphers)
        next_state = after.state(DOMAIN)
    cm_list = b''.join(note_cm(DOMAIN, raw) for raw in notes)
    ciphertexts = b''.join(ciphers)
    auth = (b'KPX4AU01' + DOMAIN + point_bytes(previous) + snapshot.state(DOMAIN)
        + u64(reserve) + u64(FEE) + b''.join(nfs) + h(cm_list)
        + bytes([arity]) + bytes(3) + u32(start) + bytes(24) + h(ciphertexts)
        + next_state + u64(reserve - FEE) + u64(0) + bytes(36))
    need(len(auth) == 528, 'exact-public-Auth-width')
    return Candidate(role, arity, auth, inputs, notes, ciphertexts, cm_list,
                     first + second, b''.join(boundary), after, FEE, 0, reserve - FEE)


def reveal(snapshot, previous, reserve, inputs, duplicate=False):
    row = inputs[0]
    raw_note, key = history.hexbytes(row['note_hex168'], 168), history.hexbytes(row['k_hex32'], 32)
    value, position = int.from_bytes(raw_note[64:72], 'little'), row['position']
    need(value == 1_000_000_000 and reserve > value + FEE, 'reveal-has-ample-current-reserve')
    cm = note_cm(DOMAIN, raw_note)
    tree, _ = snapshot.roots()
    need(tree.levels[0][position] == cm, 'reveal-current-physical-CM-membership')
    nf = real_nf(DOMAIN, key, cm, position)
    rows, witness, middle = raw_insert(snapshot.nullifiers, nf, duplicate)
    next_state = (b'KPX2ST01' + DOMAIN + tree.root + u32(snapshot.cm_cursor)
                  + nf_tree(rows).root + u32(len(rows)))
    payload = (b'KPX2RV01\x01' + raw_note[:104] + key + raw_note[136:168] + u32(position)
        + raw_note[104:136] + cm + b''.join(tree.path(position)) + witness + nf + middle
        + nf_tree(rows).root + u64(FEE) + u64(value - FEE))
    need(len(payload) == 2029 and payload[1917:1949] == inputs_nfs(inputs)[0],
         'REVEAL-shares-original-real-NF')
    after = None if duplicate else Snapshot(snapshot.cm_cursor, snapshot.deliveries, rows).verify()
    return payload, next_state, after, reserve - value, value - FEE


def selected_proof(directory, chosen, keys, manifests):
    proof = fixed((directory / 'proof128.bin').read_bytes(), 128)
    report = parse((directory / 'report.json').read_bytes())
    role = chosen.role
    need((directory / 'authorization528.bin').read_bytes() == chosen.auth
         and (directory / 'verification-key.bin').read_bytes() == keys[role]
         and report['genuine_Groth16_verified'] is True and report['role'] == role
         and report['proof_sha256'] == h(proof).hex()
         and report['authorization_sha256'] == h(chosen.auth).hex()
         and report['vk_sha256'] == h(keys[role]).hex()
         and report['parameter_manifest_sha256'] == MANIFESTS[role]
         and report['compiled_build_identity_sha256'] == manifests[role]['compiled_build_identity_sha256'],
         'exact-new-public-genuine-proof-and-role')
    return proof


def check_prepared(directory, chosen, name):
    plan = parse((directory / 'PLAN.json').read_bytes())
    need(plan['source_sha256'] == source_sha()
         and plan['classification'] == 'PUBLIC_SYNTHETIC_DO_NOT_FUND_NO_MAIN_DATA', 'same-new-reviewed-source')
    need(parse((directory / name).read_bytes()) == chosen.private_witness(), 'exact-prepared-public-witness')


def prepare(output):
    output = fresh(output)
    snapshot, previous, reserve, inputs = anchor()
    compact = private_candidate('compact2', snapshot, previous, reserve, inputs)
    wide = private_candidate('wide32', snapshot, previous, reserve, inputs)
    need(compact.auth[204:268] == wide.auth[204:268], 'same-two-real-NFs-across-both-roles')
    for role, chosen in [('compact2', compact), ('wide32', wide)]:
        save(output / (role + '.json'), chosen.private_witness())
    save(output / 'PLAN.json', {'schema': 'kpx4-public-same-note-competition-plan/v1',
        'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND_NO_MAIN_DATA', 'source_sha256': source_sha(),
        'same_two_original_real_NFs_across_roles': True, 'input_positions': [32, 33],
        'input_each_sompi': 1_000_000_000, 'public_before_reserve_sompi': reserve,
        'fee_sompi': FEE, 'nominal_note_secrets_and_native_scalar1_are_public': True,
        'witness_backup_private_input_hashes': None, 'new_native_proof_PK_or_main_reads': 0})
    return {'prepared_public_role_witnesses': 2, 'same_two_original_real_NFs': True,
            'native_proof_PK_backup_or_main_reads': 0, 'source_sha256': source_sha()}


def native_case(runtime, body, entries, output, accepted, scope):
    body, metrics = runtime.normalize(body, entries, output / 'normalized')
    runtime.sdk(body, entries)
    path = output / 'validation-case.json'
    save(path, public_case(body, entries))
    runtime.native.run(['validate-transaction', path, output / 'native'])
    report = parse((output / 'native/native-validation.json').read_bytes())
    actual = parse((output / 'native/metrics.json').read_bytes())
    engines = report['per_input_ScriptEngine']
    need(metrics == actual and metrics['actual_fee_sompi'] == FEE
         and report['isolation'] == 'PASS' and len(engines) == 1, 'exact-underpaid-public-case-context')
    if accepted:
        need(report['Full']['accepted'] is True and report['all_input_engines_accepted'] is True
             and engines[0]['accepted'] is True, 'public-positive-Native-Full')
    else:
        need(report['Full']['accepted'] is False
             and report['Full']['typed_error'] == 'SignatureInvalid(VerifyError)'
             and report['all_input_engines_accepted'] is False
             and engines[0]['accepted'] is False and engines[0]['typed_error'] == 'VerifyError',
             'public-negative-native-VerifyError')
    result = {'case': output.name, 'scope': scope, 'native_Full_and_all_engines_accept': accepted,
        'typed_error': report['Full'].get('typed_error'), 'engine_units': engines[0]['units'],
        'actual_native_validation_calls': 1, 'transaction_id': body['id'], 'fee_sompi': FEE,
        'reference_rate100_required_sompi': 100 * metrics['mining_mass'],
        'reference_rate100_fee_passes': FEE >= 100 * metrics['mining_mass']}
    need(result['reference_rate100_fee_passes'] is False, 'retained-underpaid-interoperability-scope')
    save(output / 'RESULTS.json', result)
    return body, result


def signed_reveal(runtime, snapshot, previous, reserve, inputs, keys, output, duplicate=False):
    payload, next_state, after, remaining, payout = reveal(snapshot, previous, reserve, inputs, duplicate)
    redeem = runtime.emit(snapshot.state(DOMAIN), keys['compact2'], keys['wide32'])
    successor = runtime.emit(next_state, keys['compact2'], keys['wide32'])
    body = tx(previous, [(remaining, p2sh(successor)), (payout, (b'\0\0\x20' + G + b'\xac').hex())],
              payload, push(bytes(65)) + push(bytes(128)) + push(redeem), 200)
    entries = [context(reserve, redeem)]
    request = {'case': public_case(body, entries), 'input_index': 0,
        'public_development_secret_hex': (1).to_bytes(32, 'big').hex(),
        'sighash_type': 1, 'common_reveal_witness': True}
    request_path = output / 'PUBLIC-SCALAR1-SIGNING-REQUEST.json'
    save(request_path, request)
    runtime.native.run(['control-resign-freeze', request_path, output / 'signed'])
    signed = parse((output / 'signed/transaction.json').read_bytes())
    actual_case = parse((output / 'signed/validation-case.json').read_bytes())
    expected = copy.deepcopy(body)
    expected['id'], expected['mass'] = signed['id'], signed['mass']
    expected['inputs'][0]['signatureScript'] = signed['inputs'][0]['signatureScript']
    frame = history.hexbytes(signed['inputs'][0]['signatureScript'])
    need(signed == expected and history.contexts(actual_case) == entries
         and frame[0] == 65 and frame[65] == 1 and frame[68:196] == bytes(128)
         and frame[199:] == redeem and frame[1:65] != bytes(64), 'exact-public-REVEAL-SIGHASH-ALL-only-signature-change')
    return signed, entries, after, remaining


def native(prepared, compact_proof, wide_proof, output):
    output = fresh(output)
    manifests, keys = public_parameters()
    snapshot, previous, reserve, inputs = anchor()
    runtime, results, bodies, chosen = Runtime(), [], {}, {}
    for role, proof_dir in [('compact2', compact_proof), ('wide32', wide_proof)]:
        candidate = private_candidate(role, snapshot, previous, reserve, inputs)
        check_prepared(prepared, candidate, role + '.json')
        proof = selected_proof(proof_dir, candidate, keys, manifests)
        body, entries = runtime.body(candidate, previous, reserve, keys['compact2'], keys['wide32'], proof)
        body, result = native_case(runtime, body, entries, output / (role + '-positive'), True,
            'Genuine role proof on the same exact public postwide UTXO context; mutually exclusive alternatives')
        result['proof_sha256'], result['authorization_sha256'] = h(proof).hex(), h(candidate.auth).hex()
        bodies[role], chosen[role] = body, candidate
        results.append(result)
    need(chosen['compact2'].auth[204:268] == chosen['wide32'].auth[204:268], 'actual-role-NFs-identical')
    body, entries, after_reveal, reveal_reserve = signed_reveal(runtime, snapshot, previous, reserve,
                                                              inputs, keys, output / 'reveal-positive')
    body, result = native_case(runtime, body, entries, output / 'reveal-positive', True,
        'Public scalar1 authorized REVEAL of the same original note0/NF0 before either private alternative')
    results.append(result)
    reveal_point = {'transactionId': body['id'], 'index': 0}
    for role in ('compact2', 'wide32'):
        current = chosen[role]
        winner = {'transactionId': bodies[role]['id'], 'index': 0}
        bad, entries, _, _ = signed_reveal(runtime, current.after, winner, current.reserve_after,
            inputs, keys, output / ('reveal-after-' + role + '-NF-duplicate'), True)
        _, result = native_case(runtime, bad, entries, output / ('reveal-after-' + role + '-NF-duplicate'),
            False, 'Current state/CM path and occupied NF predecessor equality; ample reserve; signed REVEAL duplicate-NF rejection')
        results.append(result)
    # A retained proof/Auth rebase is a deliberately STALE statement. It is not
    # mislabeled as a fresh current-state proof or as isolated NF nonmembership.
    for loser, winner in [('compact2', 'wide32'), ('wide32', 'compact2')]:
        stale = copy.deepcopy(bodies[loser])
        source = chosen[winner]
        previous = {'transactionId': bodies[winner]['id'], 'index': 0}
        redeem = runtime.emit(source.after.state(DOMAIN), keys['compact2'], keys['wide32'])
        old_frame = history.hexbytes(stale['inputs'][0]['signatureScript'])
        stale['inputs'][0]['signatureScript'] = (old_frame[:196] + push(redeem)).hex()
        stale['inputs'][0]['previousOutpoint'] = previous
        stale['outputs'][0]['value'] = source.reserve_after - FEE
        _, result = native_case(runtime, stale, [context(source.reserve_after, redeem)],
            output / ('old-' + loser + '-proof-rebased-after-' + winner + '-STALE-AUTH'), False,
            'Unchanged old proof/Auth with new transaction outpoint/current program/context; STALE Auth rejection, NOT isolated duplicate-NF evidence')
        results.append(result)
    fresh_bad = private_candidate('compact2', after_reveal, reveal_point, reveal_reserve, inputs, True)
    save(output / 'compact-after-reveal.json', fresh_bad.private_witness())
    summary = {'schema': 'kpx4-public-same-note-competition-native/v1',
        'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND_NO_MAIN_DATA', 'source_sha256': source_sha(),
        'same_two_real_NFs_across_two_actual_role_proofs': True, 'input_notes_each_sompi': 1_000_000_000,
        'actual_native_validation_calls': len(results), 'new_genuine_proofs_consumed': 2,
        'role_positives': 2, 'authorized_REVEAL_positive': 1,
        'current_occupied_NF_REVEAL_rejections_after_private_roles': 2,
        'old_proof_rebases_labeled_stale_Auth_only': 2,
        'fresh_current_state_privateSAT_negative_witness_prepared': True,
        'next_public_witness_filename': 'compact-after-reveal.json',
        'witness_or_private_input_hashes': None, 'results': results,
        'accepted_chain_race_backing_currentness_privacy_fee_or_live_readiness_claimed': False}
    save(output / 'RESULTS.json', summary)
    return {key: value for key, value in summary.items() if key != 'results'}


def finish(native_directory, proof_directory, output):
    output = fresh(output)
    previous_report = parse((native_directory / 'RESULTS.json').read_bytes())
    need(previous_report['source_sha256'] == source_sha(), 'same-reviewed-competition-source')
    manifests, keys = public_parameters()
    snapshot, previous, reserve, inputs = anchor()
    _, _, after_reveal, reveal_reserve, _ = reveal(snapshot, previous, reserve, inputs)
    current_case = parse((native_directory / 'reveal-positive/validation-case.json').read_bytes())
    current_report = parse((native_directory / 'reveal-positive/native/native-validation.json').read_bytes())
    need(current_report['Full']['accepted'] is True and current_report['all_input_engines_accepted'] is True,
         'retained-actual-public-REVEAL-positive')
    current = {'transactionId': current_case['transaction']['id'], 'index': 0}
    chosen = private_candidate('compact2', after_reveal, current, reveal_reserve, inputs, True)
    need(parse((native_directory / 'compact-after-reveal.json').read_bytes()) == chosen.private_witness(),
         'exact-current-state-privateSAT-duplicate-NF-witness')
    proof = selected_proof(proof_directory, chosen, keys, manifests)
    runtime = Runtime()
    body, entries = runtime.body(chosen, current, reveal_reserve, keys['compact2'], keys['wide32'], proof)
    body, result = native_case(runtime, body, entries, output / 'genuine-current-compact-after-REVEAL-NF-duplicate',
        False, 'Fresh current-state genuine private-SAT proof; authentic occupied NF equality; native duplicate-NF guard rejects before G16')
    need(result['engine_units'] < 14_750_000, 'fresh-genuine-proof-rejection-precedes-G16-opcode')
    summary = {'schema': 'kpx4-public-current-state-genuine-NF-boundary/v1',
        'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND_NO_MAIN_DATA', 'source_sha256': source_sha(),
        'genuine_private_relation_proof_verified': True, 'current_outpoint_state_CM_paths_and_reserve': True,
        'current_occupied_NF_pred_value_equals_real_NF': True,
        'reserve_before_sompi': reveal_reserve, 'sum_private_inputs_sompi': 2_000_000_000,
        'fresh_proof_not_old_proof_rebase': True, 'native_duplicate_NF_rejection_before_G16': True,
        'actual_native_validation_calls': 1, 'total_new_genuine_proofs': 3,
        'proof_sha256': h(proof).hex(), 'authorization_sha256': h(chosen.auth).hex(),
        'witness_backup_or_private_input_hashes': None, 'result': result,
        'accepted_chain_race_backing_currentness_privacy_fee_or_live_readiness_claimed': False}
    save(output / 'RESULTS.json', summary)
    return summary


def selftest():
    """Pure public construction controls; no native/prover/PK/main data read."""
    snapshot, previous, reserve, inputs = anchor()
    a = private_candidate('compact2', snapshot, previous, reserve, inputs)
    b = private_candidate('wide32', snapshot, previous, reserve, inputs)
    need(a.auth[204:268] == b.auth[204:268] and a.after.roots()[1].root == b.after.roots()[1].root,
         'same-two-real-NFs-and-resulting-NF-root-across-roles')
    for chosen in (a, b):
        payload, _, after, _, _ = reveal(chosen.after, previous, chosen.reserve_after, inputs, True)
        need(after is None and payload[761:793] == payload[1917:1949],
             'negative-REVEAL-current-authenticated-occupied-predecessor-equality')
    _, _, after_reveal, remaining, _ = reveal(snapshot, previous, reserve, inputs)
    bad = private_candidate('compact2', after_reveal, previous, remaining, inputs, True)
    need(bad.after is None and bad.nf_witness[4:36] == bad.auth[204:236]
         and remaining > 2_000_000_000 and len(bad.payload()) == 3920,
         'fresh-counterfactual-private-current-NF-and-ample-reserve')
    # The production insertion API must continue to reject the exact occupied
    # NF that only this negative-control raw builder can encode.
    try:
        insert_nf(after_reveal, bad.auth[204:236])
    except ValueError as error:
        need(str(error) == 'spent-or-zero-NF', 'strict-normal-api-error')
    else:
        raise ValueError('normal-insertion-accepted-occupied-NF')
    return {'pure_public_construction_controls': 5, 'passed': True,
            'native_proof_PK_backup_or_main_data_calls': 0, 'source_sha256': source_sha()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    sub.add_parser('selftest')
    prepare_parser = sub.add_parser('prepare')
    prepare_parser.add_argument('--output', type=Path, required=True)
    native_parser = sub.add_parser('native')
    for name in ('prepared', 'compact-proof', 'wide-proof', 'output'):
        native_parser.add_argument('--' + name, type=Path, required=True)
    finish_parser = sub.add_parser('finish')
    for name in ('native-directory', 'proof-directory', 'output'):
        finish_parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if args.operation == 'selftest':
        result = selftest()
    elif args.operation == 'prepare':
        result = prepare(args.output)
    elif args.operation == 'native':
        result = native(args.prepared, args.compact_proof, args.wide_proof, args.output)
    else:
        result = finish(args.native_directory, args.proof_directory, args.output)
    print(json.dumps(result, sort_keys=True))
