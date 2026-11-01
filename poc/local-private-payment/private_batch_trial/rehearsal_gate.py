"""Reexecute a complete retained supplied-context native lifecycle.

All inputs are finite public artifacts. No success Boolean replaces the actual
GEN3 Output/CV checks, ordered public-state replay and NativeFull on every CASE.
Under ADR-0084 this is an end-of-run cryptographic/evidence recheck, not the
launch authority for a first Testnet rehearsal. It is not confirmation of a
Testnet payout or a declaration of trial readiness.
"""
import copy
import hashlib
from pathlib import Path

import funding
import genesis
import complete_rehearsal_manifest
import exit_wire
import private_lifecycle
import private_worker
import wallet_history


def witness_data(raw):
    """Read P2SH signature-script pushes without executing the redeem script."""
    need = genesis.need
    result, offset = [], 0
    while offset < len(raw):
        opcode = raw[offset]; offset += 1
        if opcode == 0:
            result.append(b''); continue
        if 1 <= opcode <= 75:
            size = opcode
        elif opcode in (76, 77, 78):
            width = {76: 1, 77: 2, 78: 4}[opcode]
            need(offset + width <= len(raw), 'rehearsal-signature-push-length')
            size = int.from_bytes(raw[offset:offset + width], 'little'); offset += width
        elif opcode == 79 or 81 <= opcode <= 96:
            continue  # Script-number selectors, not a 128-byte proof.
        else:
            raise wallet_history.wallet.Invalid('rehearsal-push-only-signature-script')
        need(offset + size <= len(raw), 'rehearsal-signature-push-data')
        result.append(raw[offset:offset + size]); offset += size
    return result


def case_projection(case, kind):
    """Canonical native projection, reconstructed from the actual whole CASE."""
    body, entries = case['transaction'], case['entries']
    need = genesis.need
    need(kind in ('payment', 'exit') and type(body['version']) is int and body['version'] == 1
         and len(body['inputs']) == len(entries) == 1 and body['lockTime'] == 0
         and body['gas'] == 0 and body['subnetworkId'] == '00' * 20, 'rehearsal-exact-native-frame')
    source = body['inputs'][0]; point = source['previousOutpoint']
    need(type(source['sequence']) is int and source['sequence'] == (1 << 64) - 1,
         'rehearsal-exact-native-sequence')
    raw_point = genesis.hx(point['transactionId'], 32) + genesis.uint(point['index'], 32).to_bytes(4, 'little')
    script = genesis.hx(entries[0]['scriptPublicKey'], 37)
    need(entries[0]['isCoinbase'] is False and entries[0]['covenantId'] is None, 'rehearsal-reserve-entry-flags')
    payload_hex = body['payload']
    need(type(payload_hex) is str, 'rehearsal-public-payload')
    payload = genesis.hx(payload_hex, 10492 if kind == 'payment' else 1604)
    prefix = (b'KPBAFX01' if kind == 'payment' else b'KPBXFX01') + b'\x01\0\x01\0'
    prefix += raw_point + b'\xff' * 8 + genesis.amount(entries[0]['amount']).to_bytes(8, 'little')
    prefix += (37).to_bytes(2, 'little') + script + len(body['outputs']).to_bytes(2, 'little')
    for output in body['outputs']:
        need(output['covenant'] is None and type(output['scriptPublicKey']) is str,
             'rehearsal-native-output-covenant')
        output_script = genesis.hx(output['scriptPublicKey'], len(output['scriptPublicKey']) // 2)
        need(len(output_script) in (36, 37), 'rehearsal-native-output-script-width')
        prefix += genesis.amount(output['value']).to_bytes(8, 'little') + len(output_script).to_bytes(2, 'little')
        prefix += output_script + b'\0'
    return prefix + bytes(36) + len(payload).to_bytes(4, 'little') + payload


def history_prefix(value, count):
    """Build the exact post-prefix head; never reuse the terminal head."""
    genesis.need(type(count) is int and 0 <= count <= len(value['transitions']),
                 'rehearsal-prefix-count')
    result = copy.deepcopy(value)
    result['transitions'] = result['transitions'][:count]
    if count == 0:
        result['head'] = {name: value['genesis'][name] for name in
                          ('outpoint_hex36', 'state_hex112', 'reserve_sompi')}
    else:
        event = value['transitions'][count - 1]
        raw = bytes.fromhex(event['projection_hex'])
        if event['kind'] == 'payment':
            body = raw[193:]
            state = (b'KPBAST01' + body[104:136] + body[284:316]
                     + body[348:352] + body[316:348] + body[352:356])
            reserve = int.from_bytes(body[356:364], 'little')
        else:
            effect = exit_wire.validate_public(raw)
            state, reserve = effect.next_state(), effect.new_reserve
        result['head'] = {'outpoint_hex36': event['successor_outpoint_hex36'],
                          'state_hex112': state.hex(),
                          'reserve_sompi': reserve}
    return result


def require_actual_replay_refusals(history_value, selected):
    """Replay transitions against their actual successor state and exact error."""
    checks = ((0, 'payment', wallet_history.wallet.Invalid,
               'wallet-payment-exact-current-context'),
              (2, 'exit', ValueError, 'new-exit-exact-selected-head'))
    refused = 0
    for index, kind, error_type, category in checks:
        state = wallet_history.load_supplied(history_prefix(history_value, index + 1),
            selected.verifier.profile, selected.identity, selected.tail,
            selected.verifier.verify, selected.initial_cv)
        raw = bytes.fromhex(history_value['transitions'][index]['projection_hex'])
        try:
            if kind == 'payment':
                wallet_history.payment(raw, state.head, state.state, selected.tail,
                                       selected.verifier.verify)
            else:
                exit_wire.require_current_head(raw, state.head, selected.tail)
        except error_type as error:
            genesis.need(error.args == (category,),
                         'rehearsal-exact-' + kind + '-replay-refusal')
            refused += 1
        else:
            raise wallet_history.wallet.Invalid(
                'rehearsal-actual-' + kind + '-replay-accepted')
    return refused


def require_activation_trial(value, args, read):
    trial_ref = value['bootstrap_trial']
    genesis.fields(trial_ref, ('path', 'sha256'))
    expected = {'path': str(Path(args.trial).absolute()),
                'sha256': args.trial_sha256}
    activation_trial = private_worker.parse(read(Path(expected['path']),
                                                 expected['sha256']))
    genesis.need(trial_ref == expected
         and value['bootstrap_trial_id'] == activation_trial['trial_id'],
         'rehearsal-same-fresh-activation-trial')
    return activation_trial


def verify(args, read, manifest_path, manifest_sha256, output):
    selected = funding.component(args, read)
    raw = read(Path(manifest_path).absolute(), manifest_sha256)
    value = private_worker.parse(raw)
    genesis.fields(value, ('schema', 'scope', 'bootstrap_trial_id', 'bootstrap_trial',
                           'component_profile_sha256', 'tail_sha256', 'source_contract',
                           'history', 'cases', 'terminal_scan_controller'))
    require_activation_trial(value, args, read)
    genesis.need(value['schema'] == complete_rehearsal_manifest.MANIFEST_SCHEMA
         and value['scope'] == wallet_history.SCOPE
         and value['component_profile_sha256'] == args.component_profile_sha256
         and value['tail_sha256'] == args.tail_sha256, 'complete-selected-offline-native-rehearsal')
    # A hand-written list of CASEs is not enough. Rebuild the manifest from the
    # exact fresh-trial, owner-intake, registered-release, R0 and Exit evidence.
    genesis.need(complete_rehearsal_manifest.rebuild(read, value['source_contract']) == value,
                 'rehearsal-exact-source-contract-rebuild')
    for item in (value['history'], value['terminal_scan_controller']):
        genesis.fields(item, ('path', 'sha256'))
    history_raw = read(Path(value['history']['path']).absolute(), value['history']['sha256'])
    history_value = private_worker.parse(history_raw)
    state = wallet_history.load_supplied(history_value, selected.verifier.profile, selected.identity,
        selected.tail, selected.verifier.verify, selected.initial_cv)
    genesis.need(state.point is None and state.reserve == 0, 'rehearsal-terminal-zero-reserve')
    replay_rejections = require_actual_replay_refusals(history_value, selected)
    genesis.need(replay_rejections == 2, 'rehearsal-payment-and-exit-replay-refusal')
    expected_kinds = ['genesis', 'payment', 'payment'] + ['exit'] * 9
    genesis.need(type(value['cases']) is list and [item['kind'] for item in value['cases']] == expected_kinds
         and [event['kind'] for event in history_value['transitions']] == expected_kinds[1:],
         'rehearsal-two-batches-nine-current-head-exits')
    output = Path(output).absolute()
    genesis.need(not output.exists(), 'rehearsal-fresh-actual-validation-directory')
    output.mkdir(parents=True, mode=0o700)
    runtime = funding.public_runtime(read)
    checks = []
    for index, spec in enumerate(value['cases']):
        genesis.fields(spec, ('kind', 'path', 'sha256'))
        case_raw = read(Path(spec['path']).absolute(), spec['sha256'])
        case = private_worker.parse(case_raw)
        work = output / ('case-' + str(index)); work.mkdir(mode=0o700)
        normalized, _ = runtime.normalize(case, work / 'normalized')
        genesis.need(normalized == case, 'rehearsal-actual-native-body-ID-storage-mass')
        if index == 0:
            # UUID is encoded in the actual new payload and canonically parsed.
            import uuid
            payload = genesis.hx(case['transaction']['payload'], genesis.WIDTH)
            trial_id = str(uuid.UUID(bytes=payload[72:88]))
            derived = genesis.validate_case(case, selected, trial_id, signed=True)
            origin = history_value['genesis']
            genesis.need(derived['state_hex112'] == origin['state_hex112']
                and derived['outpoint_hex36'] == origin['outpoint_hex36']
                and derived['outputs_hex520'] == origin['outputs_hex520'], 'rehearsal-actual-GEN3-origin')
        else:
            event = history_value['transitions'][index - 1]
            genesis.need(case_projection(case, spec['kind']).hex() == event['projection_hex'],
                         'rehearsal-actual-CASE-exact-history-projection')
            expected_successor = None if index == len(value['cases']) - 1 else case['transaction']['id'] + '00000000'
            genesis.need(event['successor_outpoint_hex36'] == expected_successor,
                         'rehearsal-actual-successor-outpoint-graph')
            if spec['kind'] == 'exit':
                witness_hex = case['transaction']['inputs'][0]['signatureScript']
                pushed = witness_data(genesis.hx(witness_hex, len(witness_hex) // 2))
                actual_proofs = [data for data in pushed if len(data) == 128]
                genesis.need(actual_proofs == [genesis.hx(event['proof_hex128'], 128)],
                             'rehearsal-retained-Exit-proof-is-actual-witness')
        runtime.validate(case, work / 'native-Full')
        checks.append({'kind': spec['kind'], 'raw_case_sha256': spec['sha256'],
                       'actual_native_Full_all_inputs': True})
    scans = private_worker.parse(read(Path(value['terminal_scan_controller']['path']).absolute(),
                                     value['terminal_scan_controller']['sha256']))
    genesis.need(scans['schema'] == 'kpb-original-lifecycle-controller-result/v1' and scans['operation'] == 'scan'
         and scans['scope'] == wallet_history.SCOPE
         and [row['owner_component'] for row in scans['owners']] == [0, 1, 2]
         and scans['controller_read_or_hashed_private_bodies'] is False, 'rehearsal-three-original-terminal-scans')
    for row in scans['owners']:
        status = private_lifecycle.public_receipt(row['status'], 'scan')
        genesis.need(status['terminal_reconciled'] is True
             and status['history_sha256'] == value['history']['sha256'], 'rehearsal-same-terminal-original-scan')
    result = {'schema': 'kpb-executed-complete-native-rehearsal-gate/v1', 'scope': wallet_history.SCOPE,
        'manifest_sha256': manifest_sha256, 'component_profile_sha256': args.component_profile_sha256,
        'tail_sha256': args.tail_sha256, 'actual_native_CASE_checks': checks,
        'actual_history_payment_and_exit_replay_rejections': replay_rejections,
        'actual_public_tree_replay_terminal_reserve_sompi': 0, 'original_terminal_scan_statuses': 3,
        'testnet_terminal_broadcast_confirmation_or_readiness': False,
        'controller_Original_private_truth_or_wallet_body_read': False}
    funding.save(output / 'RESULT.json', result)
    return result
