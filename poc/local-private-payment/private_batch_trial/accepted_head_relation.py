"""Pure GEN3-to-head relation replay for the selected fresh public producer.

This module creates public tree data, never AcceptedFinancialHead authority.
The caller must directly acquire the accepted whole CASEs and current UTXO,
authenticate the selected tools/source and run every SDK/native/proof check.
No imported acceptance report, scope flag, wallet, Original or filesystem input
is consumed here. The existing UNFUNDED_SUPPLIED_CONTEXT loader is unchanged.
"""
import exit_wire
import genesis
import wallet_history


def checked_callback(verify_case, kind, case, projection, proof):
    """Verification may inspect a CASE, but cannot replace its admitted bytes."""
    before = genesis.private_worker.encoded(case)
    genesis.need(verify_case(kind, case, projection, proof) is True,
                 'head-relation-actual-CASE-verification')
    genesis.need(genesis.private_worker.encoded(case) == before, 'head-relation-verifier-mutated-CASE')


def transition_shape(case):
    """Require canonical integer CASE fields before projection reconstruction."""
    genesis.fields(case, ('transaction', 'entries'))
    body, entries = case['transaction'], case['entries']
    genesis.fields(body, ('version', 'id', 'inputs', 'outputs', 'lockTime', 'subnetworkId', 'gas', 'payload', 'mass'))
    genesis.need(type(body['inputs']) is list and len(body['inputs']) == 1
                 and type(entries) is list and len(entries) == 1
                 and type(body['outputs']) is list and 1 <= len(body['outputs']) <= 2,
                 'head-relation-single-reserve-CASE')
    for name in ('version', 'lockTime', 'gas', 'mass'):
        genesis.uint(body[name])
    txid = genesis.hx(body['id'], 32)
    genesis.need(txid != bytes(32), 'head-relation-nonzero-transaction-id')
    source, entry = body['inputs'][0], entries[0]
    genesis.fields(source, ('previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'))
    genesis.fields(source['previousOutpoint'], ('transactionId', 'index'))
    genesis.uint(source['computeBudget'], 16)
    genesis.fields(entry, ('amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'))
    genesis.uint(entry['blockDaaScore'])
    for output in body['outputs']:
        genesis.fields(output, ('value', 'scriptPublicKey', 'covenant'))
    return body


def native_witness(case, expected, immutable_tail):
    """Bind the actual fixed proof push and redeem to this exact old head."""
    value = case['transaction']['inputs'][0]['signatureScript']
    genesis.need(type(value) is str, 'head-relation-native-witness-hex')
    raw = genesis.hx(value, len(value) // 2)
    redeem = b'\x4c\x70' + expected.state() + immutable_tail
    genesis.need(raw[:2] == b'\x4c\x80' and len(raw) >= 133,
                 'head-relation-fixed-native-proof-push')
    proof = raw[2:130]
    genesis.need(raw == b'\x4c\x80' + proof + b'\x4d' + len(redeem).to_bytes(2, 'little') + redeem,
                 'head-relation-exact-native-redeem-and-proof-frame')
    return proof


def case_projection(case, kind):
    """Adapt rehearsal_gate's public codec without importing operational tools.

    The existing complete-rehearsal module imports funding/network drivers.
    This finite copy uses the same native projection ABI and existing integer
    helpers, keeping this relation adapter free of those import side effects.
    The subsequent payment/Exit replay checks every reconstructed native field.
    """
    body, entries = case['transaction'], case['entries']
    genesis.need(kind in ('payment', 'exit') and body['version'] == 1 and body['lockTime'] == 0
                 and body['gas'] == 0 and body['subnetworkId'] == '00' * 20,
                 'head-relation-exact-native-header')
    source, entry = body['inputs'][0], entries[0]
    genesis.need(genesis.uint(source['sequence']) == (1 << 64) - 1, 'head-relation-exact-native-sequence')
    point = source['previousOutpoint']
    raw_point = genesis.hx(point['transactionId'], 32) + genesis.uint(point['index'], 32).to_bytes(4, 'little')
    genesis.need(entry['isCoinbase'] is False and entry['covenantId'] is None, 'head-relation-reserve-context-flags')
    payload = genesis.hx(body['payload'], 10492 if kind == 'payment' else 1604)
    prefix = (b'KPBAFX01' if kind == 'payment' else b'KPBXFX01') + b'\x01\0\x01\0'
    prefix += raw_point + b'\xff' * 8 + genesis.amount(entry['amount']).to_bytes(8, 'little')
    prefix += b'\x25\0' + genesis.hx(entry['scriptPublicKey'], 37) + len(body['outputs']).to_bytes(2, 'little')
    for output in body['outputs']:
        genesis.need(output['covenant'] is None and type(output['scriptPublicKey']) is str,
                     'head-relation-native-output-covenant')
        script = genesis.hx(output['scriptPublicKey'], len(output['scriptPublicKey']) // 2)
        genesis.need(len(script) in (36, 37), 'head-relation-native-output-script-width')
        prefix += genesis.amount(output['value']).to_bytes(8, 'little') + len(script).to_bytes(2, 'little') + script + b'\0'
    return prefix + bytes(36) + len(payload).to_bytes(4, 'little') + payload


def replay_relation(genesis_case, selected, trial_id, quoted_fee_sompi, transitions, verify_case):
    """Return plain canonical live-head JSON after all supplied checks pass.

    ``transitions`` is an ordered list of exact ``{kind, case}`` dictionaries;
    projection, witness and successor points are derived from their whole CASEs.
    ``verify_case(kind, case, projection, proof)`` is a required trusted-code
    callback, returning exactly True only after actual selected verification.
    For GEN3 its last two arguments are None. For payment it must check the
    selected aggregate/six Output/R0/native relation and SDK/NativeFull; for Exit
    the actual AuthExit proof and SDK/NativeFull. It is not a JSON verdict API.
    Fresh acceptance/current-UTXO checks and capability sealing remain outside.
    """
    genesis.need(callable(verify_case), 'head-relation-actual-verification-callback')
    genesis.amount(quoted_fee_sompi)
    admitted = genesis.validate_case(genesis_case, selected, trial_id,
        quoted_fee_sompi=quoted_fee_sompi, signed=True)
    checked_callback(verify_case, 'genesis', genesis_case, None, None)
    rows = [genesis.hx(row, 520) for row in admitted['outputs_hex520']]
    state = wallet_history.trees.PublicState([row[:32] for row in rows])
    point, reserve = genesis.hx(admitted['outpoint_hex36'], 36), genesis.RESERVE
    genesis.need(point[:32] != bytes(32), 'head-relation-nonzero-GEN3-id')
    genesis.need(type(transitions) is list, 'head-relation-ordered-whole-CASEs')
    seen_ids = {point[:32]}
    for event in transitions:
        genesis.fields(event, ('kind', 'case'))
        kind, case = event['kind'], event['case']
        genesis.need(kind in ('payment', 'exit') and point is not None, 'head-relation-live-transition')
        expected = wallet_history.context(selected.identity, point, state, reserve)
        body = transition_shape(case)
        # Freeze this immutable value before external verification. A callback
        # may replace a same-bytes transaction dictionary, detaching ``body``;
        # a later read through that alias must not select the next outpoint.
        txid = genesis.hx(body['id'], 32)
        projection = case_projection(case, kind)
        proof = native_witness(case, expected, selected.tail)
        if kind == 'payment':
            state, _, reserve = wallet_history.payment(projection, expected, state,
                                                       selected.tail, selected.verifier.verify)
        else:
            effect = exit_wire.require_current_head(projection, expected, selected.tail)
            following = state.copy()
            genesis.need(following.insert(effect.nf) == effect.witness, 'head-relation-exact-Exit-NF-witness')
            genesis.need(effect.next_state() == wallet_history.state_bytes(following, selected.identity[3]),
                         'head-relation-exact-Exit-successor-state')
            state, reserve = following, effect.new_reserve
        checked_callback(verify_case, kind, case, projection, proof)
        genesis.need(txid not in seen_ids, 'head-relation-no-repeated-transaction-id')
        seen_ids.add(txid)
        point = txid + bytes(4) if reserve else None
    # A terminal payout has no spendable financial head. Its separate terminal
    # recovery report must not be converted into a Context with a fake outpoint.
    context = wallet_history.context(selected.identity, point, state, reserve)
    return {'context_hex': context.encode().hex(),
        'commitments_hex32': [cm.hex() for cm in state.cms],
        'nullifiers': [{'value_hex32': value.hex(), 'successor_hex32': successor.hex(), 'successor_index': index}
                       for value, successor, index in state.entries]}
