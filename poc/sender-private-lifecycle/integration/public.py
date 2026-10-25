"""Unchanged financial history with sender-private joint-result assembly.

These functions verify exact bytes/roots/lineage, not G16 proofs or chain
acceptance. Owner workers and the selected native/chain verifiers independently
establish those separate facts. No private note or ownership-map input exists.
"""
from copy import deepcopy
import importlib.util
from pathlib import Path
import re
import struct
import sys

from trees import PublicState, need, sha

HERE = Path(__file__).resolve().parent
DOMAIN = bytes.fromhex('be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480')
MAGIC = b'KPX8ST01'
MAX_VALUE = 2_870_000_000_000_000_000
NOTE_FLOOR = 60_000_000
Q = 2736030358979909402780800718157159386076813972158567259200215660948447373041


def load_wire():
    name = 'kpx8_lifecycle_integration_wire'
    if name not in sys.modules:
        local = HERE.parent / 'verification/wire.py'
        selected = local if local.is_file() else HERE.parents[2] / 'poc/owner-private-lifecycle/verification/wire.py'
        spec = importlib.util.spec_from_file_location(name, selected)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def hx(value, length):
    need(type(value) is str and re.fullmatch('[0-9a-f]{' + str(length * 2) + '}', value),
         'canonical-public-hex')
    return bytes.fromhex(value)


def fields(value, keys, reason):
    need(type(value) is dict and set(value) == set(keys), reason)


def amount(value, *, positive=False):
    need(type(value) is int and (0 < value if positive else 0 <= value) and value <= MAX_VALUE,
         'integer-sompi-range')
    return value


def roster_digest(roster):
    need(type(roster) is list and len(roster) == len(set(roster)) == 3,
         'three-distinct-public-participants')
    return sha(b'KPX8RO01', *(hx(value, 32) for value in roster))


def current_entry_context(history, native_tail_hex, value):
    """Join an independently acquired current UTXO; no chain authority flag."""
    _, head = reconstruct(history)
    fields(value, ('outpoint', 'entry'), 'selected-current-UTXO-fields')
    point, entry = value['outpoint'], value['entry']
    fields(point, ('transactionId', 'index'), 'selected-current-UTXO-point')
    need(type(point['index']) is int and 0 <= point['index'] < 1 << 32, 'current-UTXO-index')
    actual_point = hx(point['transactionId'], 32) + point['index'].to_bytes(4, 'little')
    need(head['outpoint_hex36'] is not None and actual_point == hx(head['outpoint_hex36'], 36),
         'current-UTXO-exact-history-head')
    fields(entry, ('amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'),
           'selected-current-UTXO-entry')
    need(type(entry['amount']) is int and entry['amount'] == head['reserve_sompi']
         and entry['scriptPublicKey'] == load_wire().state_spk(hx(head['state_hex112'], 112),
                                                            bytes.fromhex(native_tail_hex)).hex()
         and entry['isCoinbase'] is False and entry['covenantId'] is None,
         'current-UTXO-exact-reserve-policy-metadata')
    need(type(entry['blockDaaScore']) is int and 0 <= entry['blockDaaScore'] < 1 << 64,
         'current-UTXO-canonical-DAA')
    return entry['blockDaaScore']


def mixed_rows(value, session_sha256):
    fields(value, ('schema', 'session_sha256', 'rows_hex', 'delta_decimal', 'tuple_bytes',
                   'row_count', 'scope'), 'exact-common-MPC-result')
    need(value['schema'] == 'kpx8-mixed-complete-outputs/v1'
         and value['session_sha256'] == session_sha256 and type(value['tuple_bytes']) is int
         and value['tuple_bytes'] == 520 and type(value['row_count']) is int and value['row_count'] == 6
         and value['scope'] == 'CHECKED_MPC_OUTPUTS_NOT_FINANCIAL_AUTHORIZATION',
         'common-MPC-session-and-output-shape')
    need(type(value['rows_hex']) is list and len(value['rows_hex']) == 6, 'six-complete-mixed-rows')
    rows = [hx(row, 520) for row in value['rows_hex']]
    need(len(set(rows)) == len({row[:32] for row in rows}) == 6
         and all(sha(row[96:360]) == row[360:392] for row in rows), 'mixed-complete-CM-CF-bindings')
    decimal = value['delta_decimal']
    need(type(decimal) is str and re.fullmatch('0|[1-9][0-9]*', decimal), 'canonical-aggregate-decimal')
    delta = int(decimal)
    need(0 <= delta < Q, 'canonical-BabyJubjub-aggregate')
    return rows, delta.to_bytes(32, 'little')


def initial_record(raw):
    need(type(raw) is bytes and len(raw) == 496, 'GN3-record-width')
    note, cm, cf, cfh = raw[:168], raw[168:200], raw[200:464], raw[464:]
    need(sha(b'KPX1NOT\0', DOMAIN, note) == cm and sha(cf) == cfh, 'GN3-record-CM-CF-binding')
    value = int.from_bytes(note[64:72], 'little')
    need(NOTE_FLOOR <= value <= MAX_VALUE, 'GN3-note-value-range')
    return cm, cf, value


def genesis(records, point):
    need(type(records) is list and len(records) == 3, 'three-authenticated-founding-records')
    decoded = [initial_record(record) for record in records]
    state = PublicState([row[0] for row in decoded])
    reserve = amount(sum(row[2] for row in decoded), positive=True)
    need(hx(point, 36)[:32] != bytes(32), 'nonzero-founding-point')
    initial = {'state_hex112': state.state(DOMAIN, MAGIC).hex(), 'reserve_sompi': reserve,
               'outpoint_hex36': point, 'records_hex496': [row.hex() for row in records]}
    return {'schema': 'kpx8-owner-private-history/v1', 'domain_hex32': DOMAIN.hex(),
            'genesis': initial, 'transitions': [],
            'head': {key: initial[key] for key in ('state_hex112', 'reserve_sompi', 'outpoint_hex36')}}


def reconstruct(history):
    """Return independently reconstructed trees/head; no acceptance flag exists."""
    wire = load_wire()
    fields(history, ('schema', 'domain_hex32', 'genesis', 'transitions', 'head'), 'exact-public-history-fields')
    need(history['schema'] == 'kpx8-owner-private-history/v1'
         and history['domain_hex32'] == DOMAIN.hex(), 'history-domain-schema')
    first = history['genesis']
    fields(first, ('state_hex112', 'reserve_sompi', 'outpoint_hex36', 'records_hex496'),
           'exact-founding-history-fields')
    need(type(first['records_hex496']) is list and len(first['records_hex496']) == 3,
         'three-founding-history-records')
    generated = genesis([hx(row, 496) for row in first['records_hex496']], first['outpoint_hex36'])
    need(first == generated['genesis'], 'independently-reconstructed-founding-history')
    state = PublicState([hx(row, 496)[168:200] for row in first['records_hex496']])
    reserve, point = first['reserve_sompi'], first['outpoint_hex36']
    need(type(history['transitions']) is list, 'ordered-public-transition-list')
    seen_points = {point}
    for record in history['transitions']:
        need(type(record) is dict and record.get('kind') in ('batch', 'exit'), 'history-transition-kind')
        batch = record['kind'] == 'batch'
        fields(record, ('kind', 'session', 'projection_hex', 'successor_outpoint_hex36') if batch else
               ('kind', 'projection_hex', 'proof_hex128', 'successor_outpoint_hex36'),
               'exact-history-transition-fields')
        need(point is not None, 'no-transition-after-terminal-exit')
        raw = hx(record['projection_hex'], 10973 if batch else len(record['projection_hex']) // 2)
        if batch:
            wire.validate_public(raw)
            projection = wire.parse_projection(raw)
            body = projection.body
            # The exact canonical session bytes are independently checked by
            # the session codec/owners. Here its digest/roster bind the body.
            session = record['session']
            fields(session, ('schema', 'session_id', 'domain_hex', 'prior_state_digest',
                'circuit_profile_sha256', 'public_effects_context_sha256', 'roster',
                'program_source_sha256', 'tuple_bytes', 'outputs_per_party', 'mpc_prime'),
                'history-session-fields')
            from codec import canonical_json, session as parse_session
            parse_session(canonical_json(session), session['program_source_sha256'])
            need(session['schema'] == 'kpx8-private-construction-session/v1'
                 and session['domain_hex'] == DOMAIN.hex()
                 and sha(canonical_json(session)) == body.session
                 and session['prior_state_digest'] == sha(body.old_state.raw).hex()
                 and roster_digest(session['roster']) == body.roster,
                 'history-session-state-roster-join')
            next_state, witnesses, paths = state.transition('batch', [row.nf for row in body.spends],
                [row.cm for row in body.outputs], body.old_state.raw, body.new_state.raw, DOMAIN, MAGIC)
            need(witnesses == list(body.nf_witnesses) and paths == list(body.cm_paths),
                 'history-exact-sequential-paths')
        else:
            wire.validate_exit_public(raw)
            projection = wire.parse_exit_projection(raw)
            body = projection.body
            hx(record['proof_hex128'], 128)
            next_state, witnesses, _ = state.transition('exit', [body.nf], [],
                body.old_state.raw, body.new_state.raw, DOMAIN, MAGIC)
            need(witnesses == [body.nf_witness], 'history-exact-exit-path')
        need(body.point == hx(point, 36) and body.old_reserve == reserve,
             'history-current-outpoint-reserve-required')
        successor = record['successor_outpoint_hex36']
        if body.new_reserve:
            need(hx(successor, 36)[32:] == bytes(4) and successor not in seen_points,
                 'fresh-output-zero-reserve-successor')
            seen_points.add(successor)
        else:
            need(successor is None, 'terminal-history-has-no-reserve-successor')
        state, reserve, point = next_state, body.new_reserve, successor
    expected = {'state_hex112': state.state(DOMAIN, MAGIC).hex(), 'reserve_sompi': reserve,
                'outpoint_hex36': point}
    need(history['head'] == expected, 'exact-reconstructed-history-head')
    return state, expected


def extend(history, transition):
    reconstruct(history)
    result = deepcopy(history)
    result['transitions'].append(deepcopy(transition))
    batch = transition['kind'] == 'batch'
    raw = bytes.fromhex(transition['projection_hex'])
    body = (load_wire().parse_projection(raw) if batch else load_wire().parse_exit_projection(raw)).body
    result['head'] = {'state_hex112': body.new_state.raw.hex(), 'reserve_sompi': body.new_reserve,
                      'outpoint_hex36': transition['successor_outpoint_hex36']}
    reconstruct(result)
    return result


def premix_context(history, profile_sha256, fee, native_tail):
    _, head = reconstruct(history)
    hx(profile_sha256, 32)
    amount(fee, positive=True)
    need(head['outpoint_hex36'] is not None and fee < head['reserve_sompi'], 'continuing-premix-fee')
    tail = bytes.fromhex(native_tail)
    need(type(native_tail) is str and tail.hex() == native_tail and 0 < len(tail) <= 65535 - 114,
         'selected-native-tail')
    return {'schema': 'kpx8-wallet-premix-context/v1', 'domain_hex32': DOMAIN.hex(),
        'component_profile_sha256': profile_sha256, 'prior_state_hex112': head['state_hex112'],
        'previous_outpoint_hex36': head['outpoint_hex36'], 'reserve_sompi': head['reserve_sompi'],
        'fee_sompi': fee, 'fee_shares_sompi': [fee // 3, fee // 3, fee - 2 * (fee // 3)],
        'native_tail_hex': native_tail}


def body_core(history, inputs, rows, delta, session_sha256, roster, fee):
    state, head = reconstruct(history)
    need(type(inputs) is list and len(inputs) == 3 and all(type(row) is tuple and len(row) == 2
         and type(row[0]) is bytes and len(row[0]) == 32 and type(row[1]) is bytes
         and len(row[1]) == 64 for row in inputs), 'three-public-NF-CV-records')
    need(type(rows) is list and len(rows) == 6 and all(type(row) is bytes and len(row) == 520
         for row in rows), 'six-complete-public-output-tuples')
    need(type(delta) is bytes and len(delta) == 32 and int.from_bytes(delta, 'little') < Q,
         'canonical-global-delta')
    need(all(sha(row[96:360]) == row[360:392] for row in rows), 'complete-output-ciphertext-hashes')
    fee = amount(fee, positive=True)
    reserve = head['reserve_sompi']
    need(head['outpoint_hex36'] is not None and NOTE_FLOOR <= reserve - fee <= MAX_VALUE,
         'batch-exact-fee-and-continuing-reserve')
    old = state.state(DOMAIN, MAGIC)
    witnesses = [state.insert(nf) for nf, _ in inputs]
    paths = [state.append(row[:32]) for row in rows]
    body = (b'KPX8PB01' + struct.pack('<4H', 1, 3, 6, 0) + DOMAIN + hx(session_sha256, 32)
        + roster_digest(roster) + hx(head['outpoint_hex36'], 36) + old + reserve.to_bytes(8, 'little')
        + state.state(DOMAIN, MAGIC) + (reserve - fee).to_bytes(8, 'little') + fee.to_bytes(8, 'little')
        + bytes(8) + delta + b''.join(nf + cv for nf, cv in inputs) + b''.join(rows)
        + b''.join(witnesses) + b''.join(paths) + bytes(384))
    load_wire().parse_body(body)
    return body


def attach_spend_proofs(projection, proofs):
    wire = load_wire()
    before = wire.validate_public(projection)
    need(type(proofs) is list and len(proofs) == 3
         and all(type(proof) is bytes and len(proof) == 128 for proof in proofs),
         'three-public-Spend-proofs')
    result = projection[:-384] + b''.join(proofs)
    after = wire.validate_public(result)
    need(before['effects_digest_hex32'] == after['effects_digest_hex32'],
         'Spend-proof-attachment-preserves-exact-effects')
    return result


def admitted_body(history, mixed, session_sha256, roster, fee):
    """Use only the checked joint admission projection, never owner READY rows.

    The MPC result is not financial authorization. The existing owner checks,
    nine-proof verifier, outer proof and native execution remain mandatory.
    """
    from codec import validate_admission
    inputs, rows, delta = validate_admission(mixed, session_sha256)
    return body_core(history, [(row[:32], row[32:]) for row in inputs], rows,
                     delta.to_bytes(32, 'little'), session_sha256, roster, fee)


def matched_authorizations(projection, mixed):
    """Return exact input-order proofs from a complete unlabelled bijection.

    Matching does not verify Groth16. The caller must run the selected genuine
    financial verifier before promoting this projection to usable authority.
    """
    from codec import match_authorizations, validate_authorizations
    wire = load_wire()
    wire.validate_public(projection)
    body = wire.parse_projection(projection).body
    rows = validate_authorizations(mixed, body.session.hex(), wire.effects_digest(projection).hex())
    inputs = [spend.nf + spend.cv for spend in body.spends]
    return match_authorizations(inputs, rows)


def finalized_projection(projection, mixed):
    return attach_spend_proofs(projection, matched_authorizations(projection, mixed))


def exit_body(history, nf, payout_spk, gross, fee, session_sha256):
    state, head = reconstruct(history)
    need(type(nf) is bytes and len(nf) == 32 and type(payout_spk) is bytes and len(payout_spk) == 36,
         'public-exit-NF-and-recipient-width')
    gross, fee = amount(gross, positive=True), amount(fee, positive=True)
    payout, remaining = gross - fee, head['reserve_sompi'] - gross
    need(payout >= load_wire().PAYOUT_FLOOR and (remaining == 0 or remaining >= NOTE_FLOOR)
         and head['outpoint_hex36'] is not None, 'exact-full-note-exit-money')
    old = state.state(DOMAIN, MAGIC)
    witness = state.insert(nf)
    body = (b'KPX8XB01' + struct.pack('<4H', 1, 1, 0, 1) + DOMAIN + hx(session_sha256, 32)
        + bytes(32) + hx(head['outpoint_hex36'], 36) + old + head['reserve_sompi'].to_bytes(8, 'little')
        + state.state(DOMAIN, MAGIC) + remaining.to_bytes(8, 'little') + fee.to_bytes(8, 'little')
        + payout.to_bytes(8, 'little') + payout_spk + nf + witness)
    load_wire().parse_exit_body(body)
    return body
