"""Reconstruct public state against a separately selected current checkpoint.

This verifies public roots and component proofs. It does not select a canonical
Kaspa chain: the caller must obtain its checkpoint from the reviewed chain
reader. A JSON flag can never make history accepted or current.
"""
from dataclasses import dataclass, field

from paths import fields, hx, need, parse, uint
from support import DOMAIN, MAX_VALUE, recipient
from trees import PublicState, sha


def invoice_index(session_sha, sender, role):
    need(type(sender) is int and 0 <= sender < 3
         and role in (b'PAYMENT\0', b'CHANGE\0\0'), 'invoice-purpose')
    raw = sha(b'KPX8IV01', hx(session_sha, 32), sender.to_bytes(4, 'little'), role)
    index = int.from_bytes(raw[:8], 'little')
    need(index not in (0, 0xffffffff), 'reserved-invoice-index-collision')
    return index


@dataclass
class History:
    state: PublicState
    reserve: int
    point: bytes | None
    deliveries: list
    sessions: list
    exits: list = field(default_factory=list)

    def checkpoint(self):
        return {'state_hex112': self.state.state(DOMAIN).hex(),
                'reserve_sompi': self.reserve,
                'outpoint_hex36': None if self.point is None else self.point.hex()}


def checkpoint(value, wire):
    fields(value, ('state_hex112', 'reserve_sompi', 'outpoint_hex36'), 'checkpoint-fields')
    wire.parse_state(hx(value['state_hex112'], 112))
    reserve = uint(value['reserve_sompi'])
    need(reserve <= MAX_VALUE, 'checkpoint-reserve-range')
    point = value['outpoint_hex36']
    need((reserve == 0) == (point is None), 'terminal-checkpoint-point')
    if point is not None:
        need(hx(point, 36)[:32] != bytes(32), 'checkpoint-nonzero-point')
    return value


def load(raw, expected, relation, wire, codec, program_sha):
    expected = checkpoint(expected, wire)
    value = parse(raw)
    fields(value, ('schema', 'domain_hex32', 'genesis', 'transitions', 'head'), 'history-fields')
    need(value['schema'] == 'kpx8-owner-private-history/v1'
         and value['domain_hex32'] == DOMAIN.hex(), 'history-domain')
    initial = value['genesis']
    fields(initial, ('state_hex112', 'reserve_sompi', 'outpoint_hex36', 'records_hex496'),
           'history-genesis-fields')
    records = initial['records_hex496']
    need(type(records) is list and len(records) == 3, 'three-initial-records')
    records = [hx(row, 496) for row in records]
    cms, deliveries, total = [], [], 0
    for row in records:
        note, cm, cf, cfh = row[:168], row[168:200], row[200:464], row[464:]
        note_value = int.from_bytes(note[64:72], 'little')
        need(wire.NOTE_FLOOR <= note_value <= MAX_VALUE
             and sha(b'KPX1NOT\0', DOMAIN, note) == cm and sha(cf) == cfh,
             'initial-note-CM-CFH-and-range')
        cms.append(cm); deliveries.append((cm, cf)); total += note_value
    state = PublicState(cms)
    reserve = uint(initial['reserve_sompi'])
    need(state.state(DOMAIN).hex() == initial['state_hex112']
         and total == reserve <= MAX_VALUE, 'genesis-state-and-full-reserve')
    point = hx(initial['outpoint_hex36'], 36)
    need(point[:32] != bytes(32), 'initial-reserve-point')
    result = History(state, total, point, deliveries, [])
    need(type(value['transitions']) is list, 'complete-transition-list')
    for transition in value['transitions']:
        need(type(transition) is dict and transition.get('kind') in ('batch', 'exit'),
             'history-transition-kind')
        need(result.point is not None, 'no-transition-after-terminal')
        if transition['kind'] == 'batch':
            fields(transition, ('kind', 'session', 'projection_hex', 'successor_outpoint_hex36'),
                   'batch-history-fields')
            raw_projection = bytes.fromhex(transition['projection_hex'])
            need(raw_projection.hex() == transition['projection_hex'], 'canonical-batch-hex')
            wire.validate_public(raw_projection)
            projection = wire.parse_projection(raw_projection); body = projection.body
            session_raw = codec.canonical_json(transition['session'])
            session, session_sha = codec.session(session_raw, program_sha)
            need(body.session.hex() == session_sha
                 and body.roster == sha(b'KPX8RO01', *(hx(p, 32) for p in session['roster']))
                 and session['prior_state_digest'] == sha(body.old_state.raw).hex(),
                 'history-session-and-roster')
            need(body.point == result.point and body.old_state.raw == state.state(DOMAIN)
                 and body.old_reserve == result.reserve, 'continuous-batch-native-state')
            effects = wire.effects_digest(raw_projection)
            for spend in body.spends:
                statement = b'KPX8SP01' + DOMAIN + body.old_state.cm_root + spend.nf + spend.cv + effects
                relation.verify('spend', statement, spend.proof)
                state.insert(spend.nf)
            for out in body.outputs:
                relation.output(out.tuple_bytes)
                state.append(out.cm); result.deliveries.append((out.cm, out.cf))
            relation.balance([s.cv for s in body.spends], [o.cv for o in body.outputs],
                             body.fee, body.delta)
            need(state.state(DOMAIN) == body.new_state.raw, 'reconstructed-batch-successor')
            result.sessions.append((session_sha, session['roster']))
            result.reserve = body.new_reserve
        else:
            fields(transition, ('kind', 'projection_hex', 'proof_hex128', 'successor_outpoint_hex36'),
                   'exit-history-fields')
            raw_projection = bytes.fromhex(transition['projection_hex'])
            need(raw_projection.hex() == transition['projection_hex'], 'canonical-exit-hex')
            wire.validate_exit_public(raw_projection)
            projection = wire.parse_exit_projection(raw_projection); body = projection.body
            need(body.point == result.point and body.old_state.raw == state.state(DOMAIN)
                 and body.old_reserve == result.reserve, 'continuous-exit-native-state')
            effects = wire.exit_effects_digest(raw_projection)
            statement = (b'KPX8EX01' + DOMAIN + body.old_state.cm_root + body.nf + effects
                         + body.payout.to_bytes(8, 'little') + body.fee.to_bytes(8, 'little'))
            relation.verify('exit', statement, hx(transition['proof_hex128'], 128))
            result.exits.append({'point': body.point, 'nf': body.nf, 'payout_spk': body.payout_spk,
                                 'delivery_count': len(result.deliveries), 'session_count': len(result.sessions)})
            state.insert(body.nf)
            need(state.state(DOMAIN) == body.new_state.raw, 'reconstructed-exit-successor')
            result.reserve = body.new_reserve
        successor = transition['successor_outpoint_hex36']
        need((result.reserve == 0) == (successor is None), 'transition-terminal-point')
        result.point = None if successor is None else hx(successor, 36)
        need(result.point is None or result.point[:32] != bytes(32), 'successor-nonzero-point')
    need(checkpoint(value['head'], wire) == result.checkpoint() == expected,
         'reconstructed-history-must-match-selected-checkpoint')
    return result


def claims(history, wallet, participant):
    """The caller keeps this return value inside the owner namespace."""
    changes = set()
    for session_sha, roster in history.sessions:
        if participant in roster:
            changes.add(invoice_index(session_sha, roster.index(participant), b'CHANGE\0\0'))
    spent = {row[0] for row in history.state.entries}
    owned = []
    for position, (cm, cf) in enumerate(history.deliveries):
        try:
            receipt = wallet.open(cf)
        except recipient().Invalid as error:
            # Only the narrow adapter's actual unseal rejection means this
            # ciphertext is foreign. A successfully decrypted invalid receipt,
            # wrong descriptor/domain or broken crypto dependency is an error.
            if str(error) == 'crypto-unseal':
                continue
            raise
        need(receipt.commitment() == cm, 'recovered-delivery-CM')
        nf = wallet.nullifier(receipt, position)
        kind = 'initial' if receipt.index == 0 else 'change' if receipt.index in changes else 'received'
        owned.append({'position': position, 'receipt': receipt, 'nf': nf,
                      'spent': nf in spent, 'kind': kind})
    return owned
