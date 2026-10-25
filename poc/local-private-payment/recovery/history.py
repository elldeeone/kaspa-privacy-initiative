"""Complete public-history replay and original-seed local note discovery.

An independently selected genesis digest and exact current native checkpoint
are required. This module does not pick a canonical chain or turn a JSON flag
into accepted backing. Supplied-context evidence must be labelled as such.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from support import DOMAIN, MAX_VALUE, amount, digest, encoded, fields, hx, need, parse, uint


@dataclass
class History:
    state: object
    reserve: int
    point: bytes | None
    deliveries: list[bytes]
    exits: list[dict] = field(default_factory=list)
    payments: list[dict] = field(default_factory=list)

    def checkpoint(self):
        return {'state_hex112': self.state.state().hex(), 'reserve_sompi': self.reserve,
                'outpoint_hex36': None if self.point is None else self.point.hex()}


def checkpoint(value, wire):
    fields(value, ('state_hex112', 'reserve_sompi', 'outpoint_hex36'), 'checkpoint-fields')
    wire.parse_state(hx(value['state_hex112'], 112))
    reserve = uint(value['reserve_sompi'])
    need(reserve <= MAX_VALUE and (reserve == 0 or reserve >= wire.NOTE_FLOOR),
         'checkpoint-reserve-range')
    need((reserve == 0) == (value['outpoint_hex36'] is None), 'terminal-checkpoint-outpoint')
    if reserve:
        need(hx(value['outpoint_hex36'], 36)[:32] != bytes(32), 'checkpoint-nonzero-outpoint')
    return value


def _projection(value):
    need(type(value) is str and len(value) % 2 == 0
         and all(c in '0123456789abcdef' for c in value), 'canonical-projection-hex')
    return bytes.fromhex(value)


def load(raw, expected, genesis_sha256, assets):
    wire, relation = assets.wire, assets.relation
    expected = checkpoint(expected, wire)
    value = parse(raw)
    fields(value, ('schema', 'domain_hex32', 'genesis', 'transitions', 'head'), 'history-fields')
    need(value['schema'] == 'kpxa-local-private-history/v1' and value['domain_hex32'] == DOMAIN.hex(),
         'history-domain-and-version')
    initial = value['genesis']
    need(digest(encoded(initial)) == hx(genesis_sha256, 32).hex(), 'externally-selected-genesis')
    fields(initial, ('state_hex112', 'reserve_sompi', 'outpoint_hex36', 'outputs_hex520', 'deposit_sompi'),
           'history-genesis-fields')
    need(type(initial['outputs_hex520']) is list and initial['outputs_hex520'], 'genesis-outputs')
    rows = [hx(row, 520) for row in initial['outputs_hex520']]
    deposit = amount(initial['deposit_sompi'])
    initial_cv = relation.commit(deposit, bytes(32))
    for row in rows:
        wire.parse_output(row)
        relation.output(row)
        need(row[32:96] == initial_cv, 'genesis-proof-bound-public-deposit-value')
    state = assets.trees.PublicState([row[:32] for row in rows])
    need(state.state().hex() == initial['state_hex112'], 'complete-genesis-state')
    initial_head = {key: initial[key] for key in ('state_hex112', 'reserve_sompi', 'outpoint_hex36')}
    checkpoint(initial_head, wire)
    need(initial_head['reserve_sompi'] == deposit * len(rows) <= MAX_VALUE,
         'exact-genesis-native-reserve-backing')
    result = History(state, initial_head['reserve_sompi'], hx(initial_head['outpoint_hex36'], 36), rows)
    need(type(value['transitions']) is list, 'complete-transition-sequence')
    actions = set()
    for transition in value['transitions']:
        need(type(transition) is dict and transition.get('kind') in ('payment', 'exit'), 'transition-kind')
        need(result.point is not None, 'no-transition-after-terminal')
        kind = transition['kind']
        names = ('kind', 'projection_hex', 'successor_outpoint_hex36')
        fields(transition, names if kind == 'payment' else (*names, 'proof_hex128'),
               'history-transition-fields')
        raw_projection = _projection(transition['projection_hex'])
        if kind == 'payment':
            wire.require_current_head(raw_projection, state.state(), result.point, result.reserve, assets.tail)
            body = wire.parse_projection(raw_projection).body
            relation.verify('spend', wire.spend_statement(raw_projection), body.spends[0].proof)
            for output in body.outputs:
                relation.output(output.tuple_bytes)
            relation.balance([body.spends[0].cv], [o.cv for o in body.outputs], body.fee, body.delta)
            next_state, _, _ = state.transition('batch', [body.spends[0].nf],
                [o.cm for o in body.outputs], body.old_state.raw, body.new_state.raw, DOMAIN, b'KPXAST01')
            result.payments.append({'nf': body.spends[0].nf,
                'positions': tuple(range(len(result.deliveries), len(result.deliveries) + 2))})
            result.deliveries.extend(o.tuple_bytes for o in body.outputs)
        else:
            wire.require_current_exit_head(raw_projection, state.state(), result.point, result.reserve, assets.tail)
            body = wire.parse_exit_projection(raw_projection).body
            relation.verify('exit', wire.exit_statement(raw_projection), hx(transition['proof_hex128'], 128))
            next_state, _, _ = state.transition('exit', [body.nf], [], body.old_state.raw,
                                                body.new_state.raw, DOMAIN, b'KPXAST01')
            result.exits.append({'point': body.point, 'nf': body.nf, 'payout_spk': body.payout_spk,
                                 'delivery_count': len(result.deliveries), 'payout': body.payout,
                                 'fee': body.fee})
        need(body.action_id not in actions, 'duplicate-action-id')
        actions.add(body.action_id)
        result.state = state = next_state
        result.reserve = body.new_reserve
        successor = transition['successor_outpoint_hex36']
        need((result.reserve == 0) == (successor is None), 'transition-terminal-outpoint')
        result.point = None if successor is None else hx(successor, 36)
        need(result.point is None or result.point[:32] != bytes(32), 'successor-nonzero-outpoint')
        need(result.point is None or result.point != body.point, 'successor-outpoint-must-change')
    need(checkpoint(value['head'], wire) == result.checkpoint() == expected,
         'complete-history-must-match-exact-current-native-checkpoint')
    return result


@dataclass(repr=False)
class Claim:
    position: int
    receipt: object
    nf: bytes
    spent: bool
    kind: str = 'initial'


def claims(history, receiver, assets, *, require_owned_history=True):
    """No roster, index lookahead, role convention, private map or journal.

    Empty ownership is a failed recovery cohort check, including after all
    notes have exited: genuine historical spent receipts remain discoverable.
    This prevents a wrong seed from reporting successful empty restoration.
    """
    spent = set(history.state.nfs)
    owned = []
    for position, row in enumerate(history.deliveries):
        try:
            receipt = receiver.open(row[96:360])
        except assets.recipient.Invalid as error:
            if str(error) == 'crypto-unseal':
                continue
            raise
        need(receipt.domain == DOMAIN and receipt.commitment() == row[:32], 'recovered-receipt-domain-CM')
        amount(receipt.value_sompi)
        nullifier = receiver.nullifier(receipt, position)
        need(nullifier != bytes(32), 'recovered-nonzero-NF')
        owned.append(Claim(position, receipt, nullifier, nullifier in spent))
    need(owned or not require_owned_history, 'seed-not-in-authenticated-history-cohort')
    # Derive convenience labels locally from the full authenticated history,
    # never from a public role/index convention or remembered attempt map.
    # A wallet recognizes its own historical input NF using the original seed.
    own_nfs = {claim.nf for claim in owned}
    sources = {position: ('change' if payment['nf'] in own_nfs else 'received')
               for payment in history.payments for position in payment['positions']}
    for claim in owned:
        claim.kind = sources.get(claim.position, 'initial')
    return owned


def select(history, receiver, assets, *, position=None, minimum=None, kind='any'):
    minimum = assets.wire.NOTE_FLOOR if minimum is None else uint(minimum)
    owned = claims(history, receiver, assets)
    available = [c for c in owned if not c.spent and c.receipt.value_sompi >= minimum]
    need(kind in ('any', 'received', 'change', 'received-preferred'), 'private-note-selection-policy')
    if kind == 'received-preferred':
        preferred = [c for c in available if c.kind == 'received']
        available = preferred or [c for c in available if c.kind == 'change']
    elif kind != 'any':
        available = [c for c in available if c.kind == kind]
    if position is not None:
        uint(position, 32)
        available = [c for c in available if c.position == position]
    need(available, 'no-current-unspent-owned-claim')
    return max(available, key=lambda c: (c.receipt.value_sompi, -c.position))
