"""One wallet constructs and consents to exactly one private payment.

Secret output roles/order, receipts and blinds are owner-local objects. Only
the complete role-free projection leaves the worker. There is no MPC party,
permanent note lock, witness server or public recovery roster.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets

import history
from support import DOMAIN, MAX_VALUE, MIN_NOTE, Q, amount, digest, fee_amount, hx, need, uint


@dataclass(repr=False)
class CreatedOutput:
    row: bytes
    receipt: object
    blind: bytes


def fresh_index(receiver, owned=()):
    used = {claim.receipt.index for claim in owned} | {0, 0xffffffff}
    while True:
        index = secrets.randbits(64)
        if index not in used:
            return index


def output(assets, invoice, value, *, blind=None):
    invoice.encode()
    need(invoice.domain == DOMAIN, 'selected-invoice-domain')
    receipt = assets.recipient.Receipt.for_invoice(invoice, amount(value), secrets.token_bytes(32))
    cf = assets.crypto.seal(invoice.delivery_pk, receipt.encode())
    need(len(cf) == 264, 'encrypted-receipt-width')
    blind = secrets.randbelow(Q).to_bytes(32, 'little') if blind is None else blind
    cv = assets.relation.commit(value, blind)
    statement = b'KPXAOU01' + DOMAIN + receipt.commitment() + cv + hashlib.sha256(cf).digest()
    proof = assets.relation.prove('output', statement,
        {'schema': 'kpxa-local-private-output-witness/v1',
         'note_hex168': receipt.note_bytes().hex(), 'blind_hex32': blind.hex()})
    row = assets.wire.build_output(receipt.commitment(), cv, cf, proof)
    assets.relation.output(row)
    return CreatedOutput(row, receipt, blind)


@dataclass(repr=False)
class Draft:
    projection: bytes
    claim: object
    input_blind: bytes
    payment: CreatedOutput
    change: CreatedOutput
    authenticated_invoice: bytes
    authenticated_invoice_sha256: str
    payment_sompi: int
    fee_sompi: int
    action_id: bytes


def prepare(assets, accepted, receiver, *, invoice_raw, invoice_sha256,
            payment_sompi, fee_sompi, position=None, selection_kind='any'):
    """Exact invoice digest must come from the owner's authenticated channel.

    Encryption alone never supplies that authentication. It is a private
    caller input and never appears in the public projection or status export.
    """
    need(type(invoice_raw) is bytes and len(invoice_raw) == 208
         and digest(invoice_raw) == hx(invoice_sha256, 32).hex(), 'authenticated-exact-invoice-required')
    invoice = assets.recipient.Invoice.parse(invoice_raw)
    need(invoice.domain == DOMAIN, 'authenticated-invoice-domain')
    amount(payment_sompi)
    fee_amount(fee_sompi)
    owned = history.claims(accepted, receiver, assets)
    claim = history.select(accepted, receiver, assets, position=position,
                           minimum=payment_sompi + MIN_NOTE + fee_sompi, kind=selection_kind)
    change_value = claim.receipt.value_sompi - payment_sompi - fee_sompi
    amount(change_value)
    need(accepted.point is not None and accepted.reserve - fee_sompi >= MIN_NOTE,
         'continuing-reserve-required')
    # A fresh private random index has no publicly derivable payment/change
    # meaning. Receipt216 encrypts it and original-seed discovery reads it back.
    change_invoice = receiver.invoice(fresh_index(receiver, owned))
    need(change_invoice != invoice, 'distinct-payment-and-change-descriptors')
    payment = output(assets, invoice, payment_sompi)
    change = output(assets, change_invoice, change_value)
    need(receiver.open(change.row[96:360]).encode() == change.receipt.encode(),
         'own-change-delivery-before-authorization')
    rows = [payment.row, change.row]
    if secrets.randbelow(2):
        rows.reverse()
    need(rows[0][:32] != rows[1][:32], 'distinct-output-CMs')
    blind = secrets.randbelow(Q).to_bytes(32, 'little')
    cv = assets.relation.commit(claim.receipt.value_sompi, blind)
    delta = ((int.from_bytes(blind, 'little') - int.from_bytes(payment.blind, 'little')
              - int.from_bytes(change.blind, 'little')) % Q).to_bytes(32, 'little')
    following = accepted.state.copy()
    witness = following.insert(claim.nf)
    paths = [following.append(row[:32]) for row in rows]
    action = secrets.token_bytes(32)
    need(action != bytes(32), 'nonzero-action-id')
    core = assets.wire.build_body_core(action_id=action, point=accepted.point,
        old_state=accepted.state.state(), new_state=following.state(),
        old_reserve=accepted.reserve, new_reserve=accepted.reserve - fee_sompi,
        fee=fee_sompi, delta=delta, nf=claim.nf, cv=cv, outputs=rows,
        nf_witness=witness, cm_paths=paths)
    projection = assets.wire.build_projection(core + bytes(128), assets.tail)
    return Draft(projection, claim, blind, payment, change, invoice_raw,
                 invoice_sha256, payment_sompi, fee_sompi, action)


def consent(assets, accepted, receiver, draft, projection=None):
    """Reconstruct state, private intent and every public effect independently.

    Called again immediately before generating Spend authority. Substituted
    tuples/CF/values/fee/current outpoint/policy/order require exact validation.
    """
    raw = draft.projection if projection is None else projection
    assets.wire.require_current_head(raw, accepted.state.state(), accepted.point,
                                     accepted.reserve, assets.tail)
    body = assets.wire.parse_projection(raw).body
    need(body.action_id == draft.action_id and body.fee == draft.fee_sompi and body.payout == 0,
         'exact-owner-approved-action-fee')
    need(digest(draft.authenticated_invoice) == draft.authenticated_invoice_sha256,
         'unchanged-authenticated-recipient-invoice')
    invoice = assets.recipient.Invoice.parse(draft.authenticated_invoice)
    payment, change = draft.payment, draft.change
    need(payment.receipt.invoice(invoice.delivery_pk) == invoice
         and payment.receipt.value_sompi == draft.payment_sompi,
         'exact-authenticated-payment-descriptor-and-value')
    receiver.validate_invoice(change.receipt.invoice(receiver.invoice(change.receipt.index).delivery_pk))
    need(receiver.open(change.row[96:360]).encode() == change.receipt.encode(), 'own-recoverable-change')
    rows = [out.tuple_bytes for out in body.outputs]
    need(rows.count(payment.row) == rows.count(change.row) == 1, 'each-owner-created-output-exactly-once')
    need(rows == [out.tuple_bytes for out in assets.wire.parse_projection(draft.projection).body.outputs],
         'preserve-owner-secret-output-order')
    for created in (payment, change):
        need(created.receipt.commitment() == created.row[:32]
             and assets.relation.commit(created.receipt.value_sompi, created.blind) == created.row[32:96],
             'created-output-note-and-CV-opening')
        assets.relation.output(created.row)
    selected = history.select(accepted, receiver, assets, position=draft.claim.position)
    need(selected.receipt.encode() == draft.claim.receipt.encode() and selected.nf == draft.claim.nf,
         'exact-current-owned-note')
    amount(selected.receipt.value_sompi)
    need(selected.receipt.value_sompi == payment.receipt.value_sompi
         + change.receipt.value_sompi + draft.fee_sompi, 'owner-integer-value-conservation')
    cv = assets.relation.commit(selected.receipt.value_sompi, draft.input_blind)
    need(body.spends[0].nf == selected.nf and body.spends[0].cv == cv, 'exact-owner-NF-CV')
    following, witnesses, paths = accepted.state.transition('batch', [selected.nf],
        [out.cm for out in body.outputs], body.old_state.raw, body.new_state.raw, DOMAIN, b'KPXAST01')
    need(tuple(witnesses) == body.nf_witnesses and tuple(paths) == body.cm_paths,
         'independently-reconstructed-state-paths')
    delta = ((int.from_bytes(draft.input_blind, 'little') - int.from_bytes(payment.blind, 'little')
              - int.from_bytes(change.blind, 'little')) % Q).to_bytes(32, 'little')
    need(body.delta == delta and following.state() == body.new_state.raw, 'exact-blinding-and-successor')
    assets.relation.balance([cv], [o.cv for o in body.outputs], body.fee, body.delta)
    return raw


def authorize(assets, accepted, receiver, draft, projection=None, *, before_proof=None):
    raw = consent(assets, accepted, receiver, draft, projection)
    if before_proof is not None:
        before_proof(raw)
    claim = draft.claim
    keys = receiver.keys(claim.receipt.index)
    path = accepted.state.cm.path(claim.position)
    statement = assets.wire.spend_statement(raw)
    proof = assets.relation.prove('spend', statement,
        {'schema': 'kpxa-local-private-spend-witness/v1', 'note_hex168': claim.receipt.note_bytes().hex(),
         's_hex32': keys.owner_secret.hex(), 'k_hex32': keys.nf_secret.hex(), 'position': claim.position,
         'cm_path_hex': [path[i:i + 32].hex() for i in range(0, 512, 32)],
         'blind_hex32': draft.input_blind.hex()})
    return assets.wire.attach_spend_proof(raw, proof)


def payout_index(accepted, owned, claim):
    """Re-derive a historical payout index from accepted public effects."""
    need(accepted.point is not None, 'live-exit-point')
    used = {c.receipt.index for c in owned} | {0, 0xffffffff}
    for counter in range(1 << 32):
        raw = hashlib.sha256(b'KPXAEK01' + DOMAIN + accepted.point + claim.nf
                             + counter.to_bytes(4, 'little')).digest()
        index = int.from_bytes(raw[:8], 'little')
        if index not in used:
            return index
    raise ValueError('payout-key-index-exhausted')


def payout_spk(accepted, receiver, owned, claim):
    return b'\0\0\x20' + receiver.keys(payout_index(accepted, owned, claim)).invoice.native_pk + b'\xac'


def independent_exit(assets, accepted, receiver, *, fee_sompi, position=None, before_proof=None):
    """Direct fresh Exit152/G16 path; no outer prover or live other owner."""
    fee_amount(fee_sompi)
    owned = history.claims(accepted, receiver, assets)
    claim = history.select(accepted, receiver, assets, position=position)
    payout = claim.receipt.value_sompi - fee_sompi
    need(assets.wire.PAYOUT_FLOOR <= payout <= MAX_VALUE, 'full-note-payout-range')
    remaining = accepted.reserve - claim.receipt.value_sompi
    need(remaining == 0 or MIN_NOTE <= remaining <= MAX_VALUE, 'exit-continuation-range')
    following = accepted.state.copy()
    witness = following.insert(claim.nf)
    spk = payout_spk(accepted, receiver, owned, claim)
    action = secrets.token_bytes(32)
    body = assets.wire.build_exit_body(action_id=action, point=accepted.point,
        old_state=accepted.state.state(), new_state=following.state(), old_reserve=accepted.reserve,
        new_reserve=remaining, fee=fee_sompi, payout=payout, payout_spk=spk,
        nf=claim.nf, nf_witness=witness)
    raw = assets.wire.build_exit_projection(body, assets.tail)
    assets.wire.require_current_exit_head(raw, accepted.state.state(), accepted.point,
                                          accepted.reserve, assets.tail)
    parsed = assets.wire.parse_exit_projection(raw).body
    need(parsed.payout_spk == spk and parsed.payout + parsed.fee == claim.receipt.value_sompi
         and parsed.nf == receiver.nullifier(claim.receipt, claim.position), 'exact-owner-exit-consent')
    if before_proof is not None:
        before_proof(raw)
    keys = receiver.keys(claim.receipt.index)
    path = accepted.state.cm.path(claim.position)
    proof = assets.relation.prove('exit', assets.wire.exit_statement(raw),
        {'schema': 'kpxa-local-private-exit-witness/v1', 'note_hex168': claim.receipt.note_bytes().hex(),
         's_hex32': keys.owner_secret.hex(), 'k_hex32': keys.nf_secret.hex(), 'position': claim.position,
         'cm_path_hex': [path[i:i + 32].hex() for i in range(0, 512, 32)]})
    return raw, proof


def reconcile_payouts(accepted, receiver, assets):
    owned = history.claims(accepted, receiver, assets)
    by_nf = {claim.nf: claim for claim in owned}
    for event in accepted.exits:
        if event['nf'] not in by_nf:
            continue
        prefix = history.History(accepted.state, 1, event['point'],
                                 accepted.deliveries[:event['delivery_count']])
        earlier = history.claims(prefix, receiver, assets)
        need(payout_spk(prefix, receiver, earlier, by_nf[event['nf']]) == event['payout_spk'],
             'original-seed-historical-payout-key')
    if accepted.reserve == 0:
        need(all(c.spent for c in owned), 'terminal-has-no-unspent-owned-claim')
    return True
