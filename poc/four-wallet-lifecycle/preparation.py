"""Owner-local payment preparation and pending-receipt detection.

Virtual prefixes are proposed public effects, never accepted W heads. This
module opens no backup/PK; the owning process enforces READY before creating
its private wallet for proof generation. Never serialize private candidates.
"""
from dataclasses import dataclass

from compat import core, payment, public
import no_append
from replay import advance, child_case, snapshot_record


def virtual_prefix(runtime, base, records, output):
    c = core(); p = c.primitives
    p.need(type(records) in (list, tuple) and len(records) <= 2,
           'bounded-proposed-virtual-prefix')
    snapshot, point, reserve = base['snapshot'], base['point'], base['reserve']
    p.need(point is not None and reserve > 0, 'current-base-for-proposed-prefix')
    for ordinal, record in enumerate(records):
        body, f = child_case(runtime, record, ordinal, output)
        snapshot, derived = advance(snapshot, reserve, point, record[:3920], runtime.profile.domain)
        p.need(derived == f, 'independent-proposed-child-effect')
        point, reserve = {'transactionId': body['id'], 'index': 0}, f['remaining']
    return {'snapshot': snapshot, 'point': point, 'reserve': reserve,
            'proposed_virtual_not_settled': True}


def public_body(candidate, runtime, proof=bytes(128)):
    c = core(); p = c.primitives; selected = runtime.profile
    p.fixed(proof, 128)
    before = b'\x4c\x70' + candidate.auth[76:188] + selected.child_template_tail
    after = b'\x4c\x70' + candidate.auth[364:476] + selected.child_template_tail
    point = {'transactionId': candidate.auth[40:72].hex(),
             'index': int.from_bytes(candidate.auth[72:76], 'little')}
    frame = c.native_runtime.push(bytes(65)) + c.native_runtime.push(proof) + c.native_runtime.push(before)
    body = c.native_runtime.tx(point, [(candidate.reserve_after, c.native_runtime.p2sh(after))],
                               candidate.payload(), frame, selected.aggregate_budget)
    # Explicit virtual child context, not the accepted W script/DAA.
    contexts = [c.native_runtime.context(int.from_bytes(candidate.auth[188:196], 'little'),
                                        before, daa=0)]
    return c.native_runtime.public_case(body, contexts)


@dataclass(frozen=True, repr=False)
class SenderPreparation:
    prepared: object
    virtual_case: dict
    quote_context: dict


def prepare_sender(runtime, base, records, ordinal, wallet, request, sizing, output):
    c = core(); p = c.primitives; m = payment()
    p.need(type(ordinal) is int and ordinal in (0, 1)
           and len(records) == ordinal, 'exact-sender-proposed-prefix-count')
    p.need(type(request) is m.Request and wallet.domain == runtime.profile.domain,
           'selected-request-and-owner-domain')
    p.need(sizing['schema'] == 'kpx6-four-wallet-public-sizing/v1'
           and sizing['financial_profile_sha256'] == runtime.profile.profile_sha256
           and sizing['genuine_body_requote_and_exact_fee_reconciliation_required'] is True,
           'selected-provisional-outer-sizing-scope')
    fees, total = sizing['allocated_child_fees_sompi'], p.amount(sizing['outer_fee_sompi'])
    p.need(type(fees) is list and len(fees) == 2
           and all(type(fee) is int and 0 < fee <= p.MAX for fee in fees)
           and sum(fees) == total, 'positive-exact-outer-fee-allocation')
    prefix = virtual_prefix(runtime, base, records, output / 'prefix')
    snapshot = prefix['snapshot']
    recovery = c.receiver.recover(wallet, snapshot, snapshot.state(runtime.profile.domain))
    claims = no_append.available(recovery)
    p.need(len(claims) == 1, 'one-own-current-sender-claim')
    prepared = m.prepare_payment(wallet, snapshot, claims[0], prefix['point'], prefix['reserve'],
        fees[ordinal], request, recovery.owned,
        expected_exit_credit_sompi=sizing['recipient_exit_credit_sompi'],
        fee_context=m.VIRTUAL, excluded_change_indices=(0, 1))
    case, contexts, metrics = runtime.normalize_case(public_body(prepared.candidate, runtime),
                                                     output / 'virtual-normalized')
    runtime.sdk(case['transaction'], contexts)
    p.need(metrics['actual_fee_sompi'] == fees[ordinal], 'exact-allocated-virtual-fee')
    quote_context = {'witness_context': 'EXACT_VIRTUAL_OWNER_ALLOCATION',
        'quote_id': c.native_runtime.quote_id(case['transaction'], contexts, sizing['reference_rate']),
        'transaction': case['transaction'], 'contexts': contexts, 'rate': sizing['reference_rate'],
        'authorization_sha256': p.h(prepared.candidate.auth).hex(),
        'allocated_fee_sompi': fees[ordinal], 'outer_fee_sompi': total,
        'public_sizing_sha256': p.h(c.native_runtime.encoded(sizing)).hex(),
        'standalone_native_minimum_or_settlement_authority': False,
        'final_genuine_outer_body_requote_required': True}
    return SenderPreparation(prepared, case, quote_context)


def finish_sender(runtime, prepared, proof, output):
    c = core(); p = c.primitives; m = payment()
    candidate = prepared.prepared.candidate
    case, contexts, metrics = runtime.normalize_case(public_body(candidate, runtime, proof),
                                                     output / 'proof-normalized')
    expected = c.native_runtime.encoded(prepared.virtual_case)
    original = c.primitives.parse(expected)
    original['transaction']['inputs'][0]['signatureScript'] = case['transaction']['inputs'][0]['signatureScript']
    p.need(case == original, 'official-v1-proof-only-substitution')
    runtime.sdk(case['transaction'], contexts)
    p.need(runtime.verify('compact2', candidate.auth, proof)['verified'] is True,
           'genuine-own-selected-compact-proof')
    component = m.public_component(prepared.prepared, proof, case)
    c.native_runtime.save(output / 'COMPONENT.json', component)
    successor = {'schema': 'kpx6-four-wallet-proposed-virtual-successor/v1',
        'financial_profile_sha256': runtime.profile.profile_sha256,
        'classification': 'PROPOSED_VIRTUAL_PREFIX_NOT_ACCEPTED_NATIVE_STATE',
        'previous_point': {'transactionId': case['transaction']['id'], 'index': 0},
        'reserve_sompi': candidate.reserve_after,
        'state_hex112': candidate.after.state(runtime.profile.domain).hex(),
        'snapshot': snapshot_record(candidate.after),
        'accepted_chain_currentness_or_spend_authority': False}
    c.native_runtime.save(output / 'SUCCESSOR.json', successor)
    return component, successor, metrics


def pending_receipt(runtime, base, records, wallet, request, output):
    """I-14 local consent only; an ACK creates no new financial authority."""
    c = core(); p = c.primitives; m = payment()
    p.need(type(request) is m.Request and wallet.domain == runtime.profile.domain
           and type(records) in (list, tuple) and len(records) == 2,
           'two-child-proposed-recipient-request')
    own_invoice = wallet.invoice(c.actions.invoice(request.invoice, wallet.domain).index)
    p.need(own_invoice.encode() == request.invoice, 'recipient-controls-requested-invoice')
    prefix = virtual_prefix(runtime, base, records, output / 'pending-prefix')
    snapshot = prefix['snapshot']
    own = c.receiver.recover(wallet, snapshot, snapshot.state(wallet.domain))
    gross = p.amount(request.net_principal_sompi + request.recipient_exit_credit_sompi)
    matches = [claim for claim in own.owned if claim.owner_action_available
               and claim.position >= base['snapshot'].cm_cursor
               and claim.receipt.index == own_invoice.index
               and claim.receipt.value_sompi == gross]
    p.need(len(matches) == 1, 'one-valid-new-own-pending-payment-required')
    return {'schema': 'kpx6-four-wallet-pending-recipient-check/v1',
        'financial_profile_sha256': runtime.profile.profile_sha256,
        'requested_net_sompi': request.net_principal_sompi,
        'explicit_exit_credit_sompi': request.recipient_exit_credit_sompi,
        'matched_pending_receipt_count': 1,
        'original_backup_receipt_decrypted_and_rederived': True,
        'PK_or_proof_generation_worker_required': False,
        'owned_positions_CMs_NFs_or_backup_hash_exported': False,
        'classification': 'PENDING_NOT_SETTLED_NO_NATIVE_AUTHORITY',
        'accepted_chain_currentness_or_spend_authority': False}
