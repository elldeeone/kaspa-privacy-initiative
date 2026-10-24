"""One invoice plus fresh recoverable sender change using the existing relation.

This pure owner-local preparation has no file, PK, prover or native API. A caller
must authenticate parameters before reading its own backup, derive the supplied
snapshot from approved history, bind an exact fee/quote and verify the eventual
proof/settlement. This does not create a reusable signed intent or new privacy
protocol. Never serialize the PreparedPayment/Candidate private fields.
"""
import copy
from dataclasses import dataclass
import secrets

from reuse import load

REQUEST_SCHEMA = 'kpx4-single-invoice-payment-request/v1'
STANDALONE = 'STANDALONE_ACTUAL_QUOTE_REQUIRED'
VIRTUAL = 'PROPOSED_VIRTUAL_NEW_POLICY_REQUIRED'


def receive_fields(value):
    return value.owner, value.incoming, value.key_commitment, value.native_pk


@dataclass(frozen=True, repr=False)
class Request:
    invoice: bytes
    net_principal_sompi: int
    recipient_exit_credit_sompi: int

    @classmethod
    def parse(cls, raw, expected_domain):
        c = load()
        p = c.primitives
        value = p.parse(raw)
        p.need(type(value) is dict and set(value) == {
            'schema', 'domain_hex32', 'recipient_invoice_hex208',
            'net_principal_sompi', 'recipient_exit_credit_sompi'
        } and value['schema'] == REQUEST_SCHEMA
            and value['domain_hex32'] == p.fixed(expected_domain).hex(),
            'one-invoice-request-fields-and-domain')
        invoice = c.history.hexbytes(value['recipient_invoice_hex208'], 208)
        c.actions.invoice(invoice, expected_domain)
        net = p.amount(value['net_principal_sompi'])
        credit = p.amount(value['recipient_exit_credit_sompi'])
        p.need(net >= p.PAYOUT_FLOOR and credit > 0
               and p.NOTE_FLOOR <= net + credit <= p.MAX, 'requested-net-gross-range')
        return cls(invoice, net, credit)


@dataclass(frozen=True, repr=False)
class PreparedPayment:
    candidate: object
    request: Request
    fee_context: str
    recipient_gross_sompi: int
    sender_change_sompi: int


def fresh_change(wallet, historical, selected, recipient, entropy, excluded_indices=()):
    c = load()
    p = c.primitives
    used = {item.receipt.index for item in historical} | {selected.receipt.index}
    for index in excluded_indices:
        p.uint(index, 64)
        used.add(index)
    fields = {receive_fields(item.receipt) for item in historical}
    fields |= {receive_fields(selected.receipt), receive_fields(recipient)}
    while True:
        index = int.from_bytes(c.actions.draw(entropy, 8), 'little')
        if index in used:
            continue
        invoice = wallet.invoice(index)
        wallet.validate_invoice(invoice)
        p.need(invoice.domain == wallet.domain and invoice.index == index, 'derived-self-change')
        if receive_fields(invoice) in fields:
            continue
        return c.actions.invoice(invoice.encode(), wallet.domain)


def prepare_payment(wallet, snapshot, claim, previous, reserve_sompi, fee_sompi,
                    request, historical, *, expected_exit_credit_sompi,
                    fee_context, entropy=secrets.token_bytes, excluded_change_indices=()):
    c = load()
    p = c.primitives
    p.need(type(request) is Request, 'one-request-required')
    p.need(fee_context in (STANDALONE, VIRTUAL), 'explicit-fee-settlement-context')
    p.need(claim.owner_action_available
           and all(row.value != claim.nf for row in snapshot.nullifiers),
           'selected-claim-already-spent')
    net, credit = p.amount(request.net_principal_sompi), p.amount(request.recipient_exit_credit_sompi)
    p.need(net >= p.PAYOUT_FLOOR and credit > 0 and
           credit == p.amount(expected_exit_credit_sompi), 'exact-requested-exit-credit')
    gross = p.amount(net + credit)
    p.need(gross >= p.NOTE_FLOOR, 'recipient-gross-floor')
    fee = p.amount(fee_sompi)
    p.need(fee > 0, 'positive-authorized-fee')
    target = c.actions.invoice(p.fixed(request.invoice, 208), wallet.domain)
    own_target = wallet.invoice(target.index)
    p.need(receive_fields(target) != receive_fields(own_target), 'recipient-is-sender')
    historical = tuple(historical)
    p.need(any(old.position == claim.position and old.nf == claim.nf
               and old.receipt.commitment() == claim.receipt.commitment()
               for old in historical), 'selected-claim-in-own-recovery')
    p.need(all(receive_fields(target) != receive_fields(old.receipt) for old in historical),
           'recipient-reuses-own-receive-fields')
    change = p.amount(claim.receipt.value_sompi) - gross - fee
    p.need(change >= p.NOTE_FLOOR, 'positive-change-floor-or-insufficient-value')
    p.amount(change)
    change_invoice = fresh_change(wallet, historical, claim, target, entropy,
                                  excluded_change_indices)
    candidate = c.actions.assemble(wallet, snapshot, claim, previous,
        reserve_sompi, fee, 0, bytes(36), 'compact2',
        [(target, gross), (change_invoice, change)], entropy)
    p.need(candidate.mode == 2 and candidate.payout == 0
           and candidate.reserve_after == reserve_sompi - fee
           and len(candidate.notes) == 2, 'compact-single-invoice-P0-shape')
    return PreparedPayment(candidate, request, fee_context, gross, change)


def public_component(prepared, proof128, public_case):
    """Copy only selected public bytes for an EXTERNAL settlement verifier.

    This validates wire consistency, not Groth16, native acceptance, canonical
    transaction ID, currentness or new virtual-settlement authority. The caller
    must invoke the separately selected verifier/policy before trusting it.
    """
    c = load()
    p = c.primitives
    p.need(type(prepared) is PreparedPayment, 'selected-preparation-required')
    candidate = prepared.candidate
    proof = p.fixed(proof128, 128)
    p.need(type(public_case) is dict and set(public_case) == {'transaction', 'entries'},
           'exact-public-case-fields')
    case = copy.deepcopy(public_case)
    body, entries = case['transaction'], case['entries']
    p.need(type(body) is dict and set(body) == {
        'version', 'id', 'inputs', 'outputs', 'lockTime', 'subnetworkId', 'gas', 'payload', 'mass'
    } and type(body['version']) is int and body['version'] == 1
        and type(body['lockTime']) is int and body['lockTime'] == 0
        and body['subnetworkId'] == '00' * 20
        and type(body['gas']) is int and body['gas'] == 0,
        'canonical-child-body-header')
    c.history.hexbytes(body['id'], 32)
    p.need(type(body['mass']) is int and 0 <= body['mass'] < 1 << 64, 'body-mass-range')
    p.need(type(body['inputs']) is list and len(body['inputs']) == 1
           and type(body['outputs']) is list and len(body['outputs']) == 1
           and type(entries) is list and len(entries) == 1, 'one-input-one-P0-successor')
    item = body['inputs'][0]
    p.need(type(item) is dict and set(item) == {
        'previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'
    } and type(item['sequence']) is int and item['sequence'] == (1 << 64) - 1
        and type(item['computeBudget']) is int and item['computeBudget'] == 1600,
        'canonical-child-input')
    p.need(c.actions.point_bytes(item['previousOutpoint']) == candidate.auth[40:76],
           'exact-Auth-previous-point')
    frame = c.history.hexbytes(item['signatureScript'])
    p.need(len(frame) >= 313 and frame[:66] == c.native_runtime.push(bytes(65))
           and frame[66:68] == b'\x4c\x80' and frame[68:196] == proof
           and frame[196] == 0x4d
           and len(frame) == 199 + int.from_bytes(frame[197:199], 'little'),
           'exact-public-proof-frame')
    redeem = frame[199:]
    p.need(redeem[:2] == b'\x4c\x70' and redeem[2:114] == candidate.auth[76:188],
           'child-template-current-state')
    payload = c.history.hexbytes(body['payload'])
    p.need(payload == candidate.payload(), 'selected-public-payload')
    entry = entries[0]
    reserve = int.from_bytes(candidate.auth[188:196], 'little')
    p.need(type(entry) is dict and set(entry) == {
        'amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'
    } and type(entry['amount']) is int and entry['amount'] == reserve
        and entry['scriptPublicKey'] == c.native_runtime.p2sh(redeem)
        and type(entry['blockDaaScore']) is int and 0 <= entry['blockDaaScore'] < 1 << 64
        and entry['isCoinbase'] is False and entry['covenantId'] is None,
        'exact-child-template-entry')
    output = body['outputs'][0]
    next_redeem = b'\x4c\x70' + candidate.auth[364:476] + redeem[114:]
    p.need(type(output) is dict and set(output) == {'value', 'scriptPublicKey', 'covenant'}
           and type(output['value']) is int and output['value'] == candidate.reserve_after
           and output['scriptPublicKey'] == c.native_runtime.p2sh(next_redeem)
           and output['covenant'] is None
           and entry['amount'] - output['value'] == candidate.fee,
           'exact-P0-output-reserve-and-fee')
    return {'schema': 'kpx4-selected-public-payment-component/v1',
        'classification': 'UNVERIFIED_COMPONENT_EXTERNAL_SETTLEMENT_POLICY_REQUIRED',
        'role': 'compact2', 'fee_context': prepared.fee_context,
        'auth_hex528': candidate.auth.hex(), 'payload_hex': payload.hex(),
        'proof_hex128': proof.hex(), 'public_case': case}

