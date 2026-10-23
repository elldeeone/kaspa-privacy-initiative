"""Owner-built Auth528 actions, recoverable change and public sizing material.

Only this client-owned implementation creates private witness material. No
operator fixture, expected claim map, compiled development D or exit is loaded.
"""
from dataclasses import dataclass
import hashlib
import hmac
import secrets

from receiver_tools import recipient
from owner_rules import canonical, hx, integer, need, requested_amount, u32, u64

ZERO = bytes(32)
NOTE_FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000


def p2sh(redeem):
    return (b'\0\0\xaa\x20' + hashlib.blake2b(redeem, digest_size=32).digest() + b'\x87').hex()


def state(snapshot, domain):
    cm, nf = snapshot.roots()
    return b'KPX2ST01' + domain + cm.root + u32(len(snapshot.deliveries)) + nf.root + u32(len(snapshot.nullifiers))


def snapshot_from_public(descriptor, public):
    v2 = recipient()
    need(public['descriptor_sha256'] == hashlib.sha256(canonical(descriptor)).hexdigest(),
         'replayed-descriptor-identity')
    need(public['completeness']['complete'] is True, 'incomplete-public-network-replay')
    domain = hx(descriptor['domain_hex32'], 32)
    deliveries = [v2.Delivery(row['position'], hx(row['cm'], 32), hx(row['ciphertext'], 264))
                  for row in public['deliveries']]
    entries = [v2.NFEntry(hx(row['value'], 32), hx(row['next_value'], 32), row['next_index'])
               for row in public['nullifiers']]
    snapshot = v2.Snapshot(deliveries, entries)
    encoded = hx(public['head']['state_hex112'], 112)
    need(encoded[:40] == b'KPX2ST01' + domain and state(snapshot, domain) == encoded,
         'replayed-state-roots-counts')
    # The old V2 oracle string is only a tree/receipt compatibility tag. Actual
    # network/native authority was checked by the new replay before this call.
    expected = v2.ExpectedState(domain, encoded[40:72], len(deliveries), encoded[76:108],
                               len(entries), snapshot.delivery_digest())
    snapshot.verify(expected)
    reserve = integer(public['head']['reserve_sompi'])
    if reserve:
        head = public['head']
        redeem = hx(head['current_redeem_hex'], 24417)
        initial = hx(descriptor['initial_redeem_hex'], 24417)
        need(redeem[:2] == b'\x4c\x70' and redeem[2:114] == encoded
             and redeem[114:] == initial[114:], 'current-authenticated-immutable-policy')
        entry = head['current_utxo']
        need(entry['outpoint'] == head['outpoint'] and integer(entry['amount_sompi']) == reserve
             and entry['script_public_key'] == p2sh(redeem)
             and entry['is_coinbase'] is False and entry['covenant_id'] is None,
             'current-reserve-context')
    else:
        need(public['completeness']['terminal'] is True and public['head']['outpoint'] is None
             and public['head']['current_redeem_hex'] is None and public['head']['current_utxo'] is None,
             'terminal-current-view')
    return snapshot, expected


def payout_key(seed, descriptor, claim, crypto):
    need(type(seed) is bytes and len(seed) == 32, 'seed-width')
    domain = hx(descriptor['domain_hex32'], 32)
    founding = descriptor['founding_outpoint']
    outpoint = hx(founding['transactionId'], 32) + u32(founding['index'])
    prefix = b'KPX3PAY\0' + domain + outpoint + claim.receipt.commitment() + u32(claim.position)
    for retry in range(1 << 32):
        secret = hmac.digest(seed, prefix + u32(retry), 'sha256')
        try:
            public = crypto.xonly(secret)
        except recipient().Invalid as error:
            if str(error) != 'crypto-scalar':
                raise
            continue
        need(type(public) is bytes and len(public) == 32, 'payout-public-key-width')
        if public != claim.receipt.native_pk:
            return secret, public, retry
    raise ValueError('payout-scalar-exhausted')


def insert(snapshot, nf):
    """Same indexed-NF update as the reviewed assembler, without global D."""
    v2 = recipient()
    need(type(nf) is bytes and len(nf) == 32 and nf != ZERO
         and all(entry.value != nf for entry in snapshot.nullifiers), 'spent-or-invalid-nullifier')
    _, tree = snapshot.roots()
    count = len(snapshot.nullifiers)
    need(count < 131071, 'nf-capacity')
    value = int.from_bytes(nf, 'little')
    index, previous = max(((i, entry) for i, entry in enumerate(snapshot.nullifiers)
                          if int.from_bytes(entry.value, 'little') < value),
                         key=lambda item: int.from_bytes(item[1].value, 'little'))
    need(previous.next_value == ZERO or value < int.from_bytes(previous.next_value, 'little'),
         'nullifier-current-absence')
    witness = (u32(index) + previous.value + previous.next_value + u32(previous.next_index)
               + b''.join(tree.path(index)))
    replaced = v2.NFEntry(previous.value, nf, count)
    intermediate = tree.with_leaf(index, replaced.leaf())
    witness += b''.join(intermediate.path(count))
    entries = list(snapshot.nullifiers)
    entries[index] = replaced
    entries.append(v2.NFEntry(nf, previous.next_value, previous.next_index))
    need(len(witness) == 1160, 'nf-witness-width')
    return v2.Snapshot(list(snapshot.deliveries), entries), witness


def opaque_dummy(crypto, entropy):
    secret = entropy(32)
    public = crypto.delivery_public(secret)
    cipher = crypto.seal(public, entropy(216))
    need(len(cipher) == 264, 'dummy-sealed-cipher-width')
    return cipher


def draw(entropy, width):
    raw = entropy(width)
    need(type(raw) is bytes and len(raw) == width, 'action-entropy-width')
    return raw


def receive_tuple(invoice):
    return invoice.owner, invoice.incoming, invoice.key_commitment, invoice.native_pk


def parse_invoice(raw, domain):
    """Public descriptor validation, without a receiver-possession claim."""
    v2 = recipient()
    need(type(raw) is bytes and len(raw) == 208, 'recipient-invoice-width')
    try:
        invoice = v2.Invoice.parse(raw)
        need(invoice.encode() == raw and invoice.domain == domain, 'recipient-invoice-domain')
        need(all(field != ZERO for field in (*receive_tuple(invoice), invoice.delivery_pk)),
             'recipient-invoice-zero-field')
    except v2.Invalid:
        need(False, 'recipient-invoice-format')
    # Invoice.parse is not curve validation, possession or global freshness.
    # Authentic recipient derivation/encryption remain explicit assumptions.
    return invoice


def select_claim(recovered):
    claims = [claim for claim in recovered.owned if claim.owner_action_available]
    need(bool(claims), 'recognized-unspent-claim-required')
    return min(claims, key=lambda claim: (-claim.receipt.value_sompi, claim.position))


def fresh_change_invoice(receiver, historical, selected, target, entropy):
    indices = {claim.receipt.index for claim in historical}
    tuples = {receive_tuple(claim.receipt) for claim in historical}
    indices.add(selected.receipt.index)
    tuples.add(receive_tuple(selected.receipt))
    if target is not None:
        tuples.add(receive_tuple(target))
    while True:
        # Full u64 namespace. Sompi MAX must never bound this derivation index.
        index = int.from_bytes(draw(entropy, 8), 'little')
        if index in indices:
            continue
        invoice = receiver.invoice(index)
        receiver.validate_invoice(invoice)
        need(invoice.index == index and invoice.domain == receiver.domain,
             'self-change-invoice-derivation')
        if receive_tuple(invoice) in tuples:
            continue
        parse_invoice(invoice.encode(), receiver.domain)
        return invoice


@dataclass(frozen=True, repr=False)
class Intent:
    operation: str
    amount: int = 0
    invoice: object = None

    def validate(self, domain):
        need(self.operation in ('prepare-partial-cashout', 'prepare-private-payment',
                                'prepare-full-cashout'), 'private-action-operation')
        requested_amount(self.amount)
        if self.operation == 'prepare-partial-cashout':
            need(self.amount >= PAYOUT_FLOOR and self.invoice is None, 'requested-payout-floor')
        elif self.operation == 'prepare-private-payment':
            need(self.amount >= NOTE_FLOOR and self.invoice is not None, 'requested-payment-floor')
            parse_invoice(self.invoice.encode(), domain)
        else:
            need(self.amount == 0 and self.invoice is None, 'full-cashout-intent')


@dataclass(frozen=True, repr=False)
class PublicSizingCandidate:
    """Public effects only. Deliberately has NO private-witness API or field."""
    auth: bytes
    ciphertexts: bytes
    public_witness: bytes
    before: bytes
    after: bytes
    destination: bytes
    remaining: int
    payout: int
    fee: int
    public_request: dict


@dataclass(frozen=True, repr=False)
class ActualCandidate(PublicSizingCandidate):
    inputs: tuple
    notes: tuple

    def private_witness(self):
        need(type(self) is ActualCandidate, 'actual-private-material-required')
        return {'schema': 'kpx3-private-action-witness/v1', 'auth_hex528': self.auth.hex(),
                'inputs': list(self.inputs),
                'outputs': [{'note_hex168': note.hex()} for note in self.notes]}


@dataclass(repr=False)
class ActionTemplate:
    """One prepare's private randomness, fixed across fee-dependent candidates."""
    descriptor: dict
    head: dict
    receiver: object
    claim: object
    historical: tuple
    intent: Intent
    destination: bytes
    inputs: tuple
    nfs: tuple
    after_nf: object
    nf_witness: bytes
    before: bytes
    rhos: tuple
    output_order: tuple
    entropy: object
    change_invoice: object = None

    def values(self, fee, *, private):
        fee = integer(fee)
        need(fee > 0, 'positive-private-fee')
        value = integer(self.claim.receipt.value_sompi)
        reserve = integer(self.head['reserve_sompi'])
        operation = self.intent.operation
        payout = value - fee if operation == 'prepare-full-cashout' else (
            self.intent.amount if operation == 'prepare-partial-cashout' else 0)
        need((payout == 0 if operation == 'prepare-private-payment'
              else PAYOUT_FLOOR <= payout <= value), 'private-fee-payout-floor')
        remaining = reserve - payout - fee
        need(0 <= remaining <= reserve and (remaining == 0 or remaining >= NOTE_FLOOR),
             'private-reserve-floor')
        payment = self.intent.amount if operation == 'prepare-private-payment' else 0
        change = value - payout - payment - fee
        if private:
            need(change >= 0, 'requested-value-exceeds-owned-claim')
            need(change == 0 or change >= NOTE_FLOOR, 'private-change-note-floor')
            if operation == 'prepare-partial-cashout':
                need(change >= NOTE_FLOOR, 'partial-positive-change-required')
            if operation == 'prepare-full-cashout':
                need(change == 0, 'full-cashout-zero-change')
            need(value == payout + payment + change + fee, 'private-value-conservation')
        return fee, payout, payment, change, remaining

    def sizing(self, fee):
        need(self.intent.operation == 'prepare-private-payment', 'payment-sizing-only')
        values = self.values(fee, private=False)
        # These dummy CM/cipher appends deliberately do not describe a valid
        # payment/value-conservation witness. Never create or return one here.
        return self._assemble(values, ((None, 0), (None, 0)), private=False)

    def actual(self, fee):
        values = self.values(fee, private=True)
        _, _, payment, change, _ = values
        if change and self.change_invoice is None:
            self.change_invoice = fresh_change_invoice(self.receiver, self.historical,
                self.claim, self.intent.invoice, self.entropy)
        if self.intent.operation == 'prepare-partial-cashout':
            roles = ((self.change_invoice, change), (None, 0))
        elif self.intent.operation == 'prepare-private-payment':
            roles = ((self.intent.invoice, payment),
                     (self.change_invoice, change) if change else (None, 0))
        else:
            roles = ((None, 0), (None, 0))
        return self._assemble(values, roles, private=True)

    def _assemble(self, values, roles, *, private):
        v2 = recipient()
        fee, payout, _, _, remaining = values
        domain = hx(self.descriptor['domain_hex32'], 32)
        current = v2.Snapshot(list(self.after_nf.deliveries), list(self.after_nf.nullifiers))
        public_witness = self.nf_witness
        if remaining:
            need(len(current.deliveries) <= 65533, 'private-cm-capacity')
            notes, commitments, ciphertexts = [], [], []
            occupied = {delivery.cm for delivery in current.deliveries} | {ZERO}
            for role in self.output_order:
                invoice, amount = roles[role]
                rho = self.rhos[role]
                if amount:
                    receipt = v2.Receipt.for_invoice(invoice, amount, rho)
                    note = receipt.note_bytes()
                    commitment = receipt.commitment()
                    # Each candidate gets a NEW established seal. Fixed rho and
                    # invoice are not permission to reuse nonce/ephemeral keys.
                    cipher = self.receiver.crypto.seal(invoice.delivery_pk, receipt.encode())
                    if invoice is self.change_invoice:
                        opened = self.receiver.open(cipher)
                        need(opened.encode() == receipt.encode()
                             and opened.commitment() == commitment, 'self-change-roundtrip')
                else:
                    note = bytes(72) + rho + bytes(64)
                    commitment = hashlib.sha256(b'KPX1NOT\0' + domain + note).digest()
                    cipher = opaque_dummy(self.receiver.crypto, self.entropy)
                need(len(note) == 168 and len(cipher) == 264, 'private-output-width')
                need(commitment not in occupied, 'duplicate-output-commitment')
                occupied.add(commitment)
                tree, _ = current.roots()
                at = len(current.deliveries)
                public_witness += b''.join(tree.path(at))
                current.deliveries.append(v2.Delivery(at, commitment, cipher))
                notes.append(note)
                commitments.append(commitment)
                ciphertexts.append(cipher)
            ciphertexts = b''.join(ciphertexts)
        else:
            notes, commitments, ciphertexts = [bytes(168)] * 2, [ZERO] * 2, bytes(528)
            public_witness += bytes(1024)
        need(len(current.nullifiers) <= 2 * len(current.deliveries) + 1,
             'private-nf-cm-capacity')
        after = state(current, domain)
        outpoint = hx(self.head['outpoint']['transactionId'], 32) + u32(self.head['outpoint']['index'])
        auth = (b'KPX3AU01' + domain + outpoint + self.before
                + u64(integer(self.head['reserve_sompi'])) + u64(fee)
                + b''.join(self.nfs) + b''.join(commitments)
                + hashlib.sha256(ciphertexts).digest() + after
                + u64(remaining) + u64(payout) + self.destination)
        need(len(auth) == 528 and len(public_witness) == 3344, 'private-action-width')
        entry = self.head['current_utxo']
        public = {'schema': 'kpx3-public-native-action/v1', 'network_id': 'testnet-10',
                  'genesis_hash_hex': self.descriptor['genesis_hash_hex'],
                  'domain_hex32': self.descriptor['domain_hex32'],
                  'current_redeem_hex': self.head['current_redeem_hex'],
                  'previous_outpoint': self.head['outpoint'],
                  'supplied_utxo': {'amount_sompi': str(integer(entry['amount_sompi'])),
                      'script_public_key': entry['script_public_key'],
                      'block_daa_score': str(integer(entry['block_daa_score'], (1 << 64) - 1)),
                      'is_coinbase': False, 'covenant_id': None},
                  'auth_hex528': auth.hex(), 'cipher_hex528': ciphertexts.hex(),
                  'public_witness_hex3344': public_witness.hex(),
                  'vk_hex328': self.descriptor['vk_hex328'], 'proof_hex128': bytes(128).hex()}
        fields = dict(auth=auth, ciphertexts=ciphertexts, public_witness=public_witness,
                      before=self.before, after=after, destination=self.destination,
                      remaining=remaining, payout=payout, fee=fee, public_request=public)
        if not private:
            return PublicSizingCandidate(**fields)
        need(sum(int.from_bytes(note[64:72], 'little') for note in notes) + payout + fee
             == self.claim.receipt.value_sompi, 'private-value-conservation')
        return ActualCandidate(**fields, inputs=self.inputs, notes=tuple(notes))


def material(descriptor, head, receiver, claim, historical, snapshot, expected,
             destination, intent, entropy=secrets.token_bytes):
    v2 = recipient()
    domain = hx(descriptor['domain_hex32'], 32)
    intent.validate(domain)
    snapshot.verify(expected)
    before = state(snapshot, domain)
    need(before.hex() == head['state_hex112'], 'private-current-state')
    need(claim.owner_action_available and claim.receipt.domain == domain, 'owned-unspent-claim-required')
    reserve, value = integer(head['reserve_sompi']), integer(claim.receipt.value_sompi)
    need(NOTE_FLOOR <= value <= reserve, 'owned-claim-reserve')
    current = head['current_utxo']
    redeem = hx(head['current_redeem_hex'], 24417)
    need(redeem[:2] == b'\x4c\x70' and redeem[2:114] == before
         and redeem[114:] == hx(descriptor['initial_redeem_hex'], 24417)[114:]
         and current['outpoint'] == head['outpoint'] and integer(current['amount_sompi']) == reserve
         and current['script_public_key'] == p2sh(redeem)
         and current['is_coinbase'] is False and current['covenant_id'] is None,
         'private-current-context')
    if intent.operation == 'prepare-private-payment':
        need(destination == bytes(36), 'private-payment-zero-destination')
        need(receive_tuple(intent.invoice) != receive_tuple(claim.receipt),
             'recipient-reuses-input-receive-fields')
    else:
        need(type(destination) is bytes and len(destination) == 36
             and destination[:3] == b'\0\0\x20' and destination[-1:] == b'\xac'
             and destination[3:35] != claim.receipt.native_pk, 'fresh-canonical-payout')
    cm, _ = snapshot.roots()
    position = claim.position
    need(type(position) is int and 0 <= position < len(snapshot.deliveries)
         and snapshot.deliveries[position].cm == claim.receipt.commitment(), 'owned-current-cm')
    need(len(snapshot.nullifiers) + 2 <= 131071, 'private-nf-capacity')
    keys = receiver.keys(claim.receipt.index)
    original_nf = receiver.nullifier(claim.receipt, position)
    need(original_nf == claim.nf, 'owned-original-nullifier')
    real = {'real': True, 'note_hex168': claim.receipt.note_bytes().hex(),
            's_hex32': keys.owner_secret.hex(), 'k_hex32': keys.nf_secret.hex(),
            'position': position, 'cm_path_hex': [row.hex() for row in cm.path(position)],
            'dummy_key_hex32': ZERO.hex(), 'dummy_seed_hex32': ZERO.hex()}
    real_slot = draw(entropy, 1)[0] & 1
    dummy_slot = 1 - real_slot
    occupied = {entry.value for entry in snapshot.nullifiers} | {original_nf, ZERO}
    while True:
        dummy_key, dummy_seed = draw(entropy, 32), draw(entropy, 32)
        dummy_nf = hmac.digest(dummy_key, b'KPX2DMY\0' + domain + dummy_seed + bytes([dummy_slot]), 'sha256')
        if dummy_nf not in occupied:
            break
    dummy = {'real': False, 'note_hex168': bytes(168).hex(), 's_hex32': ZERO.hex(),
             'k_hex32': ZERO.hex(), 'position': 0, 'cm_path_hex': [ZERO.hex()] * 16,
             'dummy_key_hex32': dummy_key.hex(), 'dummy_seed_hex32': dummy_seed.hex()}
    inputs, nfs = [None] * 2, [None] * 2
    inputs[real_slot], inputs[dummy_slot] = real, dummy
    nfs[real_slot], nfs[dummy_slot] = original_nf, dummy_nf
    after_nf, first = insert(snapshot, nfs[0])
    after_nf, second = insert(after_nf, nfs[1])
    output_order = (1, 0) if draw(entropy, 1)[0] & 1 else (0, 1)
    return ActionTemplate(descriptor, head, receiver, claim, tuple(historical), intent,
        destination, tuple(inputs), tuple(nfs), after_nf, first + second, before,
        (draw(entropy, 32), draw(entropy, 32)), output_order, entropy)


