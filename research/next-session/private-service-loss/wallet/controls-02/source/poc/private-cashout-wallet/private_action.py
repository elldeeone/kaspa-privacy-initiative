"""Own-receipt full-claim Auth528 and current public update witnesses.

Only this client-owned implementation creates private witness material. No
operator fixture, expected claim map, compiled development D or exit is loaded.
"""
from dataclasses import dataclass
import hashlib
import hmac
import secrets

from receiver_tools import recipient
from owner_rules import canonical, hx, integer, need, u32, u64

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


@dataclass(repr=False)
class ActionMaterial:
    """Private in-memory material fixed across quotes; never serialized/logged."""
    descriptor: dict
    head: dict
    claim: object
    inputs: list
    outputs: list
    nfs: list
    commitments: list
    ciphertexts: bytes
    public_witness: bytes
    before: bytes
    after: bytes
    destination: bytes
    remaining: int

    def build(self, fee):
        fee = integer(fee)
        value = self.claim.receipt.value_sompi
        need(0 < fee and fee + PAYOUT_FLOOR <= value, 'private-fee-payout-floor')
        payout = value - fee
        prior = self.head['outpoint']
        outpoint = hx(prior['transactionId'], 32) + u32(prior['index'])
        domain = hx(self.descriptor['domain_hex32'], 32)
        auth = (b'KPX3AU01' + domain + outpoint + self.before
                + u64(integer(self.head['reserve_sompi'])) + u64(fee)
                + b''.join(self.nfs) + b''.join(self.commitments)
                + hashlib.sha256(self.ciphertexts).digest() + self.after
                + u64(self.remaining) + u64(payout) + self.destination)
        need(len(auth) == 528 and len(self.public_witness) == 3344, 'private-action-width')
        witness = {'schema': 'kpx3-private-action-witness/v1', 'auth_hex528': auth.hex(),
                   'inputs': self.inputs, 'outputs': [{'note_hex168': note.hex()} for note in self.outputs]}
        entry = self.head['current_utxo']
        public = {'schema': 'kpx3-public-native-action/v1', 'network_id': 'testnet-10',
                  'genesis_hash_hex': self.descriptor['genesis_hash_hex'],
                  'domain_hex32': self.descriptor['domain_hex32'],
                  'current_redeem_hex': self.head['current_redeem_hex'],
                  'previous_outpoint': prior,
                  'supplied_utxo': {'amount_sompi': str(integer(entry['amount_sompi'])),
                                   'script_public_key': entry['script_public_key'],
                                   'block_daa_score': str(integer(entry['block_daa_score'], (1 << 64) - 1)),
                                   'is_coinbase': False, 'covenant_id': None},
                  'auth_hex528': auth.hex(), 'cipher_hex528': self.ciphertexts.hex(),
                  'public_witness_hex3344': self.public_witness.hex(),
                  'vk_hex328': self.descriptor['vk_hex328'], 'proof_hex128': bytes(128).hex()}
        return auth, witness, public


def material(descriptor, head, receiver, claim, snapshot, expected, destination,
             entropy=secrets.token_bytes):
    v2 = recipient()
    domain = hx(descriptor['domain_hex32'], 32)
    snapshot.verify(expected)
    need(claim.owner_action_available and claim.receipt.domain == domain, 'owned-unspent-claim-required')
    reserve, value = integer(head['reserve_sompi']), integer(claim.receipt.value_sompi)
    need(NOTE_FLOOR <= value <= reserve, 'owned-claim-reserve')
    remaining = reserve - value
    need(remaining == 0 or remaining >= NOTE_FLOOR, 'full-claim-reserve-floor')
    need(type(destination) is bytes and len(destination) == 36 and destination[:3] == b'\0\0\x20'
         and destination[-1:] == b'\xac' and destination[3:35] != claim.receipt.native_pk,
         'fresh-canonical-payout')
    cm, _ = snapshot.roots()
    position = claim.position
    need(0 <= position < len(snapshot.deliveries)
         and snapshot.deliveries[position].cm == claim.receipt.commitment(), 'owned-current-cm')
    need(len(snapshot.nullifiers) + 2 <= 131071
         and (remaining == 0 or len(snapshot.deliveries) <= 65533), 'private-state-capacity')
    keys = receiver.keys(claim.receipt.index)
    original_nf = receiver.nullifier(claim.receipt, position)
    need(original_nf == claim.nf, 'owned-original-nullifier')
    real = {'real': True, 'note_hex168': claim.receipt.note_bytes().hex(),
            's_hex32': keys.owner_secret.hex(), 'k_hex32': keys.nf_secret.hex(),
            'position': position, 'cm_path_hex': [row.hex() for row in cm.path(position)],
            'dummy_key_hex32': ZERO.hex(), 'dummy_seed_hex32': ZERO.hex()}
    occupied = {entry.value for entry in snapshot.nullifiers} | {original_nf, ZERO}
    while True:
        dummy_key, dummy_seed = entropy(32), entropy(32)
        need(len(dummy_key) == len(dummy_seed) == 32, 'dummy-input-entropy-width')
        dummy_nf = hmac.digest(dummy_key, b'KPX2DMY\0' + domain + dummy_seed + b'\x01', 'sha256')
        if dummy_nf not in occupied:
            break
    dummy = {'real': False, 'note_hex168': bytes(168).hex(), 's_hex32': ZERO.hex(),
             'k_hex32': ZERO.hex(), 'position': 0, 'cm_path_hex': [ZERO.hex()] * 16,
             'dummy_key_hex32': dummy_key.hex(), 'dummy_seed_hex32': dummy_seed.hex()}
    current, first = insert(snapshot, original_nf)
    current, second = insert(current, dummy_nf)
    witness = first + second
    if remaining:
        outputs, commitments, ciphers = [], [], []
        for _ in range(2):
            while True:
                rho = entropy(32)
                need(len(rho) == 32, 'dummy-rho-width')
                note = bytes(72) + rho + bytes(64)
                commitment = hashlib.sha256(b'KPX1NOT\0' + domain + note).digest()
                if commitment != ZERO and commitment not in commitments:
                    break
            tree, _ = current.roots()
            at = len(current.deliveries)
            witness += b''.join(tree.path(at))
            cipher = opaque_dummy(crypto=receiver.crypto, entropy=entropy)
            current.deliveries.append(v2.Delivery(at, commitment, cipher))
            outputs.append(note)
            commitments.append(commitment)
            ciphers.append(cipher)
        ciphertexts = b''.join(ciphers)
    else:
        outputs, commitments, ciphertexts = [bytes(168)] * 2, [ZERO] * 2, bytes(528)
        witness += bytes(1024)
    need(len(current.nullifiers) <= 2 * len(current.deliveries) + 1,
         'private-nf-cm-capacity')
    return ActionMaterial(descriptor, head, claim, [real, dummy], outputs,
                          [original_nf, dummy_nf], commitments, ciphertexts, witness,
                          state(snapshot, domain), state(current, domain), destination, remaining)
