"""Auth528 trial assembly. Explicit fresh domain; no network, key or prover API."""
from __future__ import annotations

import hashlib
import hmac

MAX = 2_870_000_000_000_000_000
FLOOR = 60_000_000
ZERO = bytes(32)


def require(condition, category):
    if not condition:
        raise ValueError(category)


def h(*parts):
    return hashlib.sha256(b''.join(parts)).digest()


def u32(value):
    require(type(value) is int and 0 <= value <= 0xffffffff, 'u32')
    return value.to_bytes(4, 'little')


def u64(value):
    require(type(value) is int and 0 <= value <= MAX, 'bounded-u64')
    return value.to_bytes(8, 'little')


def state(domain, snapshot):
    require(type(domain) is bytes and len(domain) == 32, 'domain32')
    cm, nf = snapshot.roots()
    return b'KPX2ST01' + domain + cm.root + u32(len(snapshot.deliveries)) + nf.root + u32(len(snapshot.nullifiers))


def insert(module, snapshot, value):
    require(type(value) is bytes and len(value) == 32 and value != ZERO
            and all(entry.value != value for entry in snapshot.nullifiers), 'unseen-nonzero-NF')
    _, tree = snapshot.roots()
    count = len(snapshot.nullifiers)
    require(count < 131071, 'NF-capacity')
    integer = int.from_bytes(value, 'little')
    index, predecessor = max(((i, row) for i, row in enumerate(snapshot.nullifiers)
        if int.from_bytes(row.value, 'little') < integer),
        key=lambda pair: (int.from_bytes(pair[1].value, 'little'), pair[0]))
    require(predecessor.next_value == ZERO
            or integer < int.from_bytes(predecessor.next_value, 'little'), 'strict-NF-interval')
    leaf = predecessor.value + predecessor.next_value + u32(predecessor.next_index)
    witness = u32(index) + leaf + b''.join(tree.path(index))
    replacement = module.NFEntry(predecessor.value, value, count)
    middle = tree.with_leaf(index, replacement.leaf())
    witness += b''.join(middle.path(count))
    entries = list(snapshot.nullifiers)
    entries[index] = replacement
    entries.append(module.NFEntry(value, predecessor.next_value, predecessor.next_index))
    require(len(witness) == 1160, 'NF-witness-width')
    return module.Snapshot(list(snapshot.deliveries), entries), witness


def receipt(module, wallet, amount, position, rho):
    require(type(amount) is int and FLOOR <= amount <= MAX and len(rho) == 32, 'real-note-range')
    invoice = wallet.invoice(0)
    note = module.Receipt.for_invoice(invoice, amount, rho)
    cipher = wallet.crypto.seal(invoice.delivery_pk, note.encode())
    require(len(cipher) == 264, 'receipt-cipher-width')
    return note.note_bytes(), module.Delivery(position, note.commitment(), cipher)


def dummy_output(module, domain, position, rho, cipher):
    require(len(rho) == 32 and len(cipher) == 264, 'dummy-output-width')
    raw = bytes(72) + rho + bytes(64)
    return raw, module.Delivery(position, h(b'KPX1NOT\0', domain, raw), cipher)


def sealed_dummy(crypto, secret, plaintext):
    require(len(secret) == 32 and len(plaintext) == 216, 'dummy-seal-input')
    cipher = crypto.seal(crypto.delivery_public(secret), plaintext)
    require(len(cipher) == 264, 'dummy-seal-output')
    return cipher


def action(module, domain, before, inputs, outputs, previous, reserve, fee, payout,
           destination, dummy_material):
    require(len(domain) == 32 and len(inputs) == 2 and len(previous) == 36
            and len(destination) == 36 and len(dummy_material) == 2, 'action-dimensions')
    for value in (reserve, fee, payout):
        u64(value)
    require(fee > 0 and reserve >= FLOOR and fee + payout <= reserve, 'action-value-range')
    remaining = reserve - fee - payout
    require(remaining == 0 and payout > 0 or remaining >= FLOOR, 'remaining-reserve')
    require(destination == bytes(36) if payout == 0 else
            payout >= 10_000_000 and destination[:3] == b'\0\0\x20'
            and destination[-1:] == b'\xac', 'native-destination')
    old_cm, _ = before.roots()
    witness_inputs, nfs, positions = [], [], []
    for slot, specification in enumerate(inputs):
        if specification is None:
            key, seed = dummy_material[slot]
            require(len(key) == 32 and len(seed) == 32 and key != ZERO and seed != ZERO,
                    'fresh-dummy-input-material')
            nf = hmac.digest(key, b'KPX2DMY\0' + domain + seed + bytes([slot]), 'sha256')
            witness_inputs.append({'real': False, 'note_hex168': bytes(168).hex(),
                's_hex32': ZERO.hex(), 'k_hex32': ZERO.hex(), 'position': 0,
                'cm_path_hex': [ZERO.hex()] * 16,
                'dummy_key_hex32': key.hex(), 'dummy_seed_hex32': seed.hex()})
        else:
            position, wallet = specification
            require(type(position) is int and 0 <= position < len(before.deliveries)
                    and position not in positions, 'distinct-real-position')
            note = wallet.open(before.deliveries[position].ciphertext)
            require(note.domain == domain and note.index == 0
                    and note.commitment() == before.deliveries[position].cm, 'real-current-note')
            require(not payout or destination[3:35] != note.native_pk,
                    'private-payout-emergency-key-reuse')
            keys = wallet.keys(0)
            nf = wallet.nullifier(note, position)
            positions.append(position)
            witness_inputs.append({'real': True, 'note_hex168': note.note_bytes().hex(),
                's_hex32': keys.owner_secret.hex(), 'k_hex32': keys.nf_secret.hex(),
                'position': position, 'cm_path_hex': [part.hex() for part in old_cm.path(position)],
                'dummy_key_hex32': ZERO.hex(), 'dummy_seed_hex32': ZERO.hex()})
        nfs.append(nf)
    require(positions and len(set(nfs)) == 2 and ZERO not in nfs, 'real-input-distinct-NFs')
    after = module.Snapshot(list(before.deliveries), list(before.nullifiers))
    public_witness = b''
    for nf in nfs:
        after, path = insert(module, after, nf)
        public_witness += path
    if remaining == 0:
        require(not outputs, 'terminal-private-output')
        output_notes = [bytes(168), bytes(168)]
        commitments, cipher = [ZERO, ZERO], bytes(528)
        public_witness += bytes(1024)
    else:
        require(len(outputs) == 2 and len(after.deliveries) + 2 <= 65535, 'CM-capacity-and-count')
        output_notes, commitments, ciphers = [], [], []
        for raw, delivery in outputs:
            tree, _ = after.roots()
            require(len(raw) == 168 and delivery.position == len(after.deliveries)
                    and delivery.cm == h(b'KPX1NOT\0', domain, raw)
                    and len(delivery.ciphertext) == 264, 'output-CM-position')
            value = int.from_bytes(raw[64:72], 'little')
            require(FLOOR <= value <= MAX if value else
                    raw[:72] == bytes(72) and raw[104:] == bytes(64)
                    and raw[72:104] != ZERO, 'canonical-private-output')
            public_witness += b''.join(tree.path(delivery.position))
            after.deliveries.append(delivery)
            output_notes.append(raw)
            commitments.append(delivery.cm)
            ciphers.append(delivery.ciphertext)
        require(commitments[0] != commitments[1], 'distinct-output-CMs')
        cipher = b''.join(ciphers)
    require(len(after.nullifiers) <= 2 * len(after.deliveries) + 1,
            'liability-capacity-relation')
    incoming = sum(int.from_bytes(bytes.fromhex(row['note_hex168'])[64:72], 'little')
                   for row in witness_inputs)
    outgoing = sum(int.from_bytes(raw[64:72], 'little') for raw in output_notes)
    require(incoming <= reserve and incoming <= MAX and outgoing <= MAX
            and incoming == outgoing + payout + fee, 'exact-private-conservation')
    require(payout != 0 or outgoing > 0, 'P0-positive-private-output')
    auth = (b'KPX3AU01' + domain + previous + state(domain, before) + u64(reserve) + u64(fee)
            + b''.join(nfs) + b''.join(commitments) + h(cipher) + state(domain, after)
            + u64(remaining) + u64(payout) + destination)
    require(len(auth) == 528 and len(cipher) == 528 and len(public_witness) == 3344,
            'action-fixed-width')
    fixture = {'schema': 'kpx3-private-action-witness/v1', 'auth_hex528': auth.hex(),
               'inputs': witness_inputs, 'outputs': [{'note_hex168': raw.hex()} for raw in output_notes]}
    public = {'auth_hex528': auth.hex(), 'cipher_hex528': cipher.hex(),
              'public_witness_hex3344': public_witness.hex()}
    return after, fixture, public


def payout_secret(seed, domain, founding, cm, position, crypto, consumed_native_pks):
    require(len(seed) == 32 and len(domain) == 32 and len(founding) == 36 and len(cm) == 32,
            'payout-derivation-inputs')
    for retry in range(0x100000000):
        key = hmac.digest(seed, b'KPX3PAY\0' + domain + founding + cm + u32(position) + u32(retry), 'sha256')
        try:
            public = crypto.xonly(key)
        except ValueError as error:
            if str(error) != 'crypto-scalar':
                raise
            continue
        if public not in consumed_native_pks:
            return key, b'\0\0\x20' + public + b'\xac'
    raise ValueError('payout-scalar-retry-space-exhausted')
