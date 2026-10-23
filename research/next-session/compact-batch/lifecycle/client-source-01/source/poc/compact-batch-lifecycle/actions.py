"""Owner-only fixed-arity material, exact values and sparse public updates.

No file, prover, acceptance-oracle, native or network API is present. The caller
must authenticate the public parameters before reading the original own backup,
derive the snapshot from approved public native history, quote the actual body
and serialize only the selected legal candidate. Every fee retry creates fresh
receipt encryption; discarded alternatives stay private.
"""
from dataclasses import dataclass
import hmac
import secrets

from primitives import (MAX, NOTE_FLOOR, PAYOUT_FLOOR, ZERO, amount, dummy_nf,
                        fixed, h, insert_nf, need, note_cm, real_nf, u32, u64)
import receiver as receive

SCHEMA = 'kpx4-private-batch-action-witness/v1'


def draw(entropy, width):
    return fixed(entropy(width), width)


def point_bytes(point):
    need(type(point) is dict and set(point) == {'transactionId', 'index'}, 'current-outpoint-fields')
    value = point['transactionId']
    need(type(value) is str and len(value) == 64
         and all(c in '0123456789abcdef' for c in value), 'current-outpoint-encoding')
    return bytes.fromhex(value) + u32(point['index'])


def invoice(raw, domain):
    v2 = receive.module()
    parsed = v2.Invoice.parse(fixed(raw, 208))
    need(parsed.encode() == raw and parsed.domain == fixed(domain), 'recipient-invoice-instance')
    need(all(value != ZERO for value in (parsed.owner, parsed.incoming, parsed.key_commitment,
        parsed.native_pk, parsed.delivery_pk)), 'recipient-invoice-fields')
    return parsed


def input_material(wallet, snapshot, claim, entropy):
    domain = wallet.domain
    snapshot.verify()
    need(claim.owner_action_available and claim.receipt.domain == domain, 'owned-current-claim')
    matches = [delivery for delivery in snapshot.deliveries if delivery.position == claim.position]
    need(len(matches) == 1 and matches[0].cm == claim.receipt.commitment(), 'owned-physical-commitment')
    keys = wallet.keys(claim.receipt.index)
    cm, _ = snapshot.roots()
    original = real_nf(domain, keys.nf_secret, claim.receipt.commitment(), claim.position)
    need(original == claim.nf and all(row.value != original for row in snapshot.nullifiers),
         'owned-original-unspent-nullifier')
    real = {'real': True, 'note_hex168': claim.receipt.note_bytes().hex(),
            's_hex32': keys.owner_secret.hex(), 'k_hex32': keys.nf_secret.hex(),
            'position': claim.position, 'cm_path_hex': [part.hex() for part in cm.path(claim.position)],
            'dummy_key_hex32': ZERO.hex(), 'dummy_seed_hex32': ZERO.hex()}
    real_slot = draw(entropy, 1)[0] & 1
    dummy_slot = 1 - real_slot
    occupied = {entry.value for entry in snapshot.nullifiers} | {ZERO, original}
    while True:
        key, seed = draw(entropy, 32), draw(entropy, 32)
        padding = dummy_nf(domain, key, seed, dummy_slot)
        if padding not in occupied:
            break
    dummy = {'real': False, 'note_hex168': bytes(168).hex(), 's_hex32': ZERO.hex(),
             'k_hex32': ZERO.hex(), 'position': 0, 'cm_path_hex': [ZERO.hex()] * 16,
             'dummy_key_hex32': key.hex(), 'dummy_seed_hex32': seed.hex()}
    inputs, nfs = [None, None], [None, None]
    inputs[real_slot], inputs[dummy_slot] = real, dummy
    nfs[real_slot], nfs[dummy_slot] = original, padding
    after, first = insert_nf(snapshot, nfs[0])
    after, second = insert_nf(after, nfs[1])
    return tuple(inputs), tuple(nfs), after, first + second


@dataclass(frozen=True, repr=False)
class Candidate:
    role: str
    mode: int
    auth: bytes
    inputs: tuple
    notes: tuple
    ciphertexts: bytes
    cm_list: bytes
    nf_witness: bytes
    boundary: bytes
    after: object
    fee: int
    payout: int
    reserve_after: int

    def payload(self):
        payload = self.auth + self.nf_witness
        if self.mode:
            payload += self.cm_list + self.ciphertexts + self.boundary
        need(len(payload) == {0: 2848, 2: 3920, 32: 12672}[self.mode], 'mode-payload-width')
        return payload

    def private_witness(self):
        return {'schema': SCHEMA, 'auth_hex528': self.auth.hex(), 'inputs': list(self.inputs),
                'outputs': [{'note_hex168': note.hex()} for note in self.notes]}


def assemble(wallet, snapshot, claim, previous, reserve, fee, payout, destination, role,
             output_specs, entropy=secrets.token_bytes):
    """Construct only an exactly conserving legal candidate; no sizing witness."""
    v2 = receive.module()
    domain = wallet.domain
    fixed(domain)
    for value in (reserve, fee, payout):
        amount(value)
    need(reserve >= NOTE_FLOOR and fee > 0 and fee + payout <= reserve, 'reserve-fee-payout-range')
    value = amount(claim.receipt.value_sompi)
    need(NOTE_FLOOR <= value <= reserve, 'owned-value-backing')
    remaining = reserve - fee - payout
    need(remaining == 0 or remaining >= NOTE_FLOOR, 'remaining-reserve-floor')
    fixed(destination, 36)
    if payout:
        need(payout >= PAYOUT_FLOOR and destination[:3] == b'\0\0\x20'
             and destination[-1:] == b'\xac' and destination[3:35] != claim.receipt.native_pk,
             'authorized-fresh-payout')
    else:
        need(destination == bytes(36), 'P0-zero-destination')
    need(role in ('compact2', 'wide32'), 'selected-role')
    mode = 0 if remaining == 0 else 32 if role == 'wide32' else 2
    need(role == 'compact2' or (payout == 0 and mode == 32), 'wide-P0-only')
    need(payout > 0 if mode == 0 else len(output_specs) == mode, 'mode-output-count')
    if mode == 0:
        need(not output_specs, 'terminal-inactive-outputs')
    output_total = 0
    for target, value_out in output_specs:
        amount(value_out)
        if value_out:
            need(value_out >= NOTE_FLOOR and target is not None, 'private-output-floor')
            invoice(target.encode(), domain)
        else:
            need(target is None, 'canonical-dummy-output')
        output_total += value_out  # Python's integer sum cannot wrap u64.
    need(output_total <= MAX and value == output_total + payout + fee,
         'exact-private-value-conservation')
    need(output_total > 0 or payout > 0, 'positive-output-or-payout')
    inputs, nfs, after_nf, nf_path = input_material(wallet, snapshot, claim, entropy)
    notes, ciphers = [], []
    existing = {row.cm for row in snapshot.deliveries} | {ZERO}
    if mode:
        order = list(range(mode))
        for index in range(len(order) - 1, 0, -1):
            # Rejection sampling avoids modulo bias in the role permutation.
            ceiling = 256 - (256 % (index + 1))
            while True:
                sample = draw(entropy, 1)[0]
                if sample < ceiling:
                    chosen = sample % (index + 1)
                    break
            order[index], order[chosen] = order[chosen], order[index]
        for slot in order:
            target, value_out = output_specs[slot]
            while True:
                rho = draw(entropy, 32)
                if value_out:
                    receipt = v2.Receipt.for_invoice(target, value_out, rho)
                    note = receipt.note_bytes()
                else:
                    note = bytes(72) + rho + bytes(64)
                commitment = note_cm(domain, note)
                if commitment not in existing:
                    break
            existing.add(commitment)
            if value_out:
                cipher = wallet.crypto.seal(target.delivery_pk, receipt.encode())
            else:
                public = wallet.crypto.delivery_public(draw(entropy, 32))
                cipher = wallet.crypto.seal(public, draw(entropy, 216))
            notes.append(note)
            ciphers.append(fixed(cipher, 264))
        after, start, path = after_nf.append(domain, notes, ciphers)
        commitments = b''.join(note_cm(domain, note) for note in notes)
        array = h(commitments)
        metadata = bytes([mode]) + bytes(3) + u32(start) + bytes(24)
        ciphertexts = b''.join(ciphers)
        boundary = b''.join(path)
    else:
        notes = [bytes(168), bytes(168)]
        commitments, array, metadata = b'', ZERO, bytes(32)
        ciphertexts, boundary = bytes(528), b''
        after = after_nf
    before_state, after_state = snapshot.state(domain), after.state(domain)
    auth = (b'KPX4AU01' + domain + point_bytes(previous) + before_state + u64(reserve) + u64(fee)
            + b''.join(nfs) + array + metadata + h(ciphertexts) + after_state
            + u64(remaining) + u64(payout) + destination)
    fixed(auth, 528)
    candidate = Candidate(role, mode, auth, inputs, tuple(notes), ciphertexts, commitments,
                          nf_path, boundary, after, fee, payout, remaining)
    candidate.payload()
    return candidate


def payment(wallet, snapshot, claim, previous, reserve, fee, public_invoices, values,
            entropy=secrets.token_bytes):
    need(len(public_invoices) == len(values) == 32, 'wide32-recipient-count')
    parsed = [invoice(raw, wallet.domain) for raw in public_invoices]
    need(len({row.encode() for row in parsed}) == 32, 'distinct-public-recipient-invoices')
    consumed = (claim.receipt.owner, claim.receipt.incoming, claim.receipt.key_commitment, claim.receipt.native_pk)
    need(all((row.owner, row.incoming, row.key_commitment, row.native_pk) != consumed for row in parsed),
         'recipient-reuses-input-receive-fields')
    return assemble(wallet, snapshot, claim, previous, reserve, fee, 0, bytes(36), 'wide32',
                    list(zip(parsed, values)), entropy)


def cashout(seed, wallet, snapshot, claim, previous, founding, reserve, fee,
            entropy=secrets.token_bytes):
    fixed(seed)
    payout = amount(claim.receipt.value_sompi) - amount(fee)
    need(payout >= PAYOUT_FLOOR, 'full-cashout-net-payout-floor')
    prefix = (b'KPX3PAY\0' + wallet.domain + point_bytes(founding) + claim.receipt.commitment()
              + u32(claim.position))
    for retry in range(1 << 32):
        secret = hmac.digest(seed, prefix + u32(retry), 'sha256')
        try:
            native_pk = wallet.crypto.xonly(secret)
        except receive.module().Invalid as error:
            if str(error) != 'crypto-scalar':
                raise
            continue
        if native_pk != claim.receipt.native_pk:
            break
    else:
        raise ValueError('payout-scalar-exhausted')
    remaining = reserve - payout - fee
    specs = [(None, 0), (None, 0)] if remaining else []
    return assemble(wallet, snapshot, claim, previous, reserve, fee, payout,
                    b'\0\0\x20' + native_pk + b'\xac', 'compact2', specs, entropy)
