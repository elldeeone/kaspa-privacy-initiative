"""One-backup one/two-real full cashout with existing cryptographic recipes.

No files, prover, native process, network or public export API. Private witness
objects must never be logged, persisted, hashed or supplied to another owner.
"""
from dataclasses import dataclass
import hmac
import secrets

from compat import core


def available(recovered):
    return sorted((claim for claim in recovered.owned if claim.owner_action_available),
                  key=lambda claim: (-claim.receipt.value_sompi, claim.position))


def select(recovered):
    c = core(); claims = available(recovered)
    c.primitives.need(bool(claims), 'recognized-current-positive-claim-required')
    return tuple(claims[:2])


def default_key(seed, wallet, anchor_point, claims):
    """Same KPX3PAY message; root-selected skip set includes EVERY real input."""
    c = core(); p = c.primitives
    p.fixed(seed)
    p.need(len(claims) in (1, 2), 'one-or-two-owned-inputs')
    anchor = min(claims, key=lambda claim: claim.position)
    skip = {claim.receipt.native_pk for claim in claims}
    prefix = (b'KPX3PAY\0' + wallet.domain + c.actions.point_bytes(anchor_point)
              + anchor.receipt.commitment() + p.u32(anchor.position))
    for retry in range(1 << 32):
        secret = hmac.digest(seed, prefix + p.u32(retry), 'sha256')
        try:
            public_key = wallet.crypto.xonly(secret)
        except c.receiver.module().Invalid as error:
            if str(error) != 'crypto-scalar':
                raise
            continue
        if public_key not in skip:
            return public_key
    raise ValueError('payout-scalar-exhausted')


def real_row(wallet, snapshot, claim):
    c = core(); p = c.primitives
    p.need(claim.owner_action_available and claim.receipt.domain == wallet.domain,
           'owned-current-input')
    matches = [row for row in snapshot.deliveries if row.position == claim.position]
    p.need(len(matches) == 1 and matches[0].cm == claim.receipt.commitment(), 'owned-physical-CM')
    keys = wallet.keys(claim.receipt.index)
    original = p.real_nf(wallet.domain, keys.nf_secret, claim.receipt.commitment(), claim.position)
    p.need(original == claim.nf and original != p.ZERO
           and all(row.value != original for row in snapshot.nullifiers), 'current-owned-original-NF')
    tree, _ = snapshot.roots()
    return {'real': True, 'note_hex168': claim.receipt.note_bytes().hex(),
            's_hex32': keys.owner_secret.hex(), 'k_hex32': keys.nf_secret.hex(),
            'position': claim.position, 'cm_path_hex': [part.hex() for part in tree.path(claim.position)],
            'dummy_key_hex32': p.ZERO.hex(), 'dummy_seed_hex32': p.ZERO.hex()}, original


@dataclass(frozen=True, repr=False)
class Material:
    snapshot: object
    domain: bytes
    previous: dict
    reserve: int
    total: int
    inputs: tuple
    nfs: tuple
    after: object
    paths: bytes
    destination: bytes
    consumed_count: int

    def candidate(self, fee):
        c = core(); p = c.primitives
        fee = p.amount(fee)
        payout, remaining = self.total - fee, self.reserve - self.total
        p.need(fee > 0 and p.PAYOUT_FLOOR <= payout <= p.MAX, 'cashout-fee-or-payout-floor')
        p.need(remaining == 0 or p.NOTE_FLOOR <= remaining <= p.MAX, 'other-reserve-backing-floor')
        auth = (b'KPX4AU01' + self.domain + c.actions.point_bytes(self.previous)
                + self.snapshot.state(self.domain) + p.u64(self.reserve) + p.u64(fee)
                + b''.join(self.nfs) + p.ZERO + bytes(32) + p.h(bytes(528))
                + self.after.state(self.domain) + p.u64(remaining) + p.u64(payout)
                + self.destination)
        p.fixed(auth, 528)
        return c.actions.Candidate('compact2', 0, auth, self.inputs,
            (bytes(168), bytes(168)), bytes(528), b'', self.paths, b'', self.after,
            fee, payout, remaining)


def prepare(seed, wallet, snapshot, recovered, claims, previous, anchor_point, reserve, *, expected_domain,
            entropy=secrets.token_bytes):
    c = core(); p = c.primitives
    snapshot.verify(); claims = tuple(claims)
    c.actions.point_bytes(previous);c.actions.point_bytes(anchor_point)
    previous = dict(previous)
    p.need(wallet.domain == p.fixed(expected_domain), 'selected-financial-wallet-domain')
    p.need(len(claims) in (1, 2) and len({claim.position for claim in claims}) == len(claims),
           'distinct-one-or-two-input-positions')
    known = {(claim.position, claim.nf, claim.receipt.commitment()) for claim in recovered.owned}
    p.need(all((claim.position, claim.nf, claim.receipt.commitment()) in known for claim in claims),
           'all-inputs-from-this-own-backup-recovery')
    total = 0
    for claim in claims:
        value = p.amount(claim.receipt.value_sompi)
        p.need(value >= p.NOTE_FLOOR, 'positive-input-note-floor')
        total += value
    p.amount(reserve)
    p.need(p.NOTE_FLOOR <= total <= min(p.MAX, reserve), 'checked-owned-sum-and-backing')
    if len(claims) == 1:
        inputs, nfs, after, paths = c.actions.input_material(wallet, snapshot, claims[0], entropy)
    else:
        rows = [real_row(wallet, snapshot, claim) for claim in claims]
        if c.actions.draw(entropy, 1)[0] & 1:
            rows.reverse()
        inputs, nfs = tuple(row[0] for row in rows), tuple(row[1] for row in rows)
        p.need(len(set(nfs)) == 2, 'two-distinct-original-real-NFs')
        after, first = p.insert_nf(snapshot, nfs[0])
        after, second = p.insert_nf(after, nfs[1])
        paths = first + second
    # Snapshot itself stays the exact established type. Carry the domain in
    # Material rather than mutating a shared/global source or data structure.
    destination = b'\0\0\x20' + default_key(seed, wallet, anchor_point, claims) + b'\xac'
    return Material(snapshot, wallet.domain, previous, reserve, total, tuple(inputs), tuple(nfs), after,
                    paths, destination, len(claims))


def controlled_payouts(seed, wallet, recovered, anchor_point, payouts):
    """Certify actual SPK matches, never infer hidden real/dummy arity.

    Two own NF matches reconstruct the complete bounded two-real skip set. A
    one-match candidate establishes key control ONLY on an exact actual SPK
    match; mismatches remain unresolved, never accepted as a one-real default.
    """
    p = core().primitives
    owned = {}
    for claim in recovered.owned:
        owned.setdefault(claim.nf, []).append(claim)
    matched_count, value, complete_groups, partial_groups, unresolved = 0, 0, 0, 0, 0
    for payout in payouts:
        auth = bytes.fromhex(payout['auth_hex528']);p.fixed(auth, 528)
        matches, ambiguous = [], False
        for nf in (auth[204:236], auth[236:268]):
            choices = owned.get(nf, [])
            ambiguous |= len(choices) > 1
            if len(choices) == 1:
                matches.append(choices[0])
        if not matches:
            continue
        if ambiguous:
            unresolved += 1;continue
        public_key = default_key(seed, wallet, anchor_point, matches)
        if payout['script_public_key'] != (b'\0\0\x20' + public_key + b'\xac').hex():
            unresolved += 1;continue
        matched_count += 1;value += payout['amount_sompi']
        if len(matches) == 2:
            complete_groups += 1
        else:
            partial_groups += 1
    return {'historical_native_payout_key_control_match_count': matched_count,
            'historical_native_payout_sompi': value,
            'bounded_two_real_group_reconstruction_count': complete_groups,
            'one_known_NF_exact_key_matches_without_arity_claim': partial_groups,
            'unresolved_owned_NF_payout_records': unresolved,
            'native_current_UTXO_or_spendability_verified': False}
