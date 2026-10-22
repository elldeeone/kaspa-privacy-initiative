#!/usr/bin/env python3
"""Independent byte-level TWO-V6 contract oracle and metamorphic controls.

This deliberately DOES NOT verify Groth16 proofs. Its proof checker is injected
and mandatory. Tests use an explicit synthetic exact-byte checker to isolate the
binding relation; their success is not genuine-proof or zkVM evidence.
"""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
from itertools import permutations
from pathlib import Path
import json
import struct
import unittest

DOMAIN = bytes.fromhex("d36fda2e668fa858ae852484e63ea6dabb259403901fd9c88a16e9c5b17e5baa")
VK_HASH = bytes.fromhex("9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef")
MAX_SOMPI = 2_900_000_000_000_000_000
P_LEN, B_LEN, INPUT_LEN = 1088, 875, 2846


class Reject(ValueError):
    pass


def require(condition, why):
    if not condition:
        raise Reject(why)


def contract(raw, verify):
    """Only the original fixed rehearsal instance."""
    return _contract(raw, verify, DOMAIN, VK_HASH)


def research_instance_contract(raw, verify, *, trusted_domain, trusted_vk_hash):
    """Separate research-instance entrypoint with identities selected externally.

    Callers must obtain both expected identities from the frozen fixture contract,
    independently of raw witness bytes. This never qualifies the original fixed
    rehearsal instance. It still requires the explicit proof-checker callback.
    """
    require(len(trusted_domain) == 32 and len(trusted_vk_hash) == 32,
            "trusted research identity lengths")
    return _contract(raw, verify, bytes(trusted_domain), bytes(trusted_vk_hash))


def _contract(raw, verify, domain, key_hash):
    """Check bytes and invoke verify(proof, (limb0, limb1)) for each bundle.

    The callback must raise or return False for an invalid proof. It is not a
    host-verdict input of the desired guest; this oracle only separates binding
    checks from cryptographic proof verification for independent review.
    """
    raw = bytes(raw)
    require(len(raw) == INPUT_LEN, "exact input length")
    public = raw[:P_LEN]
    require(public[:12] == b"KPI2V6P1" + struct.pack("<HH", 1, 2), "public framing")
    require(public[12:44] == domain and public[44:76] == key_hash, "fixed instance")
    fee_sum = int.from_bytes(public[76:92], "little")
    require(2 <= fee_sum <= 2 * MAX_SOMPI, "aggregate fee range")
    nullifiers = [public[92 + 32*i:124 + 32*i] for i in range(4)]
    records = [public[220 + 217*i:437 + 217*i] for i in range(4)]
    require(all(n != bytes(32) for n in nullifiers), "nonzero NFs")
    require(all(a < b for a, b in zip(nullifiers, nullifiers[1:])), "strict NF order")
    require(all(a <= b for a, b in zip(records, records[1:])), "record order")
    p, q = raw[-8:-4], raw[-4:]
    require(sorted(p) == list(range(4)), "NF bijection")
    require(sorted(q) == list(range(4)), "record bijection")
    fees, anchors = [], []
    for i in range(2):
        bundle = raw[P_LEN + B_LEN*i:P_LEN + B_LEN*(i+1)]
        auth, proof = bundle[:377], bundle[377:505]
        ciphers = [bundle[505:690], bundle[690:875]]
        require(auth[:8] == b"KPICU06\0" and auth[8:40] == domain, "authorization identity")
        require(auth[204] == 1, "SPEND profile")
        require(auth[205:213] == bytes(8), "zero payout")
        fee = int.from_bytes(auth[213:221], "little")
        require(1 <= fee <= MAX_SOMPI, "individual fee range")
        require(auth[221:345] == bytes(124), "unsupported native/bootstrap fields")
        require(auth[345:377] == sha256(b"".join(ciphers)).digest(), "original ciphertext order")
        anchors.append(auth[40:76])
        fees.append(fee)
        cms = [auth[140:172], auth[172:204]]
        require(all(c != bytes(32) for c in cms) and cms[0] != cms[1], "within-bundle CMs")
        for s in range(2):
            k = 2*i+s
            require(nullifiers[p[k]] == auth[76+32*s:108+32*s], "NF mapping")
            require(records[q[k]] == cms[s] + ciphers[s], "complete record mapping")
        digest = sha256(auth).digest()
        limbs = tuple(int.from_bytes(digest[j:j+16], "little") for j in (0, 16))
        require(verify(proof, limbs) is True, "inner proof")
    require(anchors[0] == anchors[1], "same count and anchor")
    require(sum(fees) == fee_sum, "exact aggregate fee")
    return b"KPI2V6J1" + struct.pack("<H", 1) + sha256(public).digest()


def synthetic_auth(nfs, cms, ciphers, fee):
    """Synthetic byte fixture, not a valid Groth16 proof or note transition."""
    return (b"KPICU06\0" + DOMAIN + struct.pack("<I", 9) + bytes([10])*32
            + b"".join(nfs) + b"".join(cms) + bytes([1]) + bytes(8)
            + struct.pack("<Q", fee) + bytes(124)
            + sha256(b"".join(ciphers)).digest())


def encode_synthetic(*, duplicate_record=False, duplicate_cm=False, fees=(1, MAX_SOMPI)):
    nfs = [bytes([i])*32 for i in (1, 2, 3, 4)]
    cms = [bytes([i])*32 for i in (31, 32, 33, 34)]
    ciphers = [bytes([i])*185 for i in (41, 42, 43, 44)]
    if duplicate_record or duplicate_cm:
        cms[2] = cms[0]
    if duplicate_record:
        ciphers[2] = ciphers[0]
    auths = [synthetic_auth(nfs[2*i:2*i+2], cms[2*i:2*i+2], ciphers[2*i:2*i+2], fees[i])
             for i in range(2)]
    # This synthetic checker binds exact authorization digest limbs and proof
    # marker bytes. It does not implement or model cryptographic soundness.
    proofs = [bytes([51+i])*128 for i in range(2)]
    allowed = {(proofs[i], tuple(int.from_bytes(sha256(auths[i]).digest()[j:j+16], "little")
                              for j in (0, 16))) for i in range(2)}
    verify = lambda proof, limbs: (proof, limbs) in allowed
    records = [cms[i] + ciphers[i] for i in range(4)]
    ns, rs = sorted(nfs), sorted(records)
    # Preserve index multiplicity even for equal full records.
    available = list(range(4))
    q = []
    for record in records:
        index = next(j for j in available if rs[j] == record)
        available.remove(index)
        q.append(index)
    public = (b"KPI2V6P1" + struct.pack("<HH", 1, 2) + DOMAIN + VK_HASH
              + sum(fees).to_bytes(16, "little") + b"".join(ns) + b"".join(rs))
    bundles = [auths[i] + proofs[i] + b"".join(ciphers[2*i:2*i+2]) for i in range(2)]
    raw = public + b"".join(bundles) + bytes(ns.index(n) for n in nfs) + bytes(q)
    assert len(raw) == INPUT_LEN
    return raw, verify


class BindingControls(unittest.TestCase):
    def test_separate_research_entrypoint_cannot_qualify_default_instance(self):
        raw, _ = encode_synthetic()
        domain, key_hash = bytes([91])*32, bytes([92])*32
        changed = bytearray(raw)
        changed[12:44], changed[44:76] = domain, key_hash
        for i in range(2):
            base = P_LEN+B_LEN*i
            changed[base+8:base+40] = domain
        allowed = set()
        for i in range(2):
            base = P_LEN+B_LEN*i
            digest = sha256(changed[base:base+377]).digest()
            limbs = tuple(int.from_bytes(digest[j:j+16], "little") for j in (0, 16))
            allowed.add((bytes(changed[base+377:base+505]), limbs))
        verify = lambda proof, limbs: (proof, limbs) in allowed
        with self.assertRaisesRegex(Reject, "fixed instance"):
            contract(changed, verify)
        research_instance_contract(changed, verify, trusted_domain=domain, trusted_vk_hash=key_hash)
        with self.assertRaisesRegex(Reject, "fixed instance"):
            research_instance_contract(changed, verify, trusted_domain=domain, trusted_vk_hash=VK_HASH)

    def test_sizes_journal_and_limb_binding(self):
        raw, verify = encode_synthetic()
        journal = contract(raw, verify)
        self.assertEqual(len(journal), 42)
        self.assertEqual(journal[10:], sha256(raw[:P_LEN]).digest())
        with self.assertRaisesRegex(Reject, "inner proof"):
            contract(raw, lambda proof, limbs: verify(proof, tuple(reversed(limbs))))

    def test_exhaustive_bijections_and_equal_record_multiplicity(self):
        for duplicate, expected in [(False, 1), (True, 2)]:
            raw, verify = encode_synthetic(duplicate_record=duplicate)
            accepted = 0
            for p in permutations(range(4)):
                for q in permutations(range(4)):
                    try:
                        contract(raw[:-8] + bytes(p) + bytes(q), verify)
                        accepted += 1
                    except Reject:
                        pass
            self.assertEqual(accepted, expected)

    def test_duplicate_cms_with_distinct_ciphers_preserve_complete_pairing(self):
        raw, verify = encode_synthetic(duplicate_cm=True)
        contract(raw, verify)
        # Exchange just ciphertexts of the two equal-CM records. Sorting the
        # resulting records restores byte-for-byte identical public data. This
        # is harmless precisely because both complete records remain present.
        records = [raw[220+217*i:437+217*i] for i in range(4)]
        groups = Counter(record[:32] for record in records)
        self.assertEqual(max(groups.values()), 2)
        self.assertEqual(len(set(records)), 4)

    def test_projection_commits_to_whole_records_and_slot_order(self):
        raw, verify = encode_synthetic()
        # Swap ciphertext slots, then repair public record ordering/mapping.
        # Original per-bundle digest must still reject before proof checking.
        bad = bytearray(raw)
        a, b = P_LEN+505, P_LEN+690
        bad[a:a+185], bad[b:b+185] = raw[b:b+185], raw[a:a+185]
        with self.assertRaisesRegex(Reject, "ciphertext order"):
            contract(bad, verify)

    def test_cross_wiring_public_records_preserves_sets_but_rejects(self):
        raw, verify = encode_synthetic()
        bad = bytearray(raw)
        first, second = raw[220:437], raw[437:654]
        bad[220:437] = first[:32] + second[32:]
        bad[437:654] = second[:32] + first[32:]
        # Commitments and ciphertexts independently have identical multisets.
        self.assertEqual(Counter((first[:32], second[:32])),
                         Counter((bytes(bad[220:252]), bytes(bad[437:469]))))
        self.assertEqual(Counter((first[32:], second[32:])),
                         Counter((bytes(bad[252:437]), bytes(bad[469:654]))))
        with self.assertRaisesRegex(Reject, "complete record mapping"):
            contract(bad, verify)

    def test_repeated_or_out_of_range_public_indices_reject(self):
        raw, verify = encode_synthetic(duplicate_record=True)
        for base, label in [(INPUT_LEN-8, "NF bijection"),
                            (INPUT_LEN-4, "record bijection")]:
            for offset in range(4):
                for value in [4, 255, raw[base+(offset+1)%4]]:
                    bad = bytearray(raw)
                    bad[base+offset] = value
                    with self.assertRaisesRegex(Reject, label):
                        contract(bad, verify)

    def test_exact_framing_and_unsupported_fields(self):
        raw, verify = encode_synthetic()
        for candidate in [raw[:-1], raw + b"\0"]:
            with self.assertRaisesRegex(Reject, "input length"):
                contract(candidate, verify)
        for offset in [12, 44, P_LEN, P_LEN+8, P_LEN+204, P_LEN+205, P_LEN+221,
                       P_LEN+257, P_LEN+265, P_LEN+301, P_LEN+337]:
            bad = bytearray(raw)
            bad[offset] ^= 1
            with self.assertRaises(Reject, msg=f"offset {offset}"):
                contract(bad, verify)

    def test_fee_edges_use_exact_public_u128_encoding(self):
        for fees in [(1, 1), (MAX_SOMPI, MAX_SOMPI)]:
            raw, verify = encode_synthetic(fees=fees)
            contract(raw, verify)
        for fees in [(0, 1), (MAX_SOMPI+1, 1)]:
            raw, verify = encode_synthetic(fees=fees)
            with self.assertRaises(Reject):
                contract(raw, verify)
        raw, verify = encode_synthetic()
        bad = bytearray(raw)
        bad[76:92] = (MAX_SOMPI+2).to_bytes(16, "little")
        with self.assertRaisesRegex(Reject, "exact aggregate fee"):
            contract(bad, verify)

    def test_public_journal_is_partition_and_bundle_order_invariant(self):
        raw, verify = encode_synthetic()
        swapped = (raw[:P_LEN] + raw[P_LEN+B_LEN:P_LEN+2*B_LEN]
                   + raw[P_LEN:P_LEN+B_LEN] + raw[-6:-4] + raw[-8:-6]
                   + raw[-2:] + raw[-4:-2])
        self.assertEqual(contract(raw, verify), contract(swapped, verify))


def public_fixture_profile(repo):
    path = repo / "poc/shared-pool/evidence/2026-10-20-two-input-tn10/rehearsal/chain-confirmed.json"
    data = path.read_bytes()
    eligible = []
    for index, row in enumerate(json.loads(data)["transactions"]):
        payload = bytes.fromhex(row["transaction"]["payload"])
        if not payload.startswith(b"KPICR06\0"):
            continue
        auth = payload[8:385]
        if auth[204] == 1 and auth[205:213] == bytes(8) and auth[337:345] == bytes(8):
            eligible.append({"transaction_index": index,
                             "transaction_id": row["transaction"]["id"],
                             "count": int.from_bytes(auth[40:44], "little"),
                             "anchor": auth[44:76].hex()})
    return {"scope": "public header classification only; no proof verification",
            "source_sha256": sha256(data).hexdigest(), "eligible": eligible,
            "same_anchor_pair_exists": len(eligible) != len({(r["count"],r["anchor"]) for r in eligible})}


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "fixture-profile":
        print(json.dumps(public_fixture_profile(Path(sys.argv[2])), indent=2))
    else:
        unittest.main()
