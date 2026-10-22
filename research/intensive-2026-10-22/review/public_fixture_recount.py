#!/usr/bin/env python3
"""Recompute the separate public development fixture's complete P/J/input.

Expected domain/VK identity was supplied by root independently of witness bytes.
This performs no Groth16 proof verification and reads only the public directory.
"""
from hashlib import sha256
from pathlib import Path
import json
import struct
import sys

from two_v6_contract_oracle import B_LEN, P_LEN, research_instance_contract

TRUSTED_DOMAIN = bytes.fromhex("d47cb91ef9ac74dda71c7db1519381526c3dfac5f525b904f744b97a7df713bd")
TRUSTED_KEY_HASH = bytes.fromhex("2a9acd1639fb7b454384c65fb317a139695f5a2cbb3ebd941dd13b5f6045a2f4")
TRUSTED_BUNDLE_HASHES = (
    "3f8f0a13f4ce7a73b61fd093c5aad01fc2cb2ea0ca3db65ed4f0d44de72019a9",
    "1cc3094a335dfa94897929fde258d05da2a3270314738919b972838e61e2d7b8",
)


def main(directory):
    directory = Path(directory).resolve(strict=True)
    key = (directory/"verification-key.bin").read_bytes()
    assert len(key) == 328 and sha256(key).digest() == TRUSTED_KEY_HASH
    bundles = [(directory/f"bundle-{i}.bin").read_bytes() for i in range(2)]
    assert all(len(b) == B_LEN and sha256(b).hexdigest() == TRUSTED_BUNDLE_HASHES[i]
               for i, b in enumerate(bundles))
    authorizations = [b[:377] for b in bundles]
    all_nfs, all_records = [], []
    for bundle, auth in zip(bundles, authorizations):
        assert auth[8:40] == TRUSTED_DOMAIN
        for slot in range(2):
            all_nfs.append(auth[76+32*slot:108+32*slot])
            all_records.append(auth[140+32*slot:172+32*slot]+bundle[505+185*slot:690+185*slot])
    sorted_nfs = sorted(all_nfs)
    sorted_records = sorted(all_records)
    assert len(set(all_nfs)) == 4
    # This genuine pair has no duplicate records, so index() is unambiguous.
    # General multiplicity is tested exhaustively by the separate byte oracle.
    assert len(set(all_records)) == 4
    p = bytes(sorted_nfs.index(n) for n in all_nfs)
    q = bytes(sorted_records.index(r) for r in all_records)
    fee = sum(int.from_bytes(a[213:221], "little") for a in authorizations)
    public = (b"KPI2V6P1" + struct.pack("<HH", 1, 2) + TRUSTED_DOMAIN + TRUSTED_KEY_HASH
              + fee.to_bytes(16, "little") + b"".join(sorted_nfs) + b"".join(sorted_records))
    raw = public + b"".join(bundles) + p + q
    assert len(public) == P_LEN and len(raw) == 2846
    journal = b"KPI2V6J1" + struct.pack("<H", 1) + sha256(public).digest()
    # A mandatory exact-source marker callback isolates structural checks. It
    # is explicitly NOT a cryptographic verifier or evidence of proof validity.
    exact_markers = set()
    for bundle, auth in zip(bundles, authorizations):
        digest = sha256(auth).digest()
        limbs = tuple(int.from_bytes(digest[i:i+16], "little") for i in (0,16))
        exact_markers.add((bundle[377:505], limbs))
    structural_journal = research_instance_contract(
        raw, lambda proof, limbs: (proof, limbs) in exact_markers,
        trusted_domain=TRUSTED_DOMAIN, trusted_vk_hash=TRUSTED_KEY_HASH)
    assert structural_journal == journal

    # Only now inspect the producer's expected files for byte-for-byte equality.
    expected_files = [("expected-public.bin", public), ("expected-journal.bin", journal),
                      ("expected-input.bin", raw)]
    for name, computed in expected_files:
        assert (directory/name).read_bytes() == computed, f"independent bytes differ: {name}"

    manifest = json.loads((directory/"manifest.json").read_bytes())
    context = manifest["common_membership_context"]
    level = [sha256(b"\0"+bytes.fromhex(cm)).digest() for cm in context["commitments"]]
    empty = bytes(32)
    for depth in range(16):
        level = [sha256(b"\1"+level[i]+(level[i+1] if i+1<len(level) else empty)).digest()
                 for i in range(0,len(level),2)]
        empty = sha256(b"\1"+empty+empty).digest()
    assert len(level) == 1
    assert len(context["commitments"]) == context["count"] == 3
    assert all(a[40:44] == (3).to_bytes(4,"little") and a[44:76] == level[0]
               for a in authorizations)
    assert context["anchor"] == level[0].hex()

    print(json.dumps({
        "scope": "independent exact-byte recount of separate PUBLIC development fixture",
        "original_instance_qualified": False,
        "proof_verification_performed": False,
        "accepted_state_verified": False,
        "receipt_verified": False,
        "settlement_authorized": False,
        "public_directory": str(directory),
        "trusted_domain": TRUSTED_DOMAIN.hex(), "trusted_vk_sha256": TRUSTED_KEY_HASH.hex(),
        "bundle_sha256": [sha256(b).hexdigest() for b in bundles],
        "public_bytes": len(public), "public_sha256": sha256(public).hexdigest(),
        "journal_bytes": len(journal), "journal_hex": journal.hex(),
        "journal_sha256": sha256(journal).hexdigest(),
        "input_bytes": len(raw), "input_sha256": sha256(raw).hexdigest(),
        "aggregate_fee_sompi": str(fee),
        "source_expected_files_byte_identical": True,
        "public_synthetic_anchor_reconstructed": level[0].hex(),
        "private_permutations_in_this_already_public_fixture": {"p":list(p),"q":list(q)},
    }, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: public_fixture_recount.py PUBLIC_DEVELOPMENT_FIXTURE_DIR")
    main(sys.argv[1])
