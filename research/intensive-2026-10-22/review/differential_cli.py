#!/usr/bin/env python3
"""Independent, small semantic corpus for an already-built two_v6_binding CLI.

No build and no proof generation. Assembly is compared byte-for-byte with the
independent Python oracle. Synthetic witnesses must never pass Gate::verify.
All generated files stay in this review worktree and are removed after running.
"""

from hashlib import sha256
from pathlib import Path
import json
import subprocess
import sys
import tempfile

from two_v6_contract_oracle import B_LEN, INPUT_LEN, MAX_SOMPI, P_LEN, encode_synthetic


def main(binary, public_fixtures=None):
    binary = Path(binary).resolve(strict=True)
    outcomes = []
    with tempfile.TemporaryDirectory(prefix="cli-review-", dir=Path(__file__).parent) as temp:
        directory = Path(temp)

        def invoke(name, raw, expect=None):
            one, two = directory / f"{name}-one.bin", directory / f"{name}-two.bin"
            out = directory / f"{name}-input.bin"
            one.write_bytes(raw[P_LEN:P_LEN+B_LEN])
            two.write_bytes(raw[P_LEN+B_LEN:P_LEN+2*B_LEN])
            result = subprocess.run([str(binary), "assemble", str(one), str(two), str(out)],
                                    capture_output=True, text=True, timeout=30)
            if expect is None:
                assert result.returncode == 0, (name, result.stderr)
                actual = out.read_bytes()
                assert actual == raw, f"{name}: assembled bytes differ from independent oracle"
                assert out.stat().st_mode & 0o077 == 0, f"{name}: grouping witness is readable by other accounts"
                outcomes.append({"case": name, "status": "exact_assembly_match",
                                 "input_sha256": sha256(actual).hexdigest()})
                return actual
            assert result.returncode != 0 and expect in result.stderr, (name, result.stderr)
            assert not out.exists(), f"{name}: rejected assembly wrote output"
            outcomes.append({"case": name, "status": "rejected", "reason": expect})

        for name, options in [("unique", {}), ("equal-complete-records", {"duplicate_record": True}),
                              ("equal-cms-distinct-ciphers", {"duplicate_cm": True}),
                              ("maximum-fees", {"fees": (MAX_SOMPI, MAX_SOMPI)})]:
            raw, _ = encode_synthetic(**options)
            invoke(name, raw)

        raw, _ = encode_synthetic()
        # Every mutation names the exact acceptance boundary it should exercise.
        mutations = [
            ("magic", P_LEN, 1, "authorization magic"),
            ("domain", P_LEN+8, 1, "domain"),
            ("mode", P_LEN+204, 1, "SPEND mode"),
            ("payout", P_LEN+205, 1, "zero payout"),
            ("destination", P_LEN+221, 1, "native effects"),
            ("deposit", P_LEN+257, 1, "native effects"),
            ("funding-point", P_LEN+265, 1, "native effects"),
            ("funding-script", P_LEN+301, 1, "native effects"),
            ("bootstrap", P_LEN+337, 1, "native effects"),
            ("ciphertext", P_LEN+505, 1, "CiphertextDigest"),
            ("count", P_LEN+40, 1, "CountMismatch"),
            ("anchor", P_LEN+44, 1, "AnchorMismatch"),
        ]
        for name, offset, mask, error in mutations:
            bad = bytearray(raw)
            bad[offset] ^= mask
            invoke(name, bad, error)
        for name, lo, hi, replacement, error in [
            ("zero-fee", P_LEN+213, P_LEN+221, bytes(8), "Fee"),
            ("excess-fee", P_LEN+213, P_LEN+221, (MAX_SOMPI+1).to_bytes(8,"little"), "Fee"),
            ("zero-nf", P_LEN+76, P_LEN+108, bytes(32), "Nullifiers"),
            ("duplicate-nf", P_LEN+B_LEN+76, P_LEN+B_LEN+108, raw[P_LEN+76:P_LEN+108], "Nullifiers"),
            ("zero-cm", P_LEN+140, P_LEN+172, bytes(32), "Commitments"),
            ("duplicate-cm-in-bundle", P_LEN+172, P_LEN+204, raw[P_LEN+140:P_LEN+172], "Commitments"),
        ]:
            bad = bytearray(raw)
            bad[lo:hi] = replacement
            invoke(name, bad, error)

        if public_fixtures is not None:
            fixtures = Path(public_fixtures).resolve(strict=True)
            one = (fixtures/"rehearsal-row-6.bundle.bin").read_bytes()
            two = (fixtures/"rehearsal-row-8.bundle.bin").read_bytes()
            assert len(one) == len(two) == B_LEN
            assert sha256(one).hexdigest() == "10d201fc946f983e263277413e87c1e1bc6b7342642e13f82ec2a5814e81319e"
            assert sha256(two).hexdigest() == "d7096ebf3468a28a5c9860c1dca07fe65acfc6c5b15bd1908e0acd639fad770c"
            invoke("retained-real-pair-different-count", raw[:P_LEN]+one+two+raw[-8:], "CountMismatch")
            invoke("retained-real-proof-repeated", raw[:P_LEN]+one+one+raw[-8:], "Nullifiers")

        def verify_reject(name, candidate, reason=None):
            input_file, output_dir = directory/f"{name}.bin", directory/f"{name}-public"
            input_file.write_bytes(candidate)
            result = subprocess.run([str(binary), "verify", str(input_file), str(output_dir)],
                                    capture_output=True, text=True, timeout=30)
            assert result.returncode != 0 and not output_dir.exists(), (name, result.stderr)
            if reason is not None:
                assert reason in result.stderr, (name, result.stderr)
            outcomes.append({"case": name, "status": "rejected",
                             "reason": reason or result.stderr.strip()})

        # Cryptographic rejection is essential. Assembly success is not proof
        # success; these synthetic marker proofs are deliberately invalid.
        verify_reject("synthetic-proof-cannot-verify", raw)
        verify_reject("truncated-input", raw[:-1], "expected exactly 2846")
        verify_reject("trailing-input", raw+b"\0", "expected exactly 2846")
        for name, start, value, reason in [
            ("public-magic", 0, 0, "public projection"),
            ("aggregate-mismatch", 76, raw[76]^1, "aggregate fee"),
            ("nf-index-reuse", INPUT_LEN-8, raw[-7], 'Permutation("nullifiers")'),
            ("nf-index-out-of-range", INPUT_LEN-8, 4, 'Permutation("nullifiers")'),
            ("record-index-reuse", INPUT_LEN-4, raw[-3], 'Permutation("outputs")'),
            ("record-index-out-of-range", INPUT_LEN-4, 255, 'Permutation("outputs")'),
        ]:
            candidate = bytearray(raw)
            candidate[start] = value
            verify_reject(name, candidate, reason)
        candidate = bytearray(raw)
        candidate[92:124], candidate[124:156] = raw[124:156], raw[92:124]
        verify_reject("unsorted-public-nfs", candidate, "Nullifiers")
        candidate = bytearray(raw)
        candidate[220:437], candidate[437:654] = raw[437:654], raw[220:437]
        verify_reject("unsorted-public-records", candidate, "ProjectionOrder")
        candidate = bytearray(raw)
        candidate[252:437], candidate[469:654] = raw[469:654], raw[252:437]
        verify_reject("public-ciphertext-cross-wiring", candidate, "commitment/ciphertext record")
    print(json.dumps({"scope": "ordinary-host differential assembly and rejection controls",
                      "genuine_positive_proof_claim": False,
                      "binary": str(binary), "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
                      "cases": outcomes}, indent=2))


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise SystemExit("usage: differential_cli.py EXISTING_TWO_V6_BINDING_BINARY [PUBLIC_FIXTURES_DIR]")
    main(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None)
