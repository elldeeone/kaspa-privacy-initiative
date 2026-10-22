# One public-v6 guest diagnostic: independent source review

Scope: source-only review requested by the outer-proof engineer while the
two-v6 host binary was building. No build, guest execution, proof, receipt or
native transaction was performed by this reviewer. The isolated sources are in
the sibling `proof/poc/v6-guest-compat/` directory.

No material input/point/limb/journal correctness gap was found in the inspected
source. Runtime qualification remains the engineer's separate execution task.

The input is exactly 875 bytes. The guest reads at most 876 bytes and the common
verifier rejects any size other than 875. It uses a compiled, hash-pinned
328-byte key with checked canonical complete decoding, three IC points and
nonidentity conditions. The existing accelerated helper performs checked
canonical nonidentity decoding of the 128-byte submitted proof. SHA-256 of the
377-byte authorization is split into exact little-endian 128-bit field inputs.
Original ciphertext order and the zero-payout SPEND profile are enforced.

The 40-byte `KPI1V6J1 || SHA256(bundle)` journal is intentionally a diagnostic for
an already public source bundle. It exposes a per-bundle handle. It is neither
the 42-byte two-v6 journal nor a suitable hidden-grouping publication format.
Its host match is execution evidence, not a receipt or settlement authority.

## Addressed finding: image provenance was only adjacent-file consistency

Initially, `wrap RAW_ELF NEW_PROGRAMS` derived `expected-image.txt` from its
caller-selected ELF, while `execute PROGRAMS ...` compared the program only with
that adjacent file. Replacing both program and adjacent expectation with a guest
that simply emitted the known journal could satisfy that check. It did not
establish the independently expected verifier identity.

The reviewer requested a frozen image selected outside the runtime program
directory. The engineer added the host executable constant
`EXPECTED_GUEST_IMAGE`, initially disabling execution until it was built and
frozen. The inspected final pin is
`1f3b9b1785a11268432ffdd484b83ce5025315e23fc3aa9cf74e3c06e56026de`.
Execution now compares both the adjacent file and this compiled expectation.
Changing both program and adjacent file cannot bypass the reviewed host's pin.
The source/build/lock/raw-ELF/program identities should accompany actual results.

Inspected source hashes after this correction:

| Source | SHA-256 |
|---|---|
| `common/src/lib.rs` | `cf6d2b06d22680a1501f0be5886a1d704e8b801c570d29d7d90d0de4eb74df90` |
| `guest/src/main.rs` | `f420acc5d670c696a777f0ca8dd814752a73d87b92a103c46489b68b95d8c2f3` |
| `host/src/main.rs` | `be7162bf458ec5671039cb1bc04bddbfca6842eb3a37cb1392edbb6ea2bf7760` |

This review verifies the correction in source. It does not independently
recompute the ELF's image or verify a resulting execution/receipt. The one-v6
diagnostic must retain its separate identity and cannot close the same-anchor
two-v6 positive-fixture or native-settlement gates.
