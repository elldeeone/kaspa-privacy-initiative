# Ordinary-host two-v6 binding gate

This is an additive **NONSETTLING ordinary-host implementation** of the reviewed
two-v6 binding contract. It generates no zkVM program, image ID, receipt, native
transaction or accepted-state qualification. Existing wallet, covenant, prover
and generic checked-key verifier implementations are unchanged.

The canonical contract is
`research/orchestration/2026-10-22/roadmap/TWO-V6-BUNDLE-BINDING-CONTRACT.md`
in the orchestration documentation checkout, SHA256
`d16ec7b288cc93473cbeffd8af0c0071a06f575552522572f6ccd64b97a03e44`.
Its boundary cross-review and one-v6 compatibility/input controls remain the
source of the statement. This package implements that contract without adding
accepted-state, spent-set, backing, payout or recovery assumptions.

## What acceptance means

The host verifies two real Groth16 proofs with checked canonical Arkworks 0.5
decoding and the existing accelerated generic verifier. The default `Gate`
fixes the exact retained public rehearsal domain and 328-byte verification key,
including its SHA256, subgroup checks, three IC points and nonidentity checks.
It provides no constructor accepting a different key/domain.

The complete relation lives in the minimal `poc/two-v6-binding/common` crate;
the host library reexports it. This gives a future guest the identical relation
without pulling in the takeover host's native transaction dependencies. The
328 compiled public key bytes are checked directly, without runtime JSON.

It also checks every narrow SPEND-profile byte, equal private anchor/count,
four distinct nonzero active nullifiers, two nonzero distinct commitments per
bundle, original ordered ciphertext digests, individual fee bounds and exact
checked aggregate fee. Two bijections bind all public nullifiers and complete
commitment/ciphertext records. Cross-bundle duplicate commitments and complete
records retain their multiplicity. Independent CM/ciphertext sorting is rejected.

Successful verification establishes an existential partition of the public
projection into these two statements. It does not authenticate submitting users
or order, accepted anchors, current unspentness, native backing, correct
encryption, delivery, history availability, independent exits or any privacy
benefit. The collector sees the full witness and grouping. Repeating successful
host verification is not a second accepted spend or settlement.

`ConfiguredResearchGate` is a distinct, explicit alternative for a separately
identified public development fixture. Its expected domain and key digest are
trusted caller configuration supplied independently of the witness. Results
under a new experimental setup cannot qualify the original rehearsal instance.
The command-line tool uses only the canonical default `Gate`.

## Exact bytes

| Object | Encoding | Bytes |
| --- | --- | ---: |
| Bundle | authorization377 + proof128 + original ciphertext185 + ciphertext185 | 875 |
| Public projection P | `KPI2V6P1`, u16le1, u16le2, domain32, key-digest32, aggregate-fee-u128le16, sorted four NF32, sorted four complete record217 | 1,088 |
| Input | P + bundle0 + bundle1 + NF-permutation4 + record-permutation4 | 2,846 |
| Journal J | `KPI2V6J1`, u16le1, SHA256(P)32 | 42 |

Every input and record length is exact. Trailing bytes are rejected. Nullifiers
use strict unsigned lexicographic order; complete output records use nondecreasing
unsigned lexicographic order. Each permutation uses every index 0–3 exactly once,
even when two complete record values are equal.

The public projection digest is `H = SHA256(P)`. The separately returned
`journal_digest` is `SHA256(J)`, which is different from H. This implementation
does not map either digest into a native receipt or covenant argument.
`check_publication` verifies complete P/J consistency only; it is not proof or
receipt verification and cannot accept a bare digest instead of complete P.

## Build and use

Use the existing locked takeover workspace and public dependency cache. These
commands select the added library/bin only. They do not prove or contact a chain.

```bash
CARGO_TARGET_DIR=/path/to/independent-target cargo test --frozen --offline --release \
  --manifest-path poc/takeover/Cargo.toml -p kpi-two-v6-binding \
  --lib -- --test-threads=1
CARGO_TARGET_DIR=/path/to/independent-target cargo test --frozen --offline --release \
  --manifest-path poc/takeover/Cargo.toml -p kpi-takeover-host \
  --bin two_v6_binding -- --test-threads=1
CARGO_TARGET_DIR=/path/to/independent-target cargo build --frozen --offline --release \
  --manifest-path poc/takeover/Cargo.toml -p kpi-takeover-host --bin two_v6_binding
two_v6_binding assemble BUNDLE0 BUNDLE1 NEW_INPUT
two_v6_binding verify INPUT NEW_PUBLIC_OUTPUT_DIR
```

`assemble` constructs structurally bound input but does not verify either proof.
Its complete witness file is owner-readable/writable only (Unix mode 0600),
because grouping and individual authorization fields are not public outputs.
Only `verify` performs both real cryptographic checks. On success it writes
`projection.bin`, `journal.bin` and a limited scope report, without authorizations,
proofs, per-bundle hashes, anchors, individual fees or grouping indices. Existing
input/output files are never overwritten. Rejected verification creates no output
directory. Partial output after a filesystem error is retained for inspection.

## Retained public controls and evidence gap

`host/fixtures/two_v6/public-source-manifest.json` pins exact public source files,
slice offsets and SHA256 values for unmodified rehearsal rows 6 and 8. Both
875-byte bundles are verified individually. Their count/anchor values differ,
so they cannot form a valid accepted pair under this contract. Repeating row 6
instead collides on active nullifiers. No authorization/proof is rewritten to
manufacture a compatible original-instance pair.

Structural unit controls use deliberately invalid zero proofs and never claim
cryptographic acceptance. They check an independently calculated Python
SHA256 encoding vector, field boundaries, all forbidden native-effect bytes,
fee limits, every NF collision pair, all 256 in-range index vectors, paired-record
substitution, duplicate-record multiplicity, ciphertext order and publication
bytes. Real-proof controls separately check both retained proofs and require the
typed `invalid proof` result after changing only an otherwise allowed public
statement field. Malformed/noncanonical/identity controls remain distinct from
cryptographic rejection.

The original-instance full positive two-proof acceptance remains an explicit
evidence gap until a separately qualified same-anchor/count, disjoint-nullifier
pair is available. No guest/outer receipt/settlement claim follows from host
controls or a separate experimental-instance positive test.
