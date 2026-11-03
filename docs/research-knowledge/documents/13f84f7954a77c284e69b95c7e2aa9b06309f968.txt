# Exact SHA-256 constraint reductions: source analysis

Status: static source analysis only, 2026-10-23 UTC. No synthesis, setup, key
loading, proof, native validation or trial was run for this analysis. Existing
circuit and evidence sources were not modified.

## Recommendation

Adapt the pinned SHA-256 gadget in a separate experiment and replace its
three-gate choice and five-gate majority expressions with equivalent Boolean
selection expressions. This should cross the `2^22` Groth16 domain boundary
without changing SHA-256, the transfer relation or native transaction formats.
Measure this before attempting larger architectural changes.

For each bit:

```text
Ch(e, f, g)  = e.select(f, g)
Maj(a, b, c) = (a XOR b).select(c, a)
```

For majority, when `a == b`, the answer is `a`; otherwise it is `c`. For
choice, selection is the definition of the SHA-256 choice function. Each
result remains Boolean because the existing selection gadget constrains a
selection of Boolean branches by a Boolean condition.

Use the original expression whenever any operand bit is a constant. This
keeps the static saving below conservative: the generic majority rewrite can
otherwise add one gate for `c = 0` and variable `a, b`, because the original
then simplifies to `a AND b`.

## Source evidence

All registry paths below are under
`/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`.

| Source | Lines | Relevant behavior |
| --- | --- | --- |
| `ark-crypto-primitives-0.6.0/src/crh/sha256/constraints.rs` | 91-103 | Choice is two ANDs plus XOR; majority is three ANDs plus two XORs. |
| Same | 64-89, 116-137 | Standard SHA schedule, additions and feed-forward; these need no change. |
| Same | 142-212 | Standard 64-byte streaming blocks and SHA padding. |
| `ark-r1cs-std-0.6.0/src/boolean/allocated.rs` | 69-123 | Variable XOR and AND each allocate one result and enforce one R1CS constraint. |
| `ark-r1cs-std-0.6.0/src/boolean/select.rs` | 39-87 | A variable Boolean selection enforces one constraint and adds no separate Booleanity constraint. |
| `ark-r1cs-std-0.6.0/src/uint/convert.rs` | 64-76, 168-170 | `to_bits_le` clones existing bits; `UInt32::from_bits_le` reconstructs the word without allocating constraints. |
| `ark-groth16-0.6.0/src/generator.rs` | 88-89 | Domain is sized from `num_constraints + num_instance_variables`. |

Inspected SHA source SHA-256:
`7bff40e9ef3ea1ec15bd7bd472976cda1285b8dd0c3560b119dc1a508d676fb6`.
Inspected Boolean selection source SHA-256:
`0faea120e37997896c1a5a0c12af4c8c03b12cb6485e3c4cfe67d2d2ccaf1989`.
Inspected payment circuit SHA-256:
`e1e3e3e6201ef817516fda2c48fa6dbefb275fecf56632c10c4d7fe915798bd3`.

## Static compression count and saving bounds

The existing circuit calls SHA through `hash_g`, `digest` and `hmac_g` in
`poc/future-private-payment/src/circuit.rs:72-100`. Fixed-size branches are
always synthesized; a witness flag does not remove inactive hashes.

For a message of `L` bytes, standard SHA-256 uses `ceil((L+9)/64)` blocks.
For these 32-byte HMAC keys, the inner message starts with a 64-byte padded
key, and the outer message is 64 bytes plus the 32-byte inner digest.

| Use | Messages | Bytes per message | Compression blocks | Blocks after the first |
| --- | ---: | --- | ---: | ---: |
| Note commitments | 4 | 208 | 16 | 12 |
| Owner commitments | 2 | 104 | 4 | 2 |
| Key commitments | 2 | 72 | 4 | 2 |
| Two 16-level CM paths | 32 | 72 | 64 | 32 |
| Real nullifier HMACs | 2 | inner 140, outer 96 | 10 | 6 |
| Dummy nullifier HMACs | 2 | inner 137, outer 96 | 10 | 6 |
| Authorization digest | 1 | 484 | 8 | 7 |
| **Total** | **49 SHA invocations** | | **116** | **67** |

Circuit call sites: notes at 128-135 and 218/303; owner/key at 221-224;
CM paths at 248-263; both HMAC branches at 267-284; authorization at 334.

In a round with three variable operands, choice falls from three constraints
per bit to one, and majority from five to two. This saves
`(2+3) * 32 * 64 = 10,240` constraints per fully variable compression block.
Every continuation compression starts with the variable state produced by
the preceding compression. The 67 continuation blocks therefore give a
conservative source-derived saving of **686,080 constraints**. The constant
fallback prevents regressions in first-block rounds. An ideal upper bound,
counting every round of every block, is **1,187,840**; first-block constants
make that upper bound unattainable.

Against the existing measured 4,650,533 constraints, the implied interval is
**3,462,693 to 3,964,453**, before other changes. This is an estimate from
source operation counts, not a measured circuit. Including the three public
instance variables, even the conservative end is below 4,194,304 by 229,848.
A fresh synthesis must confirm the actual count and satisfaction.

Selecting the real/dummy HMAC inputs before hashing, a separate experiment,
removes ten further compression blocks. Its cost is not included in the
bound above. Do not double-count removed blocks when combining estimates.

## Independent candidate source review

Reviewed `poc/exact-sha-cost-probe/` before the full synthesis measurement.
**Source/math ACK:** the candidate implements the exact identities above and
the majority constant fallback. Choice selection cannot cost more than its
upstream expression under the pinned constant-folding cases, so it needs no
separate fallback. The 686,080 conservative reduction remains applicable.

A read-only text comparison found the body from `const STATE_LEN` through
`Sha256Gadget::digest` identical to the pinned upstream body after exactly
two replacements: the old choice block with `ch_word`, and the old majority
block with `maj_word`. IV, all 64 round constants, schedule, rotations, word
addition, state assignment order, feed-forward, streaming and padding are
unchanged. The word helpers preserve the little-endian bit order when
reconstructing `UInt32`.

The copied transfer circuit differs only in the SHA gadget import. The
copied library adds the private gadget module and a synthesis assertion
requiring `constraints + instance_variables <= 2^22`. It retains the
baseline relation and domain; no input-dependent relation specialization was
introduced. Test source covers all 64 combinations of Boolean values and
constant/witness allocation modes, checks non-regression and the 8-to-3
variable-bit saving, and covers 15 SHA message lengths including the padding
boundaries and contract lengths. These are source observations; this reviewer
did not run those tests or full synthesis.

Reviewed candidate SHA-256 pins:

```text
src/exact_sha256.rs  0f156c8611b64814b2b84de369bc03ab134992b8cd22831267b0d4c0c3a42751
src/circuit.rs       479146d51f3f20460d86867e45d9e14e1479f28e7bfcb584d0cab04117e83bf0
src/lib.rs           0e9c0e025c06d99d12c2a2b50d0f38161dee8b68880a28af1174c6438aa3c353
```

This ACK supports the isolated measurement. It does not authorize changing
the selected development key or funding profile and does not establish
proof performance, cryptographic correctness or production safety.

## Constant bytes and prefix sharing

`circuit.rs:161-170` allocates all 484 authorization bytes as witnesses and
then equates 120 bytes to constants: the authorization magic/domain and the
two state magic/domain prefixes. Replacing those bytes with actual constant
gadgets would remove 960 witness-bit allocations plus their equality checks,
and allow constant folding in the corresponding SHA schedule. The domain
passed to note/owner/key/HMAC hashes is currently the constrained witness
slice, so supplying the fixed domain directly also exposes its constants to
the gadget. This preserves a fixed-domain relation only if all public digest
binding remains intact; keep wrong-domain negative controls.

These substitutions do **not** remove an entire compression block: the
shared tag-plus-domain prefix is only 40 bytes. Cloning a streaming SHA state
after 40 bytes copies a pending buffer and shares no compression work. Owner,
key and note tags differ, and independent inputs may have different owners,
keys and incoming fields. A same-owner fast path must not silently restrict
the existing two-input relation. Therefore prefix sharing is lower priority
than the choice/majority substitution.

## Required checks for a prototype

1. Keep the current circuit and selected key unchanged; use a new package and
   fresh setup only after synthesis confirms the reduced relation.
2. Exhaustively compare both Boolean expressions across eight input triples
   and constant/witness allocation combinations; compare SHA output against
   ordinary SHA-256 at relevant message lengths and padding boundaries.
3. Re-run the frozen valid transfer relation and malformed/replay/domain/
   value-conservation controls against the isolated circuit. A passing hash
   vector alone does not establish transfer-relation equivalence.
4. Measure fresh proof latency and peak RAM, then actual native verification
   with its new verification key. Domain reduction predicts smaller FFT
   vectors; it does not establish a particular RAM or latency result.
