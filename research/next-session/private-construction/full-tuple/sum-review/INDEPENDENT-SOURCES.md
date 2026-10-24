# Exact-field private sum: independent source check

2026-10-24 UTC. **Source research only; no implementation or experiment ran.**
This additive note does not select a KAS relation or change the closed
construction experiment, its observer, or its failed privacy thresholds.

## Decision input

**An established executable exact-field fallback exists: MP-SPDZ MASCOT.**
Use it, if selected by a later ADR, to test the isolated functionality
`Delta = sum(beta_i) mod r` over the actual Jubjub scalar field. Prefer this
over writing a new secure-sum protocol merely to fill an API gap. This is a
candidate for a bounded research harness, not a production dependency decision.

MASCOT is an arithmetic MPC protocol for finite fields with malicious security
and a dishonest majority, using oblivious transfer for preprocessing. That
provides a relevant established protocol family, rather than a claim that
plain pairwise masks suffice. The paper and the implementation remain distinct
evidence. [MASCOT, Keller–Orsini–Scholl, CCS 2016](https://research-information.bris.ac.uk/en/publications/mascot-faster-malicious-arithmetic-secure-computation-with-oblivi/)

The implementation's own documentation places MASCOT in its malicious,
dishonest-majority arithmetic category. It explicitly describes MP-SPDZ as
benchmarking software without implying the review expected of critical
production code. Its default prime capacity is up to 256 bits. No claim of
financial, adaptive-corruption, or production security follows from that.
[Pinned README, lines 134–153 and 429–443](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/README.md#L134-L153)

## Verified API and arithmetic seam

Repository `data61/MP-SPDZ`, commit
`113c4e47dd94bca9ecab029d2f0abe649bea5c52`, committer date
2026-10-16T03:29:42Z, resolved from the official GitHub API during this pass.

| Required operation | Actual source seam | Boundary |
| --- | --- | --- |
| Select exact field | Compiler `-P/--prime`; runtime `-P/--prime` | This is not merely choosing a nearby prime by bit length. |
| Reject field mismatch | `OnlineOptions::finalize_with_error` compares runtime and schedule primes | Runtime exits on conflicting nonzero primes. |
| One owner's private scalar input | `sint.get_input_from(player)` | Each party's own input file/process remains private; a common host running all parties is only a test fixture. |
| Reveal only the sum | Secret additions, then `.reveal(check=True)` | Do not reveal the input vector or individual contributions; retain the default opening check. |

The relevant source is
[compiler options](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Compiler/compilerLib.py#L180-L195),
[explicit-prime compiler handling](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Compiler/program.py#L108-L154),
[runtime options](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Processor/OnlineOptions.cpp#L208-L228),
[prime mismatch rejection](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Processor/OnlineOptions.cpp#L422-L434),
[secret input](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Compiler/types.py#L2193-L2207)
and [checked opening](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Compiler/types.py#L2535-L2543).
The checked-opening path must not be replaced by unchecked benchmarking modes;
the implementation also refuses destruction with outstanding unchecked values
in its normal check-enabled build.
[MAC-check source](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/MAC_Check.hpp#L79-L88)

The field must be Jubjub **scalar** `Fr`, not BLS12-381 scalar/base field,
`GF(2^k)`, XOR, or a limbwise integer approximation:

```
r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
```

That constant is independently verified from
[`zkcrypto/jubjub` source](https://github.com/zkcrypto/jubjub/blob/0cabeca668d89f9e8edbb3cbccdefeffdf21f651/src/fr.rs#L74-L82).
For a later harness, join it to the exact already-selected Jubjub dependency;
this independently checked upstream file does not replace its frozen pin.

## Why the drop-in federated-learning route is less direct

Bonawitz et al.'s active-server protocol is a useful established reference for
adversarial dropout scheduling. It adds a signed consistency check and needs
authenticated participant identities; otherwise a server can fabricate peers.
Its active result requires `2t > n + nC`, and the output necessarily discloses
a surviving-set sum. The paper discusses the server choosing dropouts after
masked-input collection. **That is not a verified guarantee against adaptive
corruption of previously honest machines.**
[CCS 2017 paper, sections 6.2–6.3](https://acmccs.github.io/papers/p1175-bonawitzA.pdf)

Google's current published FCP implementation is not a direct exact-Fr API:
`SecAggVector` stores `uint64_t` coordinates and caps the modulus at `2^62`.
That is a concrete implementation mismatch, not an impossibility theorem for
the protocol family. Independently exposing sums of small scalar limbs also
changes the released function: carries/lifts must be analyzed, not silently
treated as one Fr sum.
[`google/federated-compute`, `edabb545c185780c99a5b50dc5b8663f8945bc52`, header](https://github.com/google/federated-compute/blob/edabb545c185780c99a5b50dc5b8663f8945bc52/fcp/secagg/shared/secagg_vector.h#L40-L59)

## Composition limits that remain open

These are requirements/inferences for KAS, not upstream guarantees:

1. **Abort is sufficient for the first sum experiment.** A missing party may
   stop this attempt. Do not recover a missing party's private scalar or silently
   accept a changed participant set. Independent one-owner KAS recovery remains
   a separate path. Stock MASCOT is not claimed to deliver a dropout survivor sum.
2. A participant can supply an incorrect scalar. The later composition must
   check the global commitment relation and all proof records before any owner
   authorizes the exact final financial effects. A failed relation stops the
   attempt; secure input alone does not prove its semantic correctness.
3. Every participant must fix the same session, participant list, ordered
   commitment/proof records, fee, NF/state/reserve context and final effect digest.
   General MPC does not provide the surrounding wallet authorization policy.
4. The output itself leaks what it mathematically determines. With all but one
   contribution known, the remaining scalar is determined by Delta. Two-party
   tests cannot establish participant privacy. Releasing sums for overlapping
   sets with reused contributions creates additional equations even when every
   individual protocol run is correct. Fresh session material and output
   randomizers are mandatory candidate obligations, not a completed composition.
5. This pass verifies neither adaptive party-corruption security nor fair
   simultaneous output delivery. A corrupt party may learn an output and abort
   before another party receives it. The exact-body authorization boundary must
   prevent that from authorizing an unrecoverable or inconsistent KAS attempt.

## Smallest decisive next test — proposed, not selected or run

Freeze the selected MP-SPDZ commit, full dependency/build identities, exact `r`,
check-enabled MASCOT mode, authenticated party configuration, and one program
that accepts five scalars and opens **only their sum**. No KAS keys, witnesses,
PK, native VM, payments or hidden financial truth are required. Use five
separate isolated processes; coordinator/operator logs are distinct from each
party's private input directory. Resource limits must be coordinated with the
main lifecycle lane, not used to truncate or weaken protocol checks.

The fixed synthetic input vector `(r-1, r-2, 1, 2, 3)` has expected Fr result
`3`. It is public calibration data, so this test has **no anonymity score**.
Retain these four outcomes without post-result tuning:

1. Correct five-party run returns canonical Fr `3`, successful checked process
   exits, selected code/field identities and only the approved aggregate/counter
   output schema, with no input-vector dump. A legitimate sum can equal one of
   the inputs; literal value absence is not the acceptance criterion.
2. A deliberately different runtime prime is refused before a result is accepted.
3. One party disappears before its input; another run loses a party after input
   delivery but before completion. Neither incomplete run may be accepted as a
   completed five-owner sum or authorize any final body. Timeout is operational
   evidence, not proof of confidentiality.
4. Feed an intentionally incorrect contribution in a separate run. MPC may
   correctly sum that wrong input; an independent public synthetic commitment
   relation must then fail and prevent final authorization. This checks the
   semantic boundary instead of claiming MPC validates wallet witnesses.

Stop on an unsupported exact-field path, disabled check, unpinned dependency,
unexpected per-owner disclosure, or inability to isolate inputs. Retain any
build/API failure. A passing run establishes only the tested API/field/abort
composition; cryptographic privacy still rests on the selected protocol model
and later review. A later hidden-owner transcript experiment must separately
freeze observer/collusion, hidden truth, output-tuple mixing and acceptance
thresholds; it cannot inherit a privacy qualification from these arithmetic
controls.

## Fetched-source identities

All hashes are whole fetched public source/PDF bytes. No binaries or dependencies
were built, and no protocol was executed in this pass.

| Public source | SHA-256 |
| --- | --- |
| MP-SPDZ `README.md` | `8c20ccbca99108cf21ac17388adddae5160899b676a9f5d727172ba8407ed1d8` |
| MP-SPDZ `Compiler/compilerLib.py` | `006bd0f511ed8bfb20dbe6da96377aa3aa692591ec64951e0107ff22c4557a3e` |
| MP-SPDZ `Compiler/program.py` | `1b112e8d96f088017daf23d4f2e253dbc25e1a7fbf24faca348b2655e0551251` |
| MP-SPDZ `Compiler/types.py` | `e5d107b1351db6258c81a70cd8295d802fc19babff1c75a8b94f0a51157a481a` |
| MP-SPDZ `Processor/OnlineOptions.cpp` | `d1082b4d10eb5d9ae7286f20c01d2d146288852ba3711622a90b4737228aa651` |
| MP-SPDZ `Protocols/MAC_Check.hpp` | `6aa24821e6dae6370cd89832f407523dc046d4648dcc281f36dd054d7cb723b8` |
| FCP `fcp/secagg/shared/secagg_vector.h` | `41435f7c2923dd4826ba8dbbe9f2bfd8f4b30504ab76d360a39bd08850f368d3` |
| Jubjub `src/fr.rs` | `2f8e5e7a61f6092d510b7ecc2bd7a573001281c113ba7b0ae49cfddb3ddfd4d8` |
| Bonawitz CCS2017 PDF above | `9ccfc6ea68563d680e7e756b5db817b37dbe2eba15273a52e46d031102bdedbd` |

The IACR endpoints for the full Bonawitz and MASCOT PDFs returned HTTP403 in
this environment. The conference-hosted Bonawitz PDF was fetched successfully;
its direct-text extraction was unavailable because `pdftotext` is absent. The
web tool supplied the paper's sections quoted in the source analysis. No
global installation or access-policy workaround was attempted.
