# Native proof composition: source review and usable dependency route

Reviewed 2026-10-22 (Australia/Sydney), from KPI source
`ec6aa15d586bcc8a90f7232b433fd48d8c73d509` on
`work/privacy-source-review-20261022`. This is a read-only upstream
source review supporting the separate, unfunded two-transition composition
experiment. It does not select a production architecture, authorize settlement,
qualify financial privacy, or reproduce any historical recovery experiment.
No compiler, prover, node or native transaction was run by this review.

**Recommendation:** reuse the existing RISC Zero 3.0.3 execution route and
qualified accelerated BN254 adapter in an isolated guest. Feed it canonical
public v6 statements and Groth16 proof bytes, verify both proofs under an
independently fixed v6 key, and prove the ordered state transition relation.
Keep this as a nonsettling experiment. A vProgs runtime migration and a new
cryptographic proof system are unnecessary to answer this bounded question.
This is an implementation recommendation derived from the sources below, not
evidence that the new guest builds or verifies a receipt.

## What was refreshed

These heads were resolved through the connected GitHub API during this review.
Files used below were read at their exact commits. A current source head does
not establish the version running on a live network, compatibility of an
unbuilt dependency graph, or deployment maturity.

| Repository / branch | Exact current commit | Change relative to earlier KPI source notes |
| --- | --- | --- |
| [Rusty Kaspa / master][native-head] | `4edcbbccb449f84832afb1ca157904b35f37d006` | Nine commits after native experiment pin `01b532e8b553523216471682649693af92f0fd16`. |
| [Kaspa docs / main][docs-head] | `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` | Same as the earlier review. |
| [KIPs / master][kips-head] | `e4ae2332117b5cb68bd6188e065ef885b6d17939` | Same; the commit marks KIPs 16/17/20/21 active. |
| [vProgs / master][vprogs-head] | `f9b84a863a7c7c20586a9cf947550475e894f72e` | Same; README still labels the framework early/prototype. |
| [Kaspa research / main][research-head] | `c923faca11a49148fa7d912d27ce00197a5c5a4a` | Same; index still labels full vProgs specification v0.0.1 Draft. |
| [Orchard / main][orchard-head] | `616a669df8c9a59c33d47064d3ce04b25d026b2e` | Same as the earlier review. |
| [Zcash ZIPs / main][zips-head] | `2bdf39494320e5e04057ac93b1794031ebfb00b5` | New head; ZIP-224 was inspected at this pin. |
| [Aztec packages / next][aztec-head] | `47e78169a047e1aebe97b3bc3ae0aab2d03bd221` | Moving development head, distinct from the prior v5.2.0 release review. |
| [RAILGUN circuits-v2 / main][railgun-circuits] | `0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb` | Same circuit pin as the earlier review. |
| [RAILGUN contract / main][railgun-contract] | `36bcf5ed7cf94bfafb6e1a303e1832c769c16780` | Current verifier/logic source inspected; no deployed-contract claim. |
| [Monero / master][monero-head] | `8340be5e920d881edc006e0896d6074cd06dfb2e` | Refreshed after the earlier review. |
| [Litecoin / master][litecoin-head] | `ec1b6489a900d09cf5991e220dce089c77a232a2` | Same source pin as the earlier review. |
| [RISC Zero / main][risc0-head] | `3bbcd44d6459b9ef6ac0df3846dc9215514934e8` | Its manifest says zkVM 5.0.0; this is not the candidate's SDK. |

## Concrete dependency and receipt route

### Keep the qualified guest separate from the native host

The current [shared-pool manifest](../poc/shared-pool/Cargo.toml) uses Arkworks
`=0.6.0` and native Kaspa `01b532e`. The previously execution-qualified
[accelerated adapter](../poc/accelerated-bn254/common/Cargo.toml) uses Arkworks
`=0.5.0`, SDK `=3.0.3`, and the officially documented `substrate-bn` patch at
`22108fe8c6ea1ebc1358fc4fd6854a6bf46e3509`, tag `v0.6.0-risczero.0`.
The patch's [manifest][bn-manifest] selects target-specific `risc0-bigint2`
with its `unstable` feature; its [arithmetic][bn-arith] selects bigint
operations only for the zkVM/RISC-V target. The official
[versioned precompile guide][precompile-guide] lists this patch.

Static comparison of the locally cached released crates found the Groth16
`data_structures.rs` file identical between 0.5.0 and 0.6.0. BN254 compressed
point widths and Groth16 field order are consistent with the native verifier.
The affine Rust representation changed in 0.6.0: the old public `infinity`
boolean became a private generic zero flag. Therefore source-level replacement
of `0.5.0` by `0.6.0` does not preserve this adapter's API. This is a dependency
boundary, not proof of an encoding incompatibility.

Use a byte boundary and check it: deserialize submitted proof points with
validation, consume the complete input, require canonical reserialization, fix
the v6 key and its arity, and compare the adapter's result with the native
Arkworks 0.6 verifier on actual public fixtures. Do not pass unchecked submitted
coordinates to substrate-bn projective constructors. The existing
[adapter code](../poc/accelerated-bn254/common/src/lib.rs) provides this checked
conversion pattern; its old proxy key and intent semantics must be replaced by
the actual v6 key and complete v6 statement, rather than inherited by accident.
This review did not run the cross-version comparison.

The earlier [accelerated result](../poc/accelerated-bn254/RESULTS.md) and
[private-note proof result](../poc/private-note-proof/gpu-2026-10-18/RESULTS.md)
are dated execution/proving evidence for their exact guests. They are useful
compatibility evidence for that toolchain route; their timings, keys, program
images and successful receipts are not measurements of the new v6 aggregate.

### The official release already supplies the missing local tools

The [SDK 3.0.3 release API][sdk-release] reports the Linux archive below. The
pinned [release workflow][sdk-release-workflow] explicitly puts both
`cargo-risczero` and `r0vm` into it. A separate runtime source build is therefore
unnecessary merely to obtain the existing 3.0.3 IPC executable.

| Official artifact | Bytes | GitHub-reported SHA-256 |
| --- | ---: | --- |
| [SDK 3.0.3 Linux tools][sdk-linux] | 72,795,381 | `71a0adaa64235be13e9b8471bea5c4ded64bf97c6bd1eb9c2285b966c0b62fee` |
| [r0.1.97.0 Linux guest Rust][guest-linux] | 528,796,425 | `100b597d605b706bec94e1d32bfaaf5851df8d75173f986d4b56a3e90916be53` |

The [guest release API][guest-release] agrees with the exact toolchain digest
already in [bootstrap.sh](../poc/lane-completeness/bootstrap.sh). The SDK 3.0.3
release workflow used Rust 1.88.0 by default; it does not promise compatibility
with guest Rust 1.97.0. That newer combination is supported by this repository's
separately preserved prior execution evidence and must still be tested for a
new guest.

The Linux release's [Dockerfile][sdk-linux-build] builds `cargo-risczero`
without a CUDA feature. Its CUDA base image does not itself enable the optional
Rust implementation: the [CLI manifest][sdk-cli-manifest] makes `cuda` explicit
and defaults to `r0vm`; the [runtime manifest][sdk-runtime-manifest] has no
default CUDA feature. Consequently an installed GPU cannot accelerate this
official CPU executable merely through a runtime flag. A retained, separately
CUDA-built compatible executable or a separate CUDA build is required.

The SDK's [build code][sdk-build] advertises `RISC0_FEATURE_bigint2` while
constructing the guest build command. It is a build-time availability signal,
not a second runtime/proof-verification mode. Retaining the repository's
`RISC0_FEATURE_bigint2=1` follows that build convention; actual acceleration
still requires guest execution/profile evidence. The SDK's
[prover selection code][sdk-prover] explicitly supports
`RISC0_PROVER=ipc` and an absolute `RISC0_SERVER_PATH`. Preserve disabled
development mode and use `ProverOpts::succinct()` for the native `0x21`
candidate, rather than treating any serialized `Receipt` variant as admissible.

### Freeze the entire receipt dependency graph

Current Rusty Kaspa's [workspace manifest][native-manifest] fixes
`risc0-circuit-recursion=4.0.4`, `risc0-zkp=3.0.4`,
`risc0-binfmt=3.0.4`, and `risc0-zkvm=3.0.4`. The preserved
[private-note host lock](../poc/private-note-proof/Cargo.lock) uses zkVM 3.0.3
with recursion 4.0.4 / zkp 3.0.4. In contrast, the
[accelerated classifier guest lock](../poc/accelerated-bn254/classifier-guest/Cargo.lock)
currently resolves some components to recursion 4.0.5 / zkp 3.0.5 despite its
SDK 3.0.3 manifest pin. An exact top-level SDK version alone does not identify
the full receipt/prover stack.

The cached recursion 4.0.4 and 4.0.5 `control_id.rs` files were byte-identical.
That narrows one compatibility concern; it is not a substitute for proving and
verifying the actual receipt with the separately pinned host/native verifier.
The native [succinct verifier][native-risc0] accepts Poseidon2, checks control
inclusion and the fixed control root, and binds the successful claim to the
expected guest image and journal digest. Its
[receipt verifier][native-receipt] also fingerprints its parameters in a
stability test. Pin the produced program, expected image, canonical journal,
receipt kind, full Cargo locks, runtime executable and actual verifier.

## What the two-transition relation must establish

**Recommendation derived from existing composition implementations:** successful
verification of two unrelated proofs is insufficient. The outer guest must
also establish that they are the intended two consecutive transitions.

1. Verify each complete public statement and proof under the independently
   authorized key, network/pool/version and transition encoding. Include every
   amount as integer sompi; retain range checks and fees/liabilities.
2. Enforce exact order and continuity: the second pre-state equals the first
   post-state, including spentness and note-append position/count semantics.
   Bind both complete statements into the outer output and reject duplicates,
   reordered statements, substituted delivery commitments and trailing bytes.
3. Commit the first pre-state, final post-state, ordered effects, exact proof
   version/key identity and conservation totals. A future settlement covenant
   would additionally have to bind these outputs to the actual currently spent
   reserve and the exact native successor/payout outputs.

The reference [vProgs aggregate verifier][vprogs-aggregate] supplies a concrete
reuse checklist: fixed child image, invariant lane/covenant/transaction-program
identities, predecessor-root continuity, ordered exits and an exit commitment
in its settlement journal. Its [batch verifier][vprogs-batch] separately
authenticates activity and resource updates. Reuse those binding principles;
the full scheduler, archive service, operator daemon and lane settlement are
outside the bounded two-v6 question.

The reference [vProgs callback][vprogs-verify] calls SDK `env::verify`.
The SDK's [implementation][sdk-composition] adds an assumption about a zkVM
receipt for a fixed image and journal; it does not parse or verify native
Groth16 proof bytes, and it cannot classify an arbitrary bad Groth16 operation
as a no-op. For this experiment, ordinary checked BN254 verification in the
guest is the established direct route. If later wrapping each v6 verification
in a child zkVM receipt, recursive composition becomes a separate design with
new child-image, assumption-discharge and resource evidence requirements.

## Established privacy systems: reuse the relevant mechanism

| Primary source fact | Reuse / adapt / reject for the bounded candidate |
| --- | --- |
| Current [ZIP-224][zip224] defines a single Halo 2 proof over an Orchard Action bundle and explicitly says that proposal does not use Halo 2 recursion. Orchard's [Action rationale][orchard-actions] combines spend and output structure; [bundle code][orchard-bundle] checks version-specific proof sizes and binding authorization. | Reuse fixed structure, canonical proof bounds and distinct conservation/authorization responsibilities. A joint bundle proof, verifying several proofs, and recursively combining receipts are different constructions. Reject direct Halo 2 import as a native verifier route: Kaspa dispatch has no corresponding tag. |
| Current Aztec [transaction merge][aztec-merge] verifies two child proofs, restricts allowed verification keys, and then [checks constant equality plus consecutive note/nullifier/public-state snapshots][aztec-continuity]. Its [merge function][aztec-effects] accumulates effects and fees while taking the left start and right end. | Adapt the two-child continuity and allowed-key checklist. Do not transplant its field-valued fee assumptions to sompi or import its development execution shortcuts. Its [root-rollup verification helper][aztec-root] distinguishes propagating an IPA claim from closing it, reinforcing that an accumulator alone is not a final verified proof. |
| RAILGUN's [join-split circuit][railgun-joinsplit] binds public root, bound parameters, nullifiers and commitments to authorization and separately constrains balance. Its [contract verifier][railgun-verifier] chooses a key by input/output arity and leaves nullifier/state checks to the surrounding logic. | Reuse complete intent/effects binding and proof-versus-state separation. Do not copy its ABI as Kaspa canonical bytes or import caller-selected/owner-upgradeable key policy. Its Groth16 proof format is not automatically the native Arkworks compressed ABI. |
| Current Monero [RingCT implementation][monero-ringct] separates range-proof verification, spend authorization and commitment-balance checks; Bulletproof/Plus verification can process multiple proof objects. | Reuse the distinction between batched verification cost and all application predicates. A batch verification API does not produce a Kaspa-supported succinct aggregate receipt and does not create state continuity. Reject reimplementing its arithmetic or changing the candidate's note model to obtain a benchmark. |
| Litecoin [MWEB consensus][mweb-consensus] constrains bounded outputs, kernels and UTXO use; [peg-out kernels][mweb-kernels] carry public amounts/scripts and require matching native outputs. | Reuse exact native boundary accounting. Aggregation/cut-through is not a recursive proof verifier, does not hide native payout amounts, and does not erase observations already made. It gives no reason to change native consensus or the current candidate's exit rights. |

These comparisons inspect specific source mechanisms. They do not import any
other project's deployment, security review, trusted setup, license terms or
anonymity claim into KPI. No mature protocol source reviewed here provides a
drop-in native verifier for the entire proposed shielded-KAS system.

## Native constraints and actual decision impact

The current [tag dispatcher][native-tags] still exposes only Groth16 `0x20`
and RISC Zero succinct `0x21`. The [Groth16 verifier file][native-groth] has
the same Git blob (`19e930972c5ac1bec53c8b356010c73fec54f7db`) at native
pin `01b532e` and current `4edcbbc`. Comparing the RISC Zero receipt file
between those commits found only two redundant `return` removals. This source
refresh identifies no new verifier primitive requiring a change of candidate.
Keep the experiment's native pin until an explicit, tested migration.

Two public digest limbs imply three Groth16 input-coefficient points: native
base verification costs 140,000 grams plus 7,500 grams of key metering, before
surrounding script work. RISC Zero succinct has a 250,000-gram base charge.
The [network parameters][native-params] retain compute/storage/transient block
limits of 500,000 / 500,000 / 1,000,000; transient serialization costs four mass
units per byte. These source costs are not measured total transaction fees or
throughput. A nonsettling aggregate can measure proof/guest cost but cannot
demonstrate that a complete new covenant fits those budgets.

The current [inline-ZK guide][inline-zk] requires both proof verification and
actual successor-output validation. Its based-app discussion is an architecture
comparison, not a rule that every multi-operation proof requires the reference
runtime. Conversely, two successful guest checks would not show independent
permissionless exits, native reserve ancestry, archive availability or useful
privacy. The newer [paginated UTXO RPC][native-rpc] adds retrieval convenience
for current UTXOs; it does not recover spent ciphertext history or prove the
candidate's independent-recovery condition.

## Existing outer Groth16 compression is a separate comparison

The current vProgs [proof selector][vprogs-proof-type] and
[backend][vprogs-backend] already permit the final aggregate receipt to use
`ProverOpts::groth16()`. Its [witness adapter][vprogs-groth-witness] converts
the RISC Zero seal into a 128-byte compressed Arkworks BN254 proof. Its
[covenant][vprogs-covenant] reconstructs the receipt claim from the fixed guest
image and journal, then supplies five Groth16 public inputs under the
programmatically fixed RISC Zero key. This is existing source and an important
alternative to retaining the large `0x21` seal; it is not a newly proposed
cryptographic primitive.

Five public inputs require six input-coefficient points, giving native base/key
cost 155,000 mass before covenant, transaction and storage costs. That source
bound is not a measured new aggregate. It changes the potential amortization
question enough that the 224 KB result below must be read as a constraint on
the retained **Succinct** route, not every existing outer-proof route.

The [SDK 3.0.3 compression implementation][sdk-groth-cuda] requires the separate
rzup `Risc0Groth16` component version `0.1.0`, including witness/setup/prover
artifacts, for CUDA compression; the [dispatcher][sdk-groth-prove] uses a
Docker implementation without CUDA. The retained CUDA executable alone does
not establish those assets are present or the path works. A future comparison
needs exact setup/artifact provenance, availability, compression resource/time
measurements, fixed-key/image/journal controls, native acceptance and explicit
setup assumptions. This review did not install assets, pull an image, compress
a receipt or widen the current Succinct experiment.

## What aggregation could actually amortize

This arithmetic uses native pin `01b532e`, retained public transactions and
measured v6 layouts. It does not construct a new settlement, change a fee policy,
predict privacy, or establish a production rate.

### The 224 KB cost is primarily the STARK seal

The retained [native-value final receipt](../poc/native-value/evidence/proofs/final/receipt.bin)
is 223,930 bytes. Reading its SDK 3.0.3 fixed-integer bincode prefix identifies
the Succinct variant and 55,667 seal words: **222,668 bytes of seal** and only
1,262 bytes of nonseal receipt serialization, including its 352-byte journal.
The [private-note receipt archive](../poc/private-note-proof/gpu-2026-10-18/evidence/gpu-artifacts.tar.gz)
contains the same seal-word count and total size. This review checked the
private-note receipt hash against its retained manifest before inspecting those
public layout bytes; it did not reverify the cryptography.

The [captured native-value settlement](../poc/native-value/evidence/settle-final-rpc.json.gz)
has this exact input-0 signature-script decomposition. The
[settlement builder](../poc/takeover/vendor/covenant/src/settlement.rs)
confirms the push order.

| Component | Bytes |
| --- | ---: |
| STARK seal | 222,668 |
| Control inclusion path | 256 |
| Claim digest and control index | 36 |
| Deposit hash, new lane tip, new state and block anchor | 128 |
| Redeem script | 561 |
| Push prefixes for these nine elements | 17 |
| **Input-0 signature script** | **223,666** |

Applying the pinned [native mass formula][native-mass] to the captured
two-input/three-output transaction gives **224,160 estimated bytes**, compute
mass **476,260**, transient mass **896,640**, and declared storage mass 119,992.
Its 2,500/10 input budgets and output scripts come from the captured transaction.
At the retained 100 sompi per normalized mass policy, the recomputed relay floor
is 47,626,000 sompi. This is distinct from its actual paid fee or a current-node
fee quote.

Only 25,840 estimated bytes of the 250,000-byte transient ceiling remain;
compute headroom is tighter at 23,740 mass. About 99.3% of the estimated
transaction size is the seal. Removing a JSON wrapper, the complete bincode
envelope, or the old 561-byte covenant cannot recover most of that cost. The
native witness already carries seal pieces rather than the entire SDK receipt.

### Conditional 2 / 4 / 8 / 16 operation comparison

The [measured v6 internal payment](../poc/shared-pool/evidence/2026-10-19-two-input-offline/summary.json)
is 30,138 estimated bytes and 330,508 compute mass, with a chosen fee of
40,000,000 sompi and relay floor 33,050,800 sompi. The script is deliberately
padded to 24,576 bytes and declares budget 3,000; its public native payload is
5,228 bytes. The [TN10 result](../poc/shared-pool/TWO-INPUT-TN10.md)
separately records native acceptance of the unchanged 40,000,000-sompi policy.

For a transparent arithmetic comparison, retain the historical 224,160-byte /
476,260-compute outer settlement and **add one unchanged 5,228-byte v6 payload
per operation**, with no additional code, input/output or execution-budget cost.
That is a favorable lower estimate within this particular retention scenario:
a real aggregate must replace the old program/covenant semantics and may need
additional native outputs, signatures, script operations or data.

| Operations | Sum of unchanged direct compute mass | Illustrative outer estimated bytes | Illustrative outer compute mass | Fits both known block ceilings? |
| ---: | ---: | ---: | ---: | --- |
| 2 | 661,016 | 234,616 | 486,716 | Arithmetically yes; new settlement unimplemented. |
| 4 | 1,322,032 | 245,072 | 497,172 | Arithmetically yes, with only 2,828 compute headroom. |
| 8 | 2,644,064 | 265,984 | 518,084 | No. |
| 16 | 5,288,128 | 307,808 | 559,908 | No. |

For the two fitting rows, illustrative relay floors per operation would be
24,335,800 / 12,429,300 sompi, before missing costs. A two-way guest result does
not establish a four-way gain. For eight operations the incremental byte budget
is at most 2,967 bytes each under the old compute layout, so retaining every
full native mutation witness does not fit. A public `Bundle` alone contains
377 authorization + 128 proof + 370 ciphertext bytes = 875 bytes, excluding
native state/mutation witnesses. Retaining that smaller record would require
an outer state-transition/recovery design that makes the omitted witnesses
unnecessary; 875 bytes is not an implemented aggregate settlement format.

The direct baseline also has material unqualified optimization headroom. Its
measured internal operation uses 14,972,614 script units. The pinned
[budget formula][native-units] gives covering budget 1,497 after the 9,999 free
units, versus the declared 3,000. With identical byte/output sizes, replacing
only that declaration implies compute mass **180,208** and relay floor
18,020,800 sompi. This is a sensitivity calculation, not a tested safe budget,
changed fee authorization or new accepted native transaction. Boundary and
worst-case qualification would precede any candidate policy change.

The break-even is explicit:

- Against unchanged direct mass, the illustrative outer wins in summed relay
  mass from two operations: 486,716 is below 661,016.
- Against hypothetically qualified tighter internal budgets, two direct
  operations cost 360,416, below that outer estimate. Three or more are needed
  for a possible relay-mass win under the same assumptions.
- A fee win requires actual native settlement, publication/recovery data,
  enough operations and a suitable fee authorization/payment mechanism. The
  existing v6 proofs already authorize exact per-operation fees; replacing
  them with a cheaper native transaction requires explicit relation/accounting
  design, not automatic savings in the current covenant.

Neither guest compatibility nor a constant-size final receipt removes inner
wallet proof generation. The retained v6 workload measured warm proofs at
20.131–22.286 seconds on four CPU threads, plus parameter loading. Prior
117.47M/139.76M-cycle classifier/private-note guests use different relations;
they cannot supply v6 aggregate cycle, CPU-time or GPU-time estimates. The new
two-proof guest must be measured; 4/8/16 operation costs remain unknown.

### A focused native budget experiment needs no private keys

The native [v1 transaction ID code][native-tx-hash] excludes compute budgets
from its canonical rest preimage; the [signature hash code][native-sighash]
also excludes them for v1 and has explicit unchanged-hash mutation vectors.
The full transaction hash includes those commitments. Thus a budget-only
experiment can retain genuine proofs, authorizations, ciphertexts, native
outputs, fees, ordinary funding signatures and descendant outpoints. Assert
unchanged v1 ID/signature hashes and changed full transaction hash explicitly.
This follows this exact source version; it is not a generic transaction rule.

The proposed isolated, no-broadcast comparison retains budget 3,000 as control
and tests 1,500 and 1,600. For every selected reserve input, first measure its
actual units `u`, then test exact mathematical covering budget
`floor(u / 10,000)` and one less. The first bootstrap SPEND uses 14,972,614
units and needs 1,497; a later ordinary SPEND uses 14,969,886 and needs only
1,496. Consequently 1,496 is not a universal expected rejection. Budget 1,474
is below the 14,750,000-unit Groth16-plus-key floor and must reject every valid
two-public-input v6 proof. Classify the actual native budget error, rather than
counting any failed validation as evidence for this bound.

At 1,600 the retained internal layout would have 190,508 compute mass; the
largest retained admission layout would have 191,628. Their 200-sompi/mass
research floors are 38,101,600 and 38,325,600 sompi, below the unchanged
40,000,000-sompi fee. These are proposed fixture expectations, not executed
results or globally qualified budget defaults. Meter input 0 separately from
ordinary funding input 1. Full commitment/nullifier/history count and path
variants need separate coverage before adopting a lower default. The retained
[maximum-count DRAIN](../poc/shared-pool/evidence/2026-10-19-two-input-offline/boundary.json)
measures 14,848,061 units in an explicitly synthetic boundary state; it is not
a complete adversarial worst-case bound.

Two economic limits survive any such optimization:

- At reference rate 100, the 147,500-mass precompile/key minimum already costs
  14,750,000 sompi, above the adopted 10,000,000-sompi ordinary fee cap for a
  10-tKAS payment. No byte-padding or budget reduction alone can qualify a
  singleton direct proof at that low end; the zero-overhead payment threshold
  is at least 14.75 tKAS before other costs.
- At rate 500, that minimum costs 73,750,000 sompi, exceeding a supported
  60,000,000-sompi singleton note before even the 10,000,000-sompi payout floor.
  A necessary balance is at least 83,750,000 sompi even with zero other
  overhead. Reducing the declared budget cannot make the existing minimum
  singleton recoverable in that research scenario.

These are constraints under the [accepted requirements](../docs/rfc/0012-useful-privacy-requirements.md),
not permission to remove an existing liability or retrospectively change its
supported minimum, fee authorization or privacy score.

### Hiding a two-operation partition is a conditional hypothesis

The current nonsettling experiment consumes retained public bundles; producing
a receipt over already public records removes no prior observation. A future
native format could change what a chain-only observer first sees, but must
specify exactly which per-operation groupings and fields disappear. Native
entry/exit values, fee totals, destination scripts, batch size and activity
times remain relevant disclosures.

The collector receiving original bundles already knows their partition.
Combining two records does not hide it from the collector, create independent
activity or imply two independent users. If a fallback publishes an original
inner authorization, its immutable public fields can reidentify that record.
A fresh DRAIN is a different disclosure case and does not automatically reveal
the entire old partition. This review cannot assign either an anonymity rate
or assume fallback is disclosure-free.

The benefit to investigate is narrowly stated: less operation grouping in a
**new** chain transcript for an observer without collector or fallback
disclosure. There is no established collector privacy benefit or measured
practical privacy qualification from two-way composition. The immediate
engineering value is learning whether the existing verifier and v6 relation
compose at usable cost; privacy and an admissible native transaction remain
separate questions.

### Later local evidence: budget qualification and native receipt harness

The earlier budget sensitivity is now followed by a separate engineer's
[retained public native experiment](/home/luke/projects/kpi-intensive-2026-10-22/native/poc/shared-pool/evidence/2026-10-22-public-native-budget/attempt-03/validation.json).
All 13 original contexts and their 13 budget-1,600 variants passed actual
native script execution with unchanged original signatures, proof bytes,
outputs and 40,000,000-sompi fees. Nine focused cases qualified the measured
boundaries and underbudget rejection; four classifier controls rejected
unrelated errors. This review inspected the classifier against pinned native
source and read its retained results; it did not rerun that engineer's tests.
The exact current public fixture uses 14,972,613 bootstrap units and
14,969,899 ordinary-SPEND units, slightly different from the older reference
above; the 1,497/1,496 boundaries are unchanged.

The measured candidate maximum is 191,628 mining mass: at the scenario rates
200 and 500 its necessary fees are 38,325,600 and 95,814,000 sompi. The first
fits the unchanged 40,000,000 fee; the latter exceeds the 60,000,000 minimum
singleton note before its payout floor. This qualifies the selected public
matrix, not every future state/count/path variant or a wallet default. It
also makes the two-operation outer comparison stricter: two measured direct
operations have at most 383,256 combined mass, below the old illustrative
486,716 outer layout. Native compression and a complete new settlement body
must be measured before claiming that aggregation wins on fees.

An additive [native receipt harness](../poc/public-receipt-native-check/README.md)
now exercises the distinct Kaspa `TxScriptEngine`/`OpZkPrecompile` implementation
at `01b532e`; the SDK only parses witness bytes and supplies official claim and
fixed-parameter definitions. The paired image, complete J42 and JOIN control
are compiled independent expectations. Its `0x20` route adapts the existing
vProgs checked proof/key mappings, preserving the official RISC0 setup trust.
Three local statement/key/framing tests pass. The frozen source, lockfile,
binary and J42 identities are in
[harness-freeze.json](../poc/public-receipt-native-check/evidence/harness-freeze.json).

The exact retained historical public receipt passes native `0x21` and eight
negative controls in the
[isolated qualification](../poc/public-receipt-native-check/evidence/historical-final/report.json).
Each control must equal its precise source-derived typed native error; framing,
control authentication, seal integrity and expected-claim checks are recorded
separately. A generic `ZkIntegrity` failure cannot pass, since native Groth16
also serializes meter errors into that variant. This qualification used a
network-isolated process with only the executable, public receipt, system
libraries and evidence output mounted. Its positive bare predicate is
223,075 bytes and consumes 25,000,001 script units, covered by budget 2,500
under the native free-remainder rule. Those are predicate resources, not a
transaction's full compute/transient/storage mass.

The new public paired receipt subsequently passed the distinct native `0x21`
opcode and all eight declared negative controls; its separate
[paired report](../poc/public-receipt-native-check/evidence/paired-succinct/report.json)
binds receipt SHA256
`51a2f69e9986179696141ef106401109a3c7bf58fe87c8b0a645e29c49c4a3ec`
to fixed image `50ceec8e…7693d832`, complete J42 SHA256
`5d667b70…b06d4ac7`, and expected JOIN control. The receipt is 223,310 bytes;
its seal is still exactly 222,668 bytes. Its bare native predicate has the
same 223,075-byte/25,000,001-unit size and cost as the historical qualification.
This is native receipt compatibility for the new guest, separate from the
producer's SDK verification. The isolated native run took 1.289 seconds wall
time with a 13.8 MiB reported memory peak, including all nine cases. Its
[terminal service metadata](../poc/public-receipt-native-check/evidence/paired-succinct/run-metadata.json)
and raw log are preserved.

The same paired claim then passed actual native `0x20` and all seven declared
negative controls without changing the frozen checker. Its separate
[Groth16 report](../poc/public-receipt-native-check/evidence/paired-groth16/report.json)
binds the 581-byte receipt SHA256
`7ace0642e77fadacf9bc704e7500a97f2c8ea6a0b81a043ae5049eefbd1b97ff`
to the same fixed image/J42 and claim digest
`7e5bed968ae55ede2c88edb1021b5bb718d8785061d8df761050badd2210b2e3`.
The SDK seal is 256 bytes, converted by checked existing point mappings into
the actual 128-byte native proof. The fixed official key is 424 bytes, with
six input-coefficient points for five public inputs. Wrong expected image,
journal, BN254 control ID and a canonically negated proof point all fail
specifically at pairing verification; truncated/trailing proof or key bytes
fail at their declared framing checks. No new guest proof was generated for
compression, and the official setup trust remains an additional assumption.

| Actual same-claim native predicate | `0x21` | `0x20` |
| --- | ---: | ---: |
| SDK receipt bytes | 223,310 | 581 |
| Complete flat native script bytes | 223,075 | 728 |
| Native script units | 25,000,001 | 15,500,001 |
| Bare covering compute budget | 2,500 | 1,550 |
| Budget contribution in grams | 250,000 | 155,000 |
| Compute lower bound if this literal script is embedded once | 473,075 | 155,728 |

The last row also counts the measured script bytes at the pinned estimator's
one compute gram per byte; it excludes remaining transaction framing,
inputs/outputs and execution. The
[comparison function](../poc/public-receipt-native-check/scripts/compare-native-costs.py)
checks retained script/proof/key hashes, common expected statement/checker,
and passing budget-1,600 direct layouts, then emits
[resource deltas and 2/4/8/16-operation necessary bounds](../poc/public-receipt-native-check/evidence/native-cost-comparison.json).
Two measured SPEND layouts sum to 381,016–381,840 compute mass. Under this
flat-script embedding comparison, `0x21` already exceeds that sum before
any additional transaction work; `0x20` leaves 225,288–226,112 compute grams
for additional aggregate costs before reaching it. This is an overhead
allowance, not an implemented transaction, fee saving or architecture choice.

For an otherwise empty block, the `0x21` literal embedding leaves at most
26,925 other estimated bytes before its transient limit; `0x20` leaves
249,272. At 4/8/16 operations those imply respective per-operation upper
bounds 6,731/3,365/1,682 versus 62,318/31,159/15,579 bytes if **all** other
bytes were zero. Fixed transaction/covenant overhead reduces every bound;
storage mass, publication/recovery and fee authorization are still missing.

The `0x20` native positive took 0.038963 seconds in this single debug-build
observation, compared with 0.238343 for `0x21`; these are not stable benchmarks
or throughput estimates. The full short `0x20` service had no retained
resource event, so its memory peak is unknown. Launch caps were observed at
2 CPUs/2 GiB/zero swap. Journal resource events give `0x21` peak 14,508,032
bytes, zero swap and 1,266,339,000 CPU nanoseconds. Post-GC `systemctl show`
defaults are explicitly excluded from the corrected runtime metadata.
No funded or settling action is performed by the harness.

### Actual one-shot state-aware transaction context (13:53 UTC)

The separate [state-native diagnostic](../poc/public-state-native-check/README.md)
now passes its actual native full-input script plus all 22 exact-error controls
for the independently selected historical n5→9 J336, image `e9d7bd51…cf9`,
compressed receipt `e01de265…83a3b` and claim `2450e2c7…5aaf4`.
The prior outpoint, authenticated prior redeem state, complete P, successor
state and actual R/R′ are reconstructed into J on the native stack; coherent
state/P/reserve changes reach the actual pairing rejection rather than an
earlier host comparison. [Exact result](../poc/public-state-native-check/evidence/historical-state-native-01/report.json)
and [independently transcribed claim preimages](../poc/public-state-native-check/evidence/historical-state-native-01/claim-boundary.json)
are retained. This is distinct from the earlier J42 bare-predicate check.

The measured native transaction is 2,920 estimated bytes, with a 1,383-byte
redeem, 1,516-byte signature script, 1,203-byte full-availability payload,
128-byte converted proof and fixed official 424-byte key. It uses 15,514,686
script units under the unchanged committed budget 1,600. Native mass is
163,290 compute/mining, 11,680 transient and 29 storage. Native Borsh roundtrip
is 2,910 bytes; that artifact includes cached identity and is not a P2P wire
size claim. The exact fee remains 80M: scenario necessary quotes at 100/200/500
are 16.329M/32.658M/81.645M. The 500 scenario **fails** by 1.645M and is
preserved without repricing the inner authorizations.

Two previously measured direct-v6 SPEND layouts at budget1,600 sum to
381,016–381,840 mass and 60,276–60,380 estimated bytes. That is a resource
reference for separate retained public workloads, **not a drop-in fee saving**:
the new diagnostic omits a continuing policy and owner exit and has a
literal synthetic predecessor guard. It cannot be funded or continue as a
reserve. No actual lower paid fee, 1% target, privacy improvement, initial
backing, accepted lineage or owner recovery follows. The separate
[SDK-free Full validator helper](../poc/public-state-consensus-check/README.md)
then consumed the exact saved body and supplied synthetic UTXO: official
isolation plus `TransactionValidator::Full` passed, as did ten exact typed
rejection controls and four separately labeled source-adapted policy cases.
Its native mass/fee values matched unchanged, including the 500-sompi failure.
This adds actual isolation, value/range, storage-commitment, maturity/sequence
and script validation in the declared context; actual mempool admission,
accepted-chain/predecessor existence, initial backing and exits remain absent.

The source investigation identified an existing pinned toolchain, GPU runtime,
SDK-to-native proof conversion and official verifier route; later implementation
evidence separately qualified actual receipt production and native acceptance.
No funded, deployed or settling action follows from this source note.

[native-head]: https://github.com/kaspanet/rusty-kaspa/tree/4edcbbccb449f84832afb1ca157904b35f37d006
[docs-head]: https://github.com/kaspanet/docs/tree/0ac77d043a802fc8196abfd5812ac2afbd97a2b9
[kips-head]: https://github.com/kaspanet/kips/commit/e4ae2332117b5cb68bd6188e065ef885b6d17939
[vprogs-head]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md
[research-head]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/README.md
[orchard-head]: https://github.com/zcash/orchard/tree/616a669df8c9a59c33d47064d3ce04b25d026b2e
[zips-head]: https://github.com/zcash/zips/tree/2bdf39494320e5e04057ac93b1794031ebfb00b5
[aztec-head]: https://github.com/AztecProtocol/aztec-packages/tree/47e78169a047e1aebe97b3bc3ae0aab2d03bd221
[railgun-circuits]: https://github.com/Railgun-Privacy/circuits-v2/tree/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb
[railgun-contract]: https://github.com/Railgun-Privacy/contract/tree/36bcf5ed7cf94bfafb6e1a303e1832c769c16780
[monero-head]: https://github.com/monero-project/monero/tree/8340be5e920d881edc006e0896d6074cd06dfb2e
[litecoin-head]: https://github.com/litecoin-project/litecoin/tree/ec1b6489a900d09cf5991e220dce089c77a232a2
[risc0-head]: https://github.com/risc0/risc0/blob/3bbcd44d6459b9ef6ac0df3846dc9215514934e8/risc0/zkvm/Cargo.toml
[bn-manifest]: https://github.com/risc0/paritytech-bn/blob/22108fe8c6ea1ebc1358fc4fd6854a6bf46e3509/Cargo.toml
[bn-arith]: https://github.com/risc0/paritytech-bn/blob/22108fe8c6ea1ebc1358fc4fd6854a6bf46e3509/src/arith.rs
[precompile-guide]: https://github.com/risc0/risc0/blob/3bbcd44d6459b9ef6ac0df3846dc9215514934e8/website/api_versioned_docs/version-3.0/zkvm/precompiles.md
[sdk-release]: https://api.github.com/repos/risc0/risc0/releases/tags/v3.0.3
[sdk-release-workflow]: https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/.github/workflows/release.yml#L50-L54
[sdk-linux-build]: https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/.github/containers/release/Dockerfile
[sdk-cli-manifest]: https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/risc0/cargo-risczero/Cargo.toml
[sdk-runtime-manifest]: https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/risc0/r0vm/Cargo.toml
[sdk-linux]: https://github.com/risc0/risc0/releases/download/v3.0.3/cargo-risczero-x86_64-unknown-linux-gnu.tgz
[guest-linux]: https://github.com/risc0/rust/releases/download/r0.1.97.0/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz
[guest-release]: https://api.github.com/repos/risc0/rust/releases/tags/r0.1.97.0
[sdk-build]: https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/risc0/build/src/lib.rs#L394-L439
[sdk-prover]: https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/risc0/zkvm/src/host/client/prove/mod.rs
[native-manifest]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/Cargo.toml
[native-risc0]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/risc0/mod.rs
[native-receipt]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/risc0/rcpt.rs
[vprogs-aggregate]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/abi/src/batch_aggregator/verifier.rs
[vprogs-batch]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/abi/src/batch_processor/verifier.rs
[vprogs-verify]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/verify_journal.rs
[sdk-composition]: https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/risc0/zkvm/src/guest/env/verify.rs
[zip224]: https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/zips/zip-0224.rst
[orchard-actions]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/actions.md
[orchard-bundle]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/bundle.rs
[aztec-merge]: https://github.com/AztecProtocol/aztec-packages/blob/47e78169a047e1aebe97b3bc3ae0aab2d03bd221/noir-projects/fnd/noir-protocol-circuits/crates/rollup-lib/src/tx_merge/tx_merge_rollup.nr
[aztec-continuity]: https://github.com/AztecProtocol/aztec-packages/blob/47e78169a047e1aebe97b3bc3ae0aab2d03bd221/noir-projects/fnd/noir-protocol-circuits/crates/rollup-lib/src/tx_merge/utils/validate_consecutive_tx_rollups.nr
[aztec-effects]: https://github.com/AztecProtocol/aztec-packages/blob/47e78169a047e1aebe97b3bc3ae0aab2d03bd221/noir-projects/fnd/noir-protocol-circuits/crates/rollup-lib/src/tx_merge/utils/merge_tx_rollups.nr
[aztec-root]: https://github.com/AztecProtocol/aztec-packages/blob/47e78169a047e1aebe97b3bc3ae0aab2d03bd221/barretenberg/noir/bb_proof_verification/src/lib.nr
[railgun-joinsplit]: https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/joinsplit.circom
[railgun-verifier]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Verifier.sol
[monero-ringct]: https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/ringct/rctSigs.cpp
[mweb-consensus]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/consensus.md
[mweb-kernels]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md
[native-tags]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/tags.rs
[native-groth]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/groth16/mod.rs
[native-params]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/config/params.rs
[inline-zk]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx
[native-rpc]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/rpc/core/src/api/rpc.rs
[native-mass]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs
[native-units]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs
[native-tx-hash]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/tx.rs
[native-sighash]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/sighash.rs
[vprogs-proof-type]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/proof_type.rs
[vprogs-backend]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/backend.rs
[vprogs-groth-witness]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/witness.rs
[vprogs-covenant]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/script.rs
[sdk-groth-cuda]: https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/risc0/groth16/src/prove/cuda.rs
[sdk-groth-prove]: https://github.com/risc0/risc0/blob/14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6/risc0/groth16/src/prove/mod.rs
