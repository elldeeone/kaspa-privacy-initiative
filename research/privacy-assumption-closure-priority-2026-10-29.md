# Privacy assumption closure priority

Date: 2026-10-29  
Repository baseline: `b58de1a182347c4223ebe84f92bb0bdd6c88d003`  
Status: implementation/evidence routing only; **no assumption is selected**

## Decision

The highest-leverage non-overlapping work is a source-owned **honest owner
material/producer authority**, followed by the already-started two-circuit
bounded setup.  The first authority can close the common applicability gap for
`S1`, `S2`, `S5`, and `S7` and the direct honest-producer row.  It cannot select
those assumptions by itself: `S2` and `S7` still depend on the idealized
MASCOT/DDNNT view, `S5` still needs the V3 hidden-key path, and every family
still needs a canonical reviewed assumption preimage.

Before any closure can authorize Step 2, the immutable successor to output ABI
v3 must represent closure evidence.  Current v3 intentionally encodes only
three **open** dispositions and `authorizing: false`; it has no closed
disposition or evidence digest
(`privacy_measurement_output_abi.py:108-117,262-285`).  Reinterpreting v3 as a
pass would be an ABI downgrade.  The successor must use a new model/ABI
identity; this note does not modify the frozen observer or model.

## What the prioritized rows actually count

The frozen two-round model has one public occurrence per round for CM hiding,
joint CV hiding, ciphertext confidentiality/key privacy, and NF unlinkability.
It has two proof occurrences per round: Output proofs and the aggregate proof
(`privacy_capture_model.py:255-299`).  The v3 registry therefore records:

| Current family row | Per view | All four views | Honest future split |
|---|---:|---:|---|
| SHA-256 note commitment | 2 | 8 | `S1`, one occurrence per round |
| Pedersen CV joint view | 2 | 8 | `S2`, one occurrence per round |
| Output ciphertext joint confidentiality | 2 | 8 | conjunctive `S5 + S6A`, one occurrence per round |
| Nullifier PRF/unlinkability | 2 | 8 | `S7`, one occurrence per round |
| Generic Groth16 public proof ZK | 4 | 16 | `S4` Output and `S12` aggregate, two occurrences each |
| Honest output encryption producer | 2 | 8 | direct authority, one occurrence per round |

These are repeated view counts, not 56 independent experiments.  In the union
view they are 14 open occurrences.  A closure receipt must bind the underlying
two-round evidence once and name the exact covered field paths; it must not mint
four unrelated copies.

## Ranked closure work

### 1. Source-own honest owner material and output production

This is the smallest shared applicability closure for the most prioritized
rows.  The selected source already intends the right distributions:

- `output_producer.py:105-125` samples a 32-byte `rho`, a scalar blind, invokes
  the sealed-box bridge, binds `CM || CV || SHA256(ciphertext)`, and produces an
  independently verified Output proof;
- `lifecycle_worker.py:114-163` calls that path for the two output slots, samples
  the input-CV rerandomization blind, derives the nullifier material, and writes
  the owner-private record; and
- `wallet_profile.py:65-69,196-240` defines the HMAC-separated owner keys and
  exact nullifier message.

But source calls are not yet an authority:

1. `OutputProver.create(..., rho=None, blind=None)` accepts caller-supplied
   randomness.  The exact selected lifecycle calls omit those parameters, but
   the production API itself does not enforce that distinction.
2. The input blind is separately sampled in `lifecycle_worker.py`; no single
   object binds all three owner blinds to the attempt, owner, round, and output
   slots before any private egress.
3. The Python interpreter and OS-random implementation are not in the complete
   selected runtime closure.  On the inspected host, CPython 3.14.4
   `secrets.randbelow` delegates to `SystemRandom._randbelow`, which uses
   rejection sampling over OS bytes (`/usr/lib/python3.14/secrets.py:18-29`,
   `/usr/lib/python3.14/random.py:228-252,888-913`).  That is good source
   behavior, not an authenticated run receipt.
4. The Rust bridge pins `crypto_box = 0.9.1` and `rand = 0.8.5`; `seal` passes a
   fresh `OsRng` directly to `PublicKey::seal`
   (`poc/future-recipient/bridge/Cargo.toml:10-15`,
   `poc/future-recipient/bridge/src/main.rs:39-43`).  It returns only ciphertext,
   but the current parent call does not emit a linear provenance authority.
5. Retry poisoning and durable one-use indices are being built separately for
   V3.  A local “values differ” test cannot replace that ledger.

The minimal production seam should be one move-only
`HonestOwnerMaterialAuthority` per `(trial, attempt, round, owner)`:

1. A source-owned launcher fixes the exact lifecycle, output-prover, crypto
   bridge, owner-auxiliary, interpreter/runtime, and launch-plan identities.
2. The source owns generation of the input blind, two output blinds, two
   `rho` values, two sealed-box ephemeral secrets, and the exact NF/delivery-key
   indices.  Ordinary production callers cannot inject them.  Deterministic
   values remain available only through a compile- or source-separated test
   fixture.
3. The authority binds the attempt and owner role before generation, consumes
   the V3 durable one-use ledger head, and poisons the entry on every success,
   error, abort, or partial output.  A retry requires a fresh attempt identity.
4. Inside the private producer, check canonical scalar ranges, exact slot
   counts, no duplicate private material within the attempt, and exact
   correspondence to the resulting CM/CV/ciphertext/NF/proof statements.
5. Export no private value and no caller-readable secret hash.  Carry only an
   opaque residual plus public statement identities/counts needed by the later
   observer join.  The later join must consume the residual once.
6. Bind two independent honest-owner authorities per round to the actual
   terminal capture capsule.  C1's known material remains direct auxiliary
   input and is not relabeled hidden.

This authority would supply applicability evidence as follows:

| Family | What this authority can close | What still blocks selection |
|---|---|---|
| `S1` | exact fixed encoding; fresh one-use hidden `rho`; honest producer and statement correspondence | explicit salted-hash hiding assumption and complete-view non-disclosure |
| `S2` | three canonical, fresh, independent owner blinds; retry non-reuse; exact CV statements | `S8/S9` idealization of P1's shares/offsets, complete-view secrecy, and reviewed joint-hiding preimage |
| `S5` | exact crypto bridge/build; fresh ephemeral per output; honest plaintext/recipient input and ciphertext correspondence | `S6A` one-use delivery-key ledger plus native negative inventory; message-security assumption |
| `S7` | exact key/index/message derivation and circuit/public-NF correspondence; no raw key export | `S8/S9` for P1's secret-input view, native key absence, and PRF/preimage assumptions |
| direct producer row | source-owned CM/CV/ciphertext/proof correspondence for both rounds | actual terminal attachment and sole-consumer observer join |

It can also authenticate fresh randomized Output-prover invocation, but cannot
repair the Output CRS.  `S4` remains blocked until setup closure.

### 2. Finish the exact two-circuit bounded setup authority

This is the most decisive single experiment for `S4` and `S12`.  The in-progress
authority already binds distinct Output and aggregate circuit closures, exactly
two setup runs, four PK/VK artifacts, inherited private output descriptors,
network/core/swap/debugger restrictions, and explicit non-claims
(`bounded_setup_authority.hpp:26-79,141-175`).  It correctly leaves the
source-owned selectors, actual worker, both full runs, setup honesty, and
`S4/S12` selection false.

Required finish, without overlap with the owner-material work:

1. freeze the static setup worker plus complete source/compiler/runtime closure;
2. add source-owned plan and worker selectors; reject caller-provided entropy;
3. execute both full setups once under the bounded policy;
4. independently validate exact PK/VK sizes, subgroup encodings, matrix/source
   identities, fixed proof fixtures, and the two-run plan binding;
5. retain the receipt's explicit `best_effort_erasure_only=true` and
   `erasure_cryptographically_proven=false`; and
6. select only the declared bounded-Testnet trust assumption
   `A-CRS-LOCAL-BOUNDED-V1`, never a ceremony or production-trust claim.

The primary Groth16 implementation samples CRS trapdoors in setup and fresh
`r,s` in its randomized prover, while exposing a non-ZK `r=s=0` path
([Arkworks Groth16 0.6.0 setup](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/generator.rs#L14-L43),
[prover](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/prover.rs#L137-L170)).
The local bounded assumption and its limits are already specified in
`crs-and-recipient-key-privacy-remediation-2026-10-29.md:418-469`.

This one two-run receipt can close the CRS applicability gate for all four
union-view proof occurrences after the observer registry splits `S4` from
`S12`.  Aggregate `S12` still depends on `S8`, `S10`, and `S11` for its
authenticated `r,s` provenance.

### 3. Create the immutable closure ABI and selection authority

Do this after the evidence-producing APIs stabilize.  Do not mutate v3 or the
frozen model in place.

The new registry must:

1. split the generic Groth16 row into `S4-OUTPUT-GROTH16` and
   `S12-AGGREGATE-GROTH16` because they have different circuits, CRSs,
   randomizers, and dependencies;
2. represent the ciphertext row as a conjunction of `S5` and exactly one
   recipient-key path (`S6A` for the bounded V3 experiment), rather than allow
   either digest to close the row alone;
3. encode dependency edges (`S2 <- S8,S9` for the captured P1 delta view;
   `S7 <- S8,S9` for the captured owner-input view;
   `S12 <- S8,S10,S11`), not only flat family labels;
4. carry canonical statement/preimage digests, source/build/runtime/launch
   identities, exact covered field paths, trial/attempt/run bindings, and
   one-shot evidence-authority identities;
5. expose closed rows only after all dependency authorities have been consumed;
   and
6. keep direct/empirical rows separate.  A cryptographic selection must never
   close a candidate filter.

The current `SELECTED_SOURCE_ASSUMPTIONS = {}` correctly fails closed, but its
future dictionary value would only be a digest
(`privacy_capture_model.py:61-68,555-603`).  The successor must require a
move-only selection authority; a digest in source or JSON is not evidence that
the actual run met freshness, key-absence, setup, or launch conditions.

## Explicitly lower-priority work

- More proof-verification tests do not close `S4` or `S12`; verification is a
  direct validity fact, not zero-knowledge or toxic-waste evidence.
- More statistical “random values differ” tests do not close `S1`, `S2`, `S5`,
  or `S7`; they cannot authenticate the source, prove entropy, or rule out
  observer disclosure.
- A generic source manifest alone does not close these rows.  It must bind the
  actual launch and be consumed with the private residual from that run.
- Changing the observer family counts now would destroy the frozen experiment.
  Version the successor only after the closure schema and exact evidence
  dependencies are reviewed.

## Stop conditions

No prioritized row may become closed if any of the following is true:

- a production caller can supply `rho`, a blind, ephemeral secret, or key index;
- a failed attempt can resume or reuse private material;
- a secret, secret hash, key/index, or directory identifier reaches the admitted
  view outside its explicitly corrupt/C1 facts;
- the generic proof row is used to hide the distinction between Output and
  aggregate setup/randomizers;
- the bounded setup is described as a ceremony, erasure proof, or production
  trust minimization;
- a flat digest is accepted without the live one-shot applicability authority;
  or
- any direct or empirical candidate filter is relabeled as an assumption.

Under the current source, all of these families remain open.  This note changes
neither `SELECTED_SOURCE_ASSUMPTIONS` nor the observer/model/ABI.

## Priority 1 implementation boundary reached

The source now contains a connected, fail-closed authority seam from V3 invoice
issuance to terminal-v2 admission:

- `honest_owner_material_authority.{hpp,cpp}` keeps the exact `RunBinding`,
  accepted-history identity, round, owner, output slot, invoice index,
  Invoice208, NF, and full Output520 row private and move-only;
- `v3_native_authority.{hpp,cpp}` preserves private binding, history,
  per-open parent-instance, and source-generation identities through
  material, allocation, export, acceptance, consumption, or poisoning;
- the source-generation identity commits to round/owner/slot/index/invoice, so
  substitutions cannot reuse an accepted invoice; and
- `native_terminal_completion.{hpp,cpp}` independently parses each retained
  projection's three NFs and six complete Output520 rows, exact-matches both
  round multisets and the full `RunBinding`, then retains the opaque residual
  inside `TerminalV2ModelAdmissionAuthority`.

Adversarial compiled controls cover cross-parent material, wrong
round/owner/slot, replay, moved-from use, substituted parent, wrong NF, wrong
output row, wrong projection, wrong `RunBinding`, complete-friend redefinition,
and removal of the old no-argument terminal factory.  A correct-parent source
mismatch durably poisons the accepted lane.  A substituted live parent burns
the one-shot capability and leaves the original lane nonterminal `Accepted`:
this is a safe halt, not a claimed durable `Poisoned` edge.

This is still a typed production boundary, not honest-production evidence.
There is no production minter for `HonestInvoiceSourceAuthority` or
`HonestOwnerOutputAuthority`, no selected owner worker/callsite, and no executed
financial run through this seam.  Test injection is macro-gated and implemented
in separate fixture source.  All assumption selections and configuration flags
remain false.
