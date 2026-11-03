# Next experiment: two-owner aggregate with real note validity

**2026-10-26 — proposed offline experiment contract; no execution or architecture
selection.** Test whether the hidden-bijection aggregate can enforce the existing
native note, proof, value and state rules. Use owner-local **current Spend200
proofs**, privately verified under fixed selected role keys, rather than give
the constructor an owner's current spending secrets. This is the established
owner-local NIZK branch in [the source memo](COLLABORATIVE-INTENT-PROVING-SOURCE-01.md),
not a selected replacement for the signature-authority branch.

The completed 49 authority and 29 aggregate checks established bounded signature
and permutation mechanics. They did not establish actual Note168/CV/proof/state
validity. This experiment targets that precise gap. It does not repeat those
checks, claim mapping privacy, or authorize keys, setup, implementation, native
profile changes, proving jobs or broadcasts under this document.

## Why the two relations cannot simply be joined

| Completed aggregate | Current native local-payment predicate |
| --- | --- |
| `AuthorityPredicate` uses a signature PK plus separate NK; Poseidon CM/NF; depth-one synthetic anchor; u64 values. | Spend requires `owner_secret=s`, separate `k`, SHA256 Note168/owner/key commitments, positioned HMAC-SHA256 NF, depth16 membership, bounded Note168 value and a canonical Baby-Jubjub CV opening. |
| Four whole 520-byte tuples are authorized and privately permuted. CV, CF/proof validity and accepted state are absent. | Output168 proves note commitment, value range and CV opening; the public verifier checks CFhash, role proofs, CV balance and state transitions. |
| 2,091 public debug fields; public owner-coded fixture; plaintext constructor knows the full map. | Selected codec/profile/native policy requires **1 NF / 2 outputs**, a complete effects projection and actual current reserve consumption. |

The synthetic fixture's CM/NF values must never be asserted equal to Native
CM/NF merely because their field names match. Reuse the **Boolean U/V bijection
pattern**, not its Poseidon note identity or its depth-one tree. Native hashes
are 32 ranged bytes, not a 256-bit integer reduced into BN254 Fr. Preserve each
whole tuple under its single permutation row.

**Current `owner_secret` is spending authority.** It stays inside the owner's
local Spend prover, together with `k`, note opening, membership path and blind.
The aggregate receives the resulting proof and statement, not that witness.
Neither secret is renamed a viewing/proving key or transferred to an MPC server.
Existing Exit authority and the wallet KDF stay unchanged. A separately derived
signing-PK/NK note would require a new reviewed profile across Spend **and Exit**;
the 49/29 fixture is not that migration.

## Exact current authorization, including its limit

Spend200 contains `D | old_CM_root | NF | CVin | effects_digest`, with its role
tag. `statements.rs:33–40` serializes all of it; `circuit.rs:170–171` hashes every
statement byte inside the relation into **two 128-bit limbs**. The public
evaluator independently reconstructs the effects digest before verifying Spend
(`common/src/lib.rs:222–253`). Current `wire.py:240–248` hashes the canonical
193-byte native prefix and 3,756-byte body core, including fee, current outpoint,
roots/counts, Delta, NF/CVin, **both complete output tuples and output proofs**,
NF insertion and CM append witnesses. Only final Spend proof bytes are excluded.

Thus a current Spend proof is authorization for those **exact complete effects**,
not merely proof that somebody owns a note. Altering a recipient/change tuple,
CFhash, fee, outpoint or public order requires a different effects digest and
fresh owner-local Spend authorization. Output168 alone supplies no spend
authorization. The owner's local checks remain necessary: `payment.py:114–159`
checks the authenticated invoice, recoverable own change, exact tuples once,
integer conservation, current note, paths and Delta before `authorize:163–176`.
There is no circuit statement that separately identifies a recipient/change pair
or individual fee allocation. The owner authorizes the whole transaction after
checking that its own intent is satisfied.

**First falsifying control:** after both owners authorize the candidate exact
batch, substitute one payment tuple with a genuinely valid coordinator-owned
output, regenerate that Output proof and recompute all public state/effects,
while retaining the original Spend proofs. Acceptance is a failure. A valid
Output proof and globally balanced batch never substitute for owner consent.

## Proposed relation and fixed boundary

1. **Owner-local inputs.** Two fresh, unfunded, explicitly public synthetic
   owners each hold one actual Note168 and create two actual Receipt216/CF264
   outputs with the existing recipient/crypto adapter. Each independently checks
   its authenticated invoice, own change, exact two tuples once, allocated fee
   and integer conservation, then proves its Spend200 against the **same complete
   candidate effects digest**. Keep all current consumption secrets local.
   Stop owner processes after these exact proofs exist; no new consent is
   implied for changed public effects. Current `payment.py` is fixed 1/2: a new
   reference-only two-owner consent adapter must preserve its checks; reusing it
   unchanged for 2/4 is not valid. Do not reuse the Poseidon HANDOFF as Native
   note material or repack previously authorized 1/2 Spend proofs as 2/4 consent.
2. **Public statement.** A separate **research-only 2/4 effects frame** contains
   two independently ordered `(NF32,CVin64)` rows, four complete Output520 tuples,
   old/new State112, the selected reserve outpoint, old/new reserve, explicit
   aggregate fee, zero payout, one canonical aggregate Delta, sequential two-NF
   insertion witnesses and four empty-slot CM append paths. Include the exact
   selected context/policy commitment and native-prefix analogue in the effects
   transcript. There is no invented `laneId` field: cross-lane tests use the
   actual D/state/outpoint/policy boundaries. No owner/pair ID, individual Delta,
   per-owner fee/role, signature slot or upload handle is public.
3. **Private aggregate inputs.** The two owner-local Spend200 statements/proofs,
   their private correspondence to the public NF/CVin rows, and any private
   output correspondence use the U/V Boolean row-and-column bijections. Verify
   **two Spend and four Output proofs under constant selected VKs**, rebuilding
   each exact statement and its SHA256/two-limb public inputs in the outer
   relation. Output proofs remain in their whole public tuples. No unconstrained
   `proof_valid`, host verdict, caller-selected VK or private replacement key is
   accepted. The whole exact batch authorized by each Spend is authoritative;
   U/V labels alone do not prove a per-owner output allocation.
4. **Complete financial relation.** Enforce nonzero/distinct NFs and nonempty,
   distinct CMs; canonical subgroup/nonidentity CV and proof encodings; strict
   scalar Delta; exact Note168 ranges inherited through the verified fixed-key
   components; sequential indexed-NF predecessor/empty-append updates; sequential
   empty CM appends; exact counts/capacities; and
   `sum(CVin)-sum(CVout)-fee*V == Delta*R`. Retain integer sompi and current fee
   and reserve bounds, `new_reserve+fee=old_reserve`, zero public payout and exact
   continuing reserve effects. Explicitly adapt the antiwrap argument from the
   current 1/2 profile's `4*MAX<q`: conservatively **7*MAX<q** for two inputs,
   four outputs and one fee. Do not infer conservation from field equality,
   valid signatures, unchecked CVs or a constructor's claimed values.
5. **Supplied current-state acceptance.** An independent deterministic reference
   acceptor starts from one frozen synthetic occupied CM/NF history and reserve
   head, verifies the relation and exact old head, then atomically advances it.
   Repeat acceptance and competing successors cannot consume that head again.
   A supplied reorg history rolls back acceptance before reconciliation. This
   tests an explicit supplied-state model, not authentic Kaspa ordering or
   consensus. An isolated relation over identical old public inputs can accept
   the same statement twice; a constraint system is not a replay database.

The experimental frame needs its own unambiguous test-only encoding and tag,
frozen byte offsets, lengths and effects/journal reconstruction before source
GO. **Do not edit or reinterpret the current 1/2 codec/profile/guest/native
policy.** Current `Profile::parse` fixes 1/2; native policy authenticates the real
current consumed reserve and selected receipt. A proposed 2/4 reference frame
must be rejected by those unchanged entry points. No new native image, keys,
policy tail, reserve, accepted state or release ABI is selected here.

The source memo's fixed-VK BN254 recursive-verification example supplies an
established candidate, not a completed adapter. Before implementation selection,
pin its actual checked point/scalar/VK conversion, subgroup options and exact
Arkworks proof encoding against these existing verifiers. Do not assume its
generic example's witness VK is a financial identity. Keep the independent
standard Arkworks and current accelerated verifiers as differential references.

## Frozen adversarial decisions for the source implementation

Before any run, expand the following **mandatory vectors** into one finite
recipe with exact public fixture bytes, unchanged expected verdicts and one
attempt identity. Publish the synthetic mapping as truth and label the ordinary
constructor **NONPRIVATE**. These are financial relation tests, not an anonymity
experiment. A source author must not omit a vector because witness generation
asserts; actual negative R1CS checking needs an explicit selected harness.

| Vector | Required result and decisive boundary |
| --- | --- |
| Honest two-owner batch; independent private record permutations | Relation ACCEPT; exact same public effects/inner proofs survive private record reorder after owners stop. Public effect reorder is **not** authorized by this control. |
| Redirect control above; change exact fee after consent | Relation REJECT with unchanged Spend proofs, even if substitute Output proofs, state and global CV balance are otherwise genuine. |
| Inflation by one sompi | With newly generated genuine per-note proofs for the fixture's inconsistent totals, group conservation REJECTS; do not count stale-proof rejection as the balance test. |
| Mismatched CVin; mismatched Output CM/CV | Inner verification REJECTS under the exact reconstructed statements. |
| Same input used twice; duplicate output tuple/CM | Distinctness/bijection REJECTS even when copied component proofs separately verify. |
| Wrong membership anchor; wrong positioned NF | Inner proof verification REJECTS; high position bits may not alias a valid leaf. |
| NF already in supplied accepted state | State insertion REJECTS even if the ownership proof is genuine. |
| Overwrite an occupied CM slot; falsify counts or a successor root | Sequential state constraints REJECT; no caller-supplied acceptance bit. |
| Cross-D, other reserve outpoint/policy tail, stale root/head | Exact statement/context checks or current-head reference acceptance REJECT at the recorded boundary. No blanket claim of a lane field absent from the source. |
| Reserve/native-prefix amounts differ from approved fee/effects | Relation REJECTS; public reserve accounting and private CV fee refer to the same integer. |
| Below note floor, above MAX, Delta=q, noncanonical/subgroup/identity CV/proof, wrong-role/wrong VK | Range/encoding/fixed-key checks REJECT. Record parser rejection separately from actual R1CS rejection; neither is the other. Include exact floor/MAX and Delta=0 positive controls where valid. |
| CF changed, old CFhash; matching new CFhash but old Output proof | REJECT at tuple hash or exact Output-statement verification respectively. |
| Same-state replay; two valid competitors; supplied reorg | Pure unchanged relation replay ACCEPTS. Stateful acceptor accepts at most one successor; repeat/stale competitor rejects. Reconciliation against supplied reorg history preserves an unspent losing claim or identifies the accepted spent NF. |
| Candidate 2/4 through unchanged 1/2 profile/parser | REJECT. This is evidence of the Native compatibility boundary, never an invitation to weaken arity checks. |
| Valid proof over wrong/unrecoverable ciphertext, described below | Financial relation may ACCEPT; receiver rejects; complete payment/delivery qualification is **FAIL/OPEN**, not a changed expected cryptographic rejection. |

The full compiled outer relation and exact assignment must actually be checked
for each semantic R1CS negative. A generator assertion, public-proof validity
oracle or decoder failure does not count as a mandatory outer constraint check.
Malformed byte-parser vectors have their own named verdict. If the selected
recursive backend cannot check an intentionally inconsistent full assignment,
retain that evidence requirement as UNEXECUTED; do not borrow the completed
Circom CPP0 result as validation of a different circuit/backend. Preserve the
first unexpected result and propose any correction prospectively.

## Encryption and privacy gates that this cannot silently retire

**Current Output168 does not prove encryption correctness.** Its private witness
is Note168 plus the CV blind; `circuit.rs:182` explicitly binds CFhash without
checking sealed-box plaintext. `common/src/wire.rs:119–145` checks SHA256(CF),
and `recipient.py:231–241` actually decrypts and validates the derived descriptor.
Freeze a gap control with a valid note/CM/CV, unrelated or wrongly addressed
CF264, matching CFhash and a genuinely regenerated Output proof. If owners
deliberately authorize those complete effects, the present financial predicate
can accept. That is not inflation or coordinator redirection after consent; it
is a sender burning or misdelivering an output. The receiver must refuse to
recognize a valid spendable claim. Honest recipient and change controls must
actually decrypt and validate the recovered Note168 descriptor/CM, validate the
published CV through its selected Output168 proof, and form genuine current
Spend/Exit proofs from that descriptor under the existing synthetic source.
Receipt216 does not carry the sender's CV blinding: a subsequent Spend chooses a
fresh local input blind, while Exit needs none.

Therefore **strict circuit-enforced ciphertext/recipient spendability remains
UNBUILT**. A proposal demanding that poison vector reject *inside* the current
financial relation cannot receive GO without a separate established
encryption/recipient-consent relation and profile decision. Do not disguise an
external receiver check as a cryptographic constraint or a completed recovery
availability result. Preserve I-14's deterministic wallet rejection boundary.

Even six genuine inner proofs do not supply a private malicious-secure outer
prover. Full extended-witness validation **before revealing outputs**,
authenticated identical input/handoff, fresh shared proving randomness and an
opening-by-opening security argument remain required. Current semi-honest
co-SNARKs and the existing MASCOT admission program do not establish them.
Owner-local proofs reduce exposure of current consuming secrets; the ordinary
aggregate constructor still sees any mapping submitted to it. No privacy GO,
MPC implementation, active retry claim, durable offline intent, current-native
2/4 acceptance, recovery availability or cheaper-fee claim follows.

## GO conditions and the decision this would support

**GO only for an offline implementation/run proposal**, after independent source
review selects and pins: the no-new-inner-setup fixed-VK verifier adapter; its
byte/limb/subgroup equivalence controls; the test-only 2/4 codec/effects and
owner-consent adapter; full state/CV/antiwrap constraints; synthetic-only fixture
recipe; exact constraint checker and negative-witness method. No actual wallet
material, private history, Original, runtime profile or funded trial is an input.
Existing public selected PK/VK/manifest provenance must suffice; missing assets
are a blocker, not authorization to generate replacement keys or setup.

Success would retire **“the aggregate has no actual note/value/state validity”**
for the explicitly tested reference relation and demonstrate exact-effects
owner-local authority without exporting current spending secrets. It would
justify considering a later private-prover experiment. It would not select a
signature-based note profile or prove encryption, malicious MPC, Native 2/4
execution, financial privacy, permissionless recovery or the 2% fee target.

Open RFC questions, preserved here while the current RFC/docs are frozen:

1. For a future profile, retain current owner-local exact-effects NIZKs, or
   adopt a separately reviewed signing-PK/NK note and synchronized Spend/Exit
   predicates? RAILGUN and Orchard inform this choice; they do not make current
   `owner_secret` safe to share. No route is selected by this experiment.
2. Is recipient-side deterministic rejection the intended encrypted-output
   guarantee, or must accepted output validity enforce recipient spendability?
   The stronger requirement needs an explicit established relation and consent
   design; current Output168 does not provide it.
3. Which complete malicious private-prover construction and real current-state
   acceptance boundary can compose with this relation without exposing owner
   mapping or weakening independent exits? Exact-effects consent deliberately
   provides no reusable authorization after a shared-head change.

## Pinned source ledger

Local sources were read through unchanged helper09 in
`/home/luke/projects/kpi-intensive-2026-10-22/continuation`, branch
`research/shielded-kas-feasibility`, HEAD
`62dea77f44da44820971ded88d674f0243df8913`. Native files below are clean tracked
sources at that commit; aggregate research files are uncommitted and identified
by bytes. Paths below the native root are relative to `poc/local-private-payment/`.

| Source | SHA256 |
| --- | --- |
| `relation/src/circuit.rs` — Spend129–172 / Output174–184 / Exit186–234 | `e13fa9bd6ba33bd01b71e824d10944b3d8561854b3c026f997b282cf57fde4b0` |
| `relation/src/statements.rs` — Spend15–65 / Output68–112 / Exit118–177 | `bcd3f5f947904fe6fecc4e747b93e0f85a5c611390d0331651e3a1884004e123` |
| `relation/src/lib.rs` — actual Note168 / owner / key / NF | `f93c2593444acd3936595e4e0d07cc680ff8ada05ce9f9c7dd5a47a387245b9e` |
| `relation/src/cv.rs` — exact codecs41–78 / balance160–177 | `350153426d8ff86905a7956a76311726812151bbe301b319ee254336b33c2f05` |
| `verification/common/src/lib.rs` — fixed profile111–152 / evaluate222–259 | `949452a43d9db837067a818e09f9660bf5f6ff9a3adac82094120e532aca6d5d` |
| `verification/common/src/g16.rs` — checked key contract56 / proof66–95 | `c6ce48be94c702858b6a9a7093ae835cf4d2afd7808e56eb2a9a762c1d21b36a` |
| `verification/common/src/wire.rs` — tuple119–145 / effects206–207 / state229–280 | `136f7b1115a64d08e9789114be04d0fa3de90b05da5aa2216bd686effc7b6562` |
| `verification/wire.py` — independent tuple184–195 / effects240–248 / state261–277 | `6727e00a143596dbd31abf06c7fd5a2ceafa07082d6e3e6de47fa389a826def8` |
| `verification/native/src/policy.rs` — actual consumed effects273–310 / Exit474–584 | `63c56238bac40a8f58b1d2e2442ee7dcc259447515995922c99bb2e502181e7f` |
| `verification/component-profile.json` — public role keys, not campaign PROFILE | `9fd9651dfd96faa864705e67b9bbcf7b76503963c99d14605243859699b24018` |
| `wallet/payment.py` — outputs32–46 / consent114–159 / authorization163–176 | `5ff0774fd1bb67ebc5ed5ec246ce2434082bfc4ce82dad9e58047b34232d2bda` |
| `poc/future-recipient/v2/recipient.py` — KDF202–221 / receive231–249 | `93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2` |
| `poc/future-recipient/bridge/src/main.rs` — existing seal/unseal39–49 | `5fe1f3b9d678086dc7b4a7681642b90841395135b0135a4f07f876f740ee5829` |
| Completed authority source, exact extracted template prefix | `2626b1c4d1b0808edb54b1dace7a3fc90369c85ed61f21a4eff9ec933f2645bf` |
| Completed aggregate `two-owner-aggregate-01/circuits/aggregate.circom` | `9aa40068bcf4098125d8735c95e767b8c444138e2dd933000b444482386b069c` |
| Collaborative source memo / prior integration proposal | `5f8ccd7e1834be152dfba9ee88a78c73748026201946cd8d92fff98bddea9959` / `fe12e53433ddede7a4c8468878bf62a32b7d8a1a2e20dbad7df78defc780ea91` |

The original full authority source is
`e5b158ec4cc88afa8be35ca8758140bb9c1e7899c31d83572ed20f30b824b68b`;
the extracted template excludes only its original main suffix. Fixed public
Spend VK is `b02bbf6a31a57c6132ae1ecaa680e1e955946fc1076fbe4f7e58142407b57203`,
manifest `4d28ba947357debb486e623c82ef03e778d3b986be9891696eca022926a08464`;
Output VK is `2839d491047edd5664db65af3fa92a7194d959e7f94f723eac982aa918c785e6`,
manifest `c400914d0b68c8f7846c198fd462210b35212f3e893f1f7801c457ad0069d729`.
These are existing public identities, not newly selected parameters.

Mature-source comparisons remain the exact inspected source patterns from the
memo: [RAILGUN JoinSplit](https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/joinsplit.circom#L15-L97)
binds separate signature PK and NK; [Orchard keys](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs#L152-L215)
and [FVK](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs#L386-L400)
separate `ask` from `(ak,nk,rivk)`, with [ZIP374 roles](https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/zips/zip-0374.md#L1129-L1193).
Neither source is imported as a durable KPI intent or a current Native key
contract. The [gnark recursion example](https://github.com/Consensys/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/nonnative_doc_test.go#L76-L157)
and [verifier](https://github.com/Consensys/gnark/blob/0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46/std/recursion/groth16/verifier.go#L527-L624)
are candidates needing the adapter gate above. No new current-upstream or
whole-repository audit claim is made from those pinned selected-path reviews.
