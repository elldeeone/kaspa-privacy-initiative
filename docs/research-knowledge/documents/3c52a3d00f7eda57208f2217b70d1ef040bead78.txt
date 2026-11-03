# RFC-0030: Restricted owner intents and private batch construction

Date: 2026-10-28 UTC.

Status: Open research profile and integration contract. [ADR-0074](../adr/0074-private-batch-construction.md)
selects the bounded protocol experiment and its interfaces. This is not a
production architecture, completed private prover or funding-readiness claim.
All [I-1–I-16](../../SECURITY-INVARIANTS.md) remain unchanged. Native test KAS
is the only asset; there is no new token or privileged withdrawal route.

## Problem and retained evidence

The completed RFC-0029 rehearsal has native deposits, payments, nine independent
payouts, zero terminal reserve and original-wallet scans. Its public 1-NF/2-output
groups and ordinary constructor still expose payment structure. The measured
12.5793% complete fee rate remains a failure of the fixed 2% target.

The new authority component separates a wallet-local signing secret from a
prover's witness. Its complete 4077-byte packet/signature contract is one-owner
research source. Extending that contract by showing every owner the final
multi-owner packet would reveal the other raw nullifiers before finalization.
Providing an opaque server-selected hash instead would remove informed consent.

The [October 28 source refresh](../../research/next-session/local-private-payment/privacy-next/PRIVATE-BATCH-SOURCE-REFRESH-2026-10-28.md)
inspected current Kaspa/Toccata, vProgs, Kaspa research, Orchard, Aztec, RAILGUN,
Monero and MWEB sources. Orchard and RAILGUN explicitly bind authorized effects;
their signature primitives do not provide private multi-owner consent by
themselves. The existing [asynchronous design](../../research/next-session/local-private-payment/privacy-next/ASYNC-HIDDEN-PARTITION-DESIGN-01.md)
and [MPC implementation plan](../../research/next-session/local-private-payment/source-checkpoint-2026-10-27/groth16-integration/INTEGRATION-IMPLEMENTATION-PLAN-03.md)
are the source baseline, not implementations of the obligations below.

## Observer and first bounded workload

The first candidate has three independent owner inputs and six complete outputs,
with two honest spenders and one declared colluding wallet. Three MASCOT servers
are separately administered in the model; the studied active view combines the
dispatcher, one corrupt server and that wallet. Known cohort/session membership,
all pre-acceptance egress, rejected/orphaned transactions and reorg history count
as observations. An extra honest server or a large batch is not evidence of
honest spending demand. The deployment and administration remain unqualified.

All-server collusion is a separate confidentiality failure. It must still not
enable spending beyond the owner's exact cryptographic intent. Signature
unforgeability and a complete sound relation are assumptions to qualify, not
results of the host codec or the disclosure model.

The initial experiment uses one exact authenticated reserve head/anchor. It
does not silently permit historical anchors or head refresh while owners are
offline. A competing payment, Exit or reorg can require refusal. A durable
historical-anchor design is a later explicit relation change.

## New owner-intent contract

Use a fresh profile/domain and matching Output, Intent/Aggregate and AuthExit
identities. Old notes, keys, verification keys, proofs and backups are not
reinterpreted or migrated. The profile pins a specific service-policy epoch;
this is service affinity for private progress, not committee withdrawal power.

The owner derives its authorization secret and nullifying material separately
from its original seed through the selected, separately tested wallet profile.
The signing seed, expanded scalar and nonce stay wallet-local. Reuse the
authority component's canonical Babyjub key representation and note owner:

```text
AK64 = Ax32LE || Ay32LE, with canonical coordinates in BN254 Fr
Note.owner = SHA256("KPBPOW01" || D32 || AK64 || Note.incoming32)
```

Actual on-curve/subgroup/nonidentity and signature scalar checks remain mandatory.
The profile manifest must bind D, the service policy and every proof identity;
changing an unbound JSON label is insufficient. Every consumption route,
including direct Exit, must check the new authorization rule.

The [canonical codec](../../poc/local-private-payment/private_batch/intent.py)
has exactly 1460 bytes, in this order:

| Field | Bytes / interpretation |
| --- | --- |
| version tag | `KPBINT01`, 8 bytes |
| context | chain genesis32, authenticated pool lineage32, profile ID32, D32, service policy32 |
| exact head | reserve outpoint36, old CM root32, old NF root32, CM count u32LE, NF count u32LE, old reserve u64LE |
| own input | nonzero NF32 and canonical CVin64 |
| own authorization | exact fee u64LE, intent nonce32 |
| own outputs | exactly two complete, ordered Output520 tuples |

The codec checks sizes, integer canonicality and simple uniqueness only. It
does not validate a note, signature, point, ciphertext, state or financial proof.
The wallet authenticates the invoice, constructs and validates recipient and
recoverable-change tuples, and approves its exact fee and outputs.

Authorization uses SHA256 of the exact encoded intent, split into LE first16
and LE last16 limbs, then the existing stock width-three Poseidon with two
inputs before the established EdDSA/Poseidon signature. This is not the newer
Poseidon2 algorithm. The actual signature relation must recompute both hashes
from constrained fields. A caller digest or host `valid` flag is never evidence.

An owner authorizes permutation of its two whole tuples into the final batch,
with no alteration, omission, duplicate or reassignment. It authorizes no other
owner's tuple or fee. This replaces whole-global-packet consent only under the
new relation below; it does not weaken or repack the existing Spend200 relation.

## Full aggregate relation and public interface

For each of the three hidden owner records, prove legitimate note ownership,
membership in the exact authorized CM root, the correct original NF, signature
validity, complete output validity and bounded integer conservation:

```text
v_input_i = v_payment_i + v_change_i + fee_i
```

Retain note floors/ranges and canonical commitment/scalar rules. Sum three u64
fees in an explicitly **66-bit** intermediate, then reject a total exceeding
u64. A 65-bit intermediate from the earlier two-owner experiment is insufficient.

Constrain Boolean bijections from the three hidden inputs into three public
`(NF32,CVin64)` rows and from all six authorized whole Output520 tuples into six
independently ordered public tuples. Every input/output occurs exactly once.
NFs and output commitments are distinct. The mandatory accepted-proof composition
below enforces current unspentness, complete NF/CM updates, reserve backing and
the actual native transaction:

```text
native payout = 0
actual native fee = sum(fee_i)
new reserve + actual native fee = old reserve
```

Only aggregate Delta is public. The relation checks the corresponding aggregate
CV equation and each owner's integer balance; a balanced aggregate alone cannot
authorize one owner to subsidize another. There is no arbitrary tip/refund or
fee redistribution. State paths and actual effects must be proved, not asserted
by the constructor.

The selected witness partition keeps each owner's actual CV relation in that
owner-local component:
`CVin_i - CVpay_i - CVchange_i - fee_i*G = delta_i*H`.
Each `delta_i` is a canonical scalar below the existing Edwards subgroup order
Q and stays private. The joint relation requires canonical public `Delta < Q`
and `sum(delta_i) = Delta + k*Q`, with `k` constrained to `{0,1,2}`. For the
existing curve, Q is
`2736030358979909402780800718157159386076813972158567259200215660948447373041`
and the circuit field P is
`21888242871839275222246405745257275088548364400416034343698204186575808495617`.
Because each private scalar is below Q, its three-term sum is below `3Q < P`;
the constrained quotient and ranges make this an exact integer equality rather
than accidental reduction modulo P. This reuses the existing
[CV scalar/group semantics](../../poc/local-private-payment/relation/src/cv.rs).
The owner-local curve constraints, whole-tuple/input correspondence and public
proved CV check remain mandatory. Removing joint curve auxiliaries does not
remove those predicates or permit opening individual deltas. Wrong Delta,
`k=3`, Q aliases and missing range constraints are required rejection controls.

The accepted native packet exposes three independently ordered NF/CV rows, six
complete tuples, current state/update data, total fee/Delta, the aggregate proof
and the mandatory proved public wrapper. It must recompute the SHA256 digest of the canonical actual effect core,
excluding only the final proof to avoid self-reference. Two 128-bit digest limbs
may form the Groth16 public prefix. This digest must be computed authentically
inside MPC before opening it; no raw NF or owner-labelled slot enters a clear
prover prefix. Whether even the allowed aggregate digest or transcript leaks
under auxiliary knowledge remains part of the observer experiment.

No owner ID, intent nonce/hash, pair tag, individual fee allocation, individual
Delta, upload handle or owner-to-wire map is published. Backend debug output is
inside the same view audit. Output ciphertexts and proofs stay bound byte for
byte to their owner's authorization.

The selected research effect core has tag `KPBAEF01` and 10,364 bytes: common
intent context276 (the five context IDs and exact old head, without `KPBINT01`),
new CM/NF roots64, new counts8, new reserve8, total fee8, aggregate Delta32,
three NF/CV rows288, six Output520 tuples3120, three NF-insertion witnesses3480
and six CM-append paths3072. All integers retain explicit little-endian widths.
The native acceptor must additionally compare the actual consumed reserve
input, successor policy/output and paid fee with those selected effects.

### Selected proof composition for the actual financial experiment

Reuse the existing mandatory proved RISC Zero public wrapper for public state
updates instead of implementing the whole public tree algorithm in private MPC.
This is a proof-composition choice, not permission to move validation to an
ordinary host Boolean. Existing source anchors are
[payment policy](../../poc/local-private-payment/verification/native/src/policy.rs)
and [guest common evaluator](../../poc/local-private-payment/verification/common/src/lib.rs).
Those source paths are reuse points; their current code does not already accept
this new profile or codec.

| Layer | Mandatory obligations |
| --- | --- |
| New private aggregate relation | Correct input ownership/membership/NF, hidden intent signatures and whole-tuple bijections, input/output note commitment and CV bindings, per-owner integer conservation, canonical aggregate Delta/CV balance, distinct resources, and SHA binding of every byte of the 10,364-byte public effect core. |
| New mandatory proved R0 public guest | Independently reconstruct the exact effect digest; verify the new aggregate Groth16 proof under its pinned VK and all six genuine Output proofs; validate the exact current CM/NF state transitions, indexed nonmembership/insertion and append paths, counts/capacities, public CV balance and policy/profile/domain. Produce the exact selected journal/projection. |
| Native covenant policy | Verify the selected R0 receipt/image and bind its journal/projection to the actual consumed reserve outpoint, old/new state, allowed successor policy/output, fee and reserve amount. No host assertion substitutes for this receipt. |

The aggregate binds all public state/path bytes while the proved guest validates
their public transition semantics. Every omitted private-CS predicate must appear
in this mandatory proved composition. Neither a standalone aggregate proof nor
a Python/Rust payload validator is native acceptance. This choice needs matching
new guest/image, proof/profile/setup identities and real terminal rehearsal.
It claims no fee saving; the unchanged full-lifecycle fee measurement remains
required. A future direct-native public-tree proof is an unimplemented alternative.

## Private witness and release ordering

The implementation must preserve the established masked external-owner input
protocol, authenticated channels and selected job/model bindings. No owner
witness enters a clear dealer file, `Input-P0`, ordinary combined WTNS or a
public client-to-register map. The backend must support private routing and
cross-owner witness extension. A scalar gate or concatenated component WTNS
files do not supply that operation.

The accepted bounded design is [ADR-0077](../adr/0077-durable-private-attempt-history.md).
It replaces persistent secret-share history with a stronger global exclusion
barrier and permanent already-public NF tombstones. Its stricter refusals remain
within the descriptor's existing minimum policy; D/ProfileID and owner consent
are unchanged. Actual implementation and financial integration need qualification.

Required order:

1. All three servers durably lock one exact attempt and checkpoint before any
   owner intake. A partial lock, failure or unknown exposure never unlocks it.
2. Admit owner-local inputs and construct the complete immutable assignment.
   Privately compare the actual derived NF256 values against every permanent
   public tombstone. Join those checks with every relation row, trace assertion
   and prefix check in the same-assignment validation. Refusal reveals only the
   selected aggregate validity result and leaves the lock unresolved.
3. Under that lock, open only the allowed aggregate effects digest. All three
   durably prepare it before minting the one-use same-context proof capability
   and before reactive masked A/B1 openings. Masked MASCOT traffic and the checked
   field-coin protocol retain their separately reviewed semantics.
4. Generate and independently verify the genuine aggregate proof with every
   mandatory field/group MAC check. Open the core to servers under the lock,
   then persist its actual NF set, effects/proof/projection hashes and exact
   binding before coordinator/R0 handoff. That initial core opening already
   counts as disclosure. Auxiliary B1 stays outside coordinator output; its
   colluding-server view remains part of privacy qualification.
5. Produce the genuine R0 receipt and validate the complete native candidate.
   All three durably pin that exact whole CASE before submission. Its hash is
   distinct from the earlier egress hash; the R0 witness did not exist earlier.
6. Resolve only after fresh independently acquired/replayed accepted history
   proves that exact candidate. Retain all released NFs forever, even after
   reorg. Only then may a new disjoint attempt start. Offline Full success,
   caller booleans and transaction IDs alone cannot authorize resolution.

The conservative design can permanently halt private progress. Independent
Exit remains available. Until the actual new-profile settlement adapter exists,
the financial implementation has no successful resolve path.

[ADR-0078](../adr/0078-public-continuation-after-private-egress.md) closes the
process-lifetime seam after durable EGRESS. Later R0/native candidate validation
uses a fresh public-only context and a private capability minted by direct
qualified verification of that exact EGRESS/whole CASE. It restores no private
shares and cannot settle or unlock. Actual fresh accepted-chain verification
remains the separate authority for SETTLED and a subsequent private round.

[ADR-0079](../adr/0079-registered-head-program-selection.md) defines the matching
registered private entry: actual accepted-head authority plus direct pinned
public exporter execution yields an immutable program selection. Public history
may change operations/assertions, so the gate checks actual selected counts and
exact row/key reuse. Arbitrary caller program hashes and qualification-store
labels cannot select a funded head.

The [release-policy implementation](../../poc/local-private-payment/private_batch/release_policy.py)
is a runnable SQLite durability/information-flow model using clear synthetic
member tokens and opaque proof bytes. It implements no private input path,
signature/proof verifier, native acceptance or production journal. Its tests
do not qualify a real MPC boundary.

## Changed cohorts, service loss and explicit privacy failure

The original ABC egress followed by C's independent Exit and an ADE retry remains
a counterexample: public NF intersections can identify A. Delayed publication,
fair output, a fixed server roster and a valid SNARK do not remove it.

Within one history-bound research service, the candidate refuses any new cohort
or changed effect set overlapping a previously prepared/disclosed NF set. A
fresh job nonce, reconnect, rollback, different setup or a new client label does
not reset this policy. Identical-cohort/effects re-proving needs a fresh execution
identity and randomness; it does not authorize rebroadcasting a used trial.

When C exits, A/B's old exact batch cannot settle; the candidate may permanently
halt their private progress. Their individual direct Exits must remain usable.
This is a privacy/liveness tradeoff, not a fully usable asynchronous mixing
solution or a successful mitigation under unrestricted O-active.

Every service participant must retain non-rollback disclosure history and the
selected policy epoch, independent of chain reorgs. An external authenticated
latest checkpoint is required when reopening the model journal. Missing history,
a mismatch or unavailable latest checkpoint refuses private progress. An
accepted chain/seed alone cannot reconstruct an unaccepted disclosure journal.
Rolling back both the journal and its trusted external checkpoint is not detected
by this model. Neither a local hash chain nor a database proves global currentness.

The honest-service/history assumption cannot be enforced merely by a final
financial proof or a TLS label. Old intent/profile restrictions and honest
release-party enforcement are necessary; another service or restored wallet
that bypasses that history restores the original privacy failure. Cross-service,
operator rollback and accepted-history-only private-retry recovery remain
**privacy unqualified/failing controls**. They must never be relabelled as funds
locks, an admin override or a reason to weaken independent Exit.

## Recovery, direct Exit and readiness

New outputs must use authenticated recipient descriptors and the selected
seed-derived receiving/encryption format. Original-seed scanning must recover
received and change notes from complete authenticated public data without the
private partition, service journal, another wallet or MPC shares.

AuthExit must prove the same new AK-bound note ownership and signature rule,
correct NF and current state, bounded exact payout/fee and actual native
destination. Every reserve decrease remains backed and authorized. No committee
history/signature or batch peer is an Exit prerequisite. First accepted NF
consumption wins between an intent and an independent Exit; there is no private
cancel flag with financial authority.

Before funding the new research profile, match its actual Output/Intent/AuthExit
relations, setup identities, original-seed derivation, delivery and complete
terminal rehearsal. A proof over dummy CF/output bytes is not recipient
spendability. A tiny synthetic MPC proof is not a native financial batch.
User authorization to execute this work permits progressing through these
technical gates; it does not make an incomplete profile ready.

## Acceptance evidence and remaining questions

Freeze actual observers and owner-truth separation before constructing a new
privacy workload. Collect actual dispatcher/server views and exact public bytes.
Require the declared single-batch two-honest-owner ambiguity under the measured
view, preserve plain-constructor/pair-tag/individual-Delta negatives, and preserve
the changed-cohort counterexample. Record service-bound refusals as lost private
liveness; record history bypass as privacy failure.

Financial success requires a fresh native testnet deposit, genuine private
payment batch, deterministic invalid/double-spend/replay rejection, original-seed
received/change spending, service shutdown, independent exits and confirmed native
payouts with complete reserve/fee accounting. All-in cost uses the unchanged
21-KAS useful denominator and includes deposits, retries and exits. Existing fee,
privacy and availability failures stay in the record.

Open: complete malicious-private witness/prover composition; safety of all reactive
openings; generic private SHA/EdDSA/state witness generation; matching native batch
and independent AuthExit; usable privacy after cohort disruption; externally
available recovery data; independently administered retention and off-host scans.
No production security, general anonymity or fee improvement is claimed here.
