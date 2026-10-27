# Two-owner authorization aggregate: proposed experiment

**2026-10-26 — preparation only. No implementation, compilation or execution.**
The next small question is whether two independently authorized records can
satisfy one relation whose public interface contains independently ordered
nullifiers and complete output tuples, with the correspondence kept in
internal wires. This tests structural grouping and authorization wiring. The
plain constructor and public fixture still expose the complete map.

Prerequisite: Root accepts the corrected predicate pipeline's frozen 49-case
result, including its mandatory actual-R1CS negative checks. Run01 remains
`FAIL_PRESERVED`; this plan grants no retry, setup, proving or native authority.

## Reuse exactly these inputs and sources

- `signature-authority-predicate-01/circuits/authority.circom`, SHA256
  `e5b158ec4cc88afa8be35ca8758140bb9c1e7899c31d83572ed20f30b824b68b`.
  Reuse `AuthorityPredicate()` twice. Its source contains a `main`: derive a
  separate library as its exact byte prefix before `component main`, retaining
  all templates/includes unchanged. Pin and independently compare that prefix;
  leave the frozen original untouched.
- Immutable public run01 `HANDOFF.json`, 173104 bytes, SHA256
  `284aef4352a57132a289dc81a8067290a0b15e6dc66e8735c5da71e73ae7f218`.
  Both baseline records share anchor and all eight public context fields.
  Their NFs and four CMs are distinct; each tuple is 520 bytes. Both owners
  exited. Reuse signatures and the existing owner-0 alternative; no new key,
  signature or owner process. Handoff classification stays **NON-PRIVATE**.
- The existing pinned Circomlib/Node/compiler/checker closure and the corrected
  generated-C++ pipeline, only after that pipeline passes its own source/result
  gate. No new primitive, package family, MPC or private prover is proposed.

## Proposed relation and precise interface

The outer `main` has **no output signals**. Its only public inputs are:

```
anchor, evaluationHeight, testTag, chainId, poolId, profileId, roleId, assetTag
NF[2]                         // canonical field elements, independently ordered
tuple[4][520]                 // whole CM32|CV64|CF264|CFH32|proof128 records
feeTotal                      // unsigned 65-bit synthetic sum, not a native fee
```

This debug interface has 2,091 public field elements. It is not a proposed
native proof ABI or an optimized fee design. No Groth16 proof/cost claim follows.

Private witnesses comprise both existing complete records, their PKs and
signatures, and Boolean permutation matrices `U[2][2]` and `V[4][4]`. No signing
secret enters any witness. Connect each common context input directly to both
child predicates. Keep nonce, signed height interval and owner-specific fields
internal. In particular, each child's `out[35]` exposes its tuple digest/limbs
and signed message if made public: **none is an outer public output**.

New wrapper constraints, explicitly additional to the unchanged children:

1. Each matrix entry is Boolean; every row and column sums to one. Public NF
   rows equal the `U` permutation of the two child NFs. Each public tuple byte
   equals the `V` permutation of the four child tuples. Use constrained products
   and linear sums, not a host permutation or host equality oracle.
2. The two public NFs differ. Decode each public CM from its first 32 bytes;
   the child/permutation constraints supply its strict canonical bytes. All
   six pairs of the four CMs differ **within this batch**. No historical/global
   CM uniqueness rule is introduced.
3. `feeTotal = feeSompi[0] + feeSompi[1]`, with an explicit 65-bit range. Each
   child already constrains its own input/output/fee values to uint64 and exact
   conservation. Their sum is below `2^65`, far below Fr; do not apply field-wrap
   accounting or silently import native MAX/floors. The existing fixture totals
   20,000,000 sompi of synthetic fees.

The private owner-slot order can change without changing public data. The
internal payment/change order remains the owner's signed SHA order; only whole
tuples may move into public rows. Bijection plus NF distinctness prevents
duplicate record consumption **inside this one relation**. It does not check a
historical spent set or prove that two records belong to different humans.

## What the reused predicate actually establishes

| Property | Existing constraint / explicit gap |
| --- | --- |
| Authority | Actual always-enabled Circomlib EdDSA/Poseidon; canonical PK/R8/S, on-curve prime subgroup/nonidentity checks; PK and separate NK bound into input note identity. No SK witness. |
| Membership/NF | Poseidon depth-one synthetic membership with Boolean leaf index; `NF=Poseidon(NK,index)`. No native tree, accepted-state oracle, NF insertion or historical spentness. |
| CM/value | Input/output Poseidon CMs bind synthetic asset/value; CM bytes are strict field encodings. Input/payment/change/fee are uint64 with exact per-owner conservation. No native note format, MAX/floors or recipient-key derivation. |
| CV | **No CVin exists.** Output CV64 bytes are signed through the complete tuple hash; no curve/commitment-opening check, CV balance equation or Delta is implemented. Publish no invented Delta/CVin field. |
| CF/CFH/proof | All tuple bytes are byte-ranged and actual in-circuit SHA-bound into consent. Encryption, `CFH=hash(CF)`, output-proof validity, recipient spendability and receipt/change recovery remain **UNBUILT**. Authorized arbitrary bytes can satisfy it. |
| Context | Shared synthetic tags are uint64; signed B includes test/chain/pool/profile/role, nonce, interval, fee and tuple digest. Asset is bound through note/CM relations; exact anchor is signed. Evaluation height lies in the signed interval but has no authenticated native time source. |
| State/replay/effects | No current reserve/outpoint, accepted-state update, reorg rule, consumed-intent database, native fee/effects binding or cancellation. Identical replay at the same eligible fictional state still satisfies the relation. |

## Proposed finite checks: 29 rows, before any run

Let A/B be baseline records; A0/A1/B0/B1 their complete tuples. Default public
order is `[NF_A,NF_B]`, `[A0,A1,B0,B1]`; this grouped positive is a control, not
the claimed private format. Recompute permutation witnesses for valid cases.

| Accept rows | Exact change |
| --- | --- |
| P01 | Default baseline. |
| P02 | Reverse public NF order only. |
| P03 | Public outputs `[A0,B0,A1,B1]` only. |
| P04 | Reverse NF order; outputs `[B1,B0,A1,A0]`. |
| P05 | Swap private A/B component slots and corresponding selector labels; public bytes exactly P03. |
| P06 | Existing signed owner-0 alternative plus B baseline; update only the corresponding complete public tuples/selectors. |
| P07 | Exact repeat of P03 at height150: **ACCEPT**, retaining the missing replay-state boundary. |

| Reject rows | Exact mutation from P01 unless specified |
| --- | --- |
| N01 / N02 | Duplicate public NF; / put valid A baseline in both private slots with duplicated public arrays. |
| N03 | Replace one public whole tuple by another, omitting its original. |
| N04 / N05 | Two private rows choose the same public column in U / V; keep other baseline data. |
| N06 | `U=[[2,-1],[-1,2]]` (encode -1 as Fr-1), row/column sums still one; set public NFs to that field-linear combination. Boolean selectors must reject. |
| N07 | Swap only A/B signature R8 and S, retaining their original PKs/records. |
| N08 | Swap only the first32 CM bytes of two public tuples; move none of their remaining488 bytes. |
| N09 / N10 | Flip public A0 CF byte96 only; / flip the same byte in both private A0 and its public row, retaining old signature. |
| N11 | Increase public feeTotal by one. |
| N12 | A fee+1/change-1 and B fee-1/change+1; recompute CMs/CM bytes and public tuples, keep original signatures and unchanged total fee. |
| N13–N16 | Public chainId / poolId / profileId / roleId +1, propagated to both children, with old signatures. |
| N17 | Public anchor+1 for both children, old signatures/siblings. |
| N18 / N19 | Public evaluationHeight99 / 201, outside the signed [100,200] interval. |
| N20 | Set A0 CF byte96 to256 in private and public tuples; keep old signature. |
| N21 | Set A fee to `2^64`, update public sum to that fee+B fee; keep other record fields. |
| N22 | Public testTag+1, propagated to both children, old signatures. |

Freeze exact emitted JSON/field encodings and expectations before execution.
All 29 rows require an actual complete witness plus an actual R1CS-check result;
generation-only rejection, parser rejection or checker error is **FAIL**, never
an accepted negative. Bypass host semantic validators for malformed controls;
retain schema/selection integrity. N06 isolates the Boolean-selector requirement;
other rejections may overlap. The immutable signatures do not provide an
otherwise-valid duplicate-CM signed fixture, so claim no isolated CM-distinctness
coverage. Stop and preserve the first unexpected result/input/witness; no rekey,
retuning, check weakening or automatic rerun.

Use the corrected pipeline's selected constraint-preserving generator method:
any assertion-disabled generator must be paired with the ordinary selected
aggregate R1CS and byte-identity/equivalence check required by that pipeline.
Source freeze must pin template extraction, wrapper, 29-case recipe, public
signal list, generated artifacts and checker. One serial job; tmpfs only after
Root checks live resources. No compiler/setup/prover action is authorized here.

## Claim and adversarial review limits

The plain constructor receives the full owner→NF→tuple map; publish that
knowledge as an expected negative control. The entire fixture and mapping
truth are public, including owner-index-derived tuple bytes. Therefore neither
permutation satisfaction nor absence of a public pair-ID proves anonymity,
indistinguishability or coordinator-map hiding. Inspect compiler public signals
and the proposed observer projection for unintended child outputs/labels, but
make **no privacy PASS**. Current native 1NF→2CM grouping remains unchanged.

Private proving still needs the malicious full-witness/input/handoff/opening
construction in the existing source memo. Active changed-cohort retries, sticky
history loss/honest departures, data availability, independent exits, native
integration and the frozen 2% fee FAIL remain unresolved. This fixture provides
no funded/recovery evidence or new safe sharing threshold.

## Proposed ADR text — status PROPOSED, no assigned ADR number

**Question:** should the next offline experiment compose existing authorization
predicates with a private bijection, before building a native/private prover?
**Proposed decision:** use the exact reused two-owner public fixture and the
minimal wrapper above. Compare independently ordered public arrays with a
plain full-map constructor. Require every negative at the actual constraint
layer. **Alternatives:** two independent predicate checks do not test their
aggregate correspondence; public owner slots/digests expose that correspondence;
starting MPC now lacks the required malicious-prover composition. **Consequences:**
bounded aggregate-wiring evidence only, large debug public-input arity, no
native/profile migration or privacy/fee/recovery qualification. Root must select
the later source/run separately; this text changes no current architecture.

## Proposed RFC delta — open, no protocol rule adopted

Add this experiment under the future hidden-partition authorization work, not
RFC0029's current wire/profile. Record required future decisions: real new-note
PK/NK/KDF and every Spend/Exit route; output validity/receipt recovery; a compact
native public-effect binding; authenticated historical/current-state rules;
durable consent/cancellation; reviewed private proving; and active retry/data
availability. A successful 29-row result can advance only the correspondence
subquestion. Before any protocol implementation, select an ADR and synchronize
architecture/threat-model/invariants review. No new token, admin exit, owner
online dependency or reinterpretation of existing notes/proofs is proposed.

Source basis: [collaborative source memo](COLLABORATIVE-INTENT-PROVING-SOURCE-01.md)
`5f8ccd7e1834be152dfba9ee88a78c73748026201946cd8d92fff98bddea9959`,
[predicate plan](SIGNATURE-AUTHORITY-PROTOTYPE-PLAN-01.md)
`42900a915b5e61078597cef42ad351819605276db20bd4f96e661816af757ac2`,
and [integration proposal](PRIVATE-BATCH-INTEGRATION-NEXT-01.md)
`fe12e53433ddede7a4c8468878bf62a32b7d8a1a2e20dbad7df78defc780ea91`.
All public source/handoff reads used unchanged helper09. No Original/private
state/log/truth, signing secret, runtime, network or financial action was used.
