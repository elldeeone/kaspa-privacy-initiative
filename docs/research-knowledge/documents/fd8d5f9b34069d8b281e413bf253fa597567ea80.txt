# Next integration: authorization, hidden partition, private proving

**2026-10-26 — proposed work sequence; no architecture selected or execution
authorized by this note.** Finish the signature predicate's negative-test
harness, then build one synthetic two-owner aggregate relation. Keep its plain
constructor as the explicit privacy failure control. A private prover requires
a separate, presently missing malicious-security construction.

This synthesizes the existing [source memo](COLLABORATIVE-INTENT-PROVING-SOURCE-01.md),
[predicate plan](SIGNATURE-AUTHORITY-PROTOTYPE-PLAN-01.md),
[hidden-partition design](ASYNC-HIDDEN-PARTITION-DESIGN-01.md), and frozen
[baseline](model/BASELINE-REPORT-01.md) / [sticky](model/sticky-owner-basket-01/OUTCOME-01.md)
results. It changes no source, fixture, expectation, model, live trial or
publication manifest. Native KAS, independent exits and I-1–I-16 remain required.

## Smallest next executable slice

1. **Finish authorization evidence.** Preserve predicate run01 as
   `FAIL_PRESERVED`: the SHA companion and four owner records satisfied the
   actual R1CS after both owners exited; the first negative stopped during
   witness generation, leaving its mandatory constraint check unperformed.
   A separately selected harness correction must keep the same 49 cases,
   expected outcomes and financial relation. Generator rejection alone cannot
   satisfy a mandatory R1CS rejection. No fresh keys to hide a failure.
2. **Compose two owners, without claiming privacy.** Reuse the selected owner
   predicate twice over the same fictional anchor. Private aggregate witnesses
   contain the two complete signed records and a permutation into public
   `2 × (NF, CVin)` and `4 × complete output tuple` arrays. Prove a bijection:
   each authorized input and each exact approved output occurs once; NFs are
   distinct; each owner separately conserves bounded integer sompi; aggregate
   fee equals the sum of authorized fees. Bind the selected context, prior
   state and resulting public effects. Enforce current-state validity in the
   relation rather than accepting a constructor's assertion. Initially keep
   the predicate's exact-anchor policy; durable head movement remains absent.
3. **Audit the public boundary before private proving.** Independently order
   input rows and whole output tuples. Publish no owner/pair/intent identifier,
   per-owner signature/statement slot, individual Delta, per-intent fee
   allocation or upload handle. Only an aggregate Delta may be public. Keep
   every byte of each 520-byte tuple covered by its owner's authorization;
   permuting tuples never permits changing their contents. The plain prover
   still knows the partition and must remain labelled **NON-PRIVATE**.
4. **Replace that constructor only after selecting the complete private
   proving protocol.** The source contract must cover private input admission,
   full extended-witness validity before revealing proof-related outputs,
   identical authenticated assignment across witness extension/proving,
   fresh proving randomness and every reactive opening. A final proof's
   rejection cannot undo an earlier disclosure. Current semi-honest TACEO
   APIs and the existing MASCOT admission program do not supply this complete
   contract. No map-hiding claim until an actual allowed coordinator/server
   view has been collected and checked.

The synthetic predicate binds authorization, not ciphertext/encryption or
output-proof validity. Those gaps must remain visible in the aggregate slice;
it cannot produce native payment/readiness or recovery evidence. A later real
profile must validate recipient spendability and recoverable change too.

## Exact replacement seams

| Existing seam | Required successor obligation |
| --- | --- |
| `relation/src/circuit.rs` Spend **and Exit** require `owner_secret` | New note identity binds a wallet-local signing PK and separate NK. Never export or reinterpret today's `owner_secret` as proving material. Every consumption route enforces legitimate owner authorization. |
| `SpendStatement` / `wallet/payment.py:authorize` bind complete current effects | New restricted intent specifies exact tuples, integer fee, context, anchor policy, nonce and validity. The existing Spend200 proof cannot be repacked. |
| `verification/common/src/lib.rs:evaluate` receives public grouped components | New aggregate verifies hidden per-owner consent, correspondence, state updates and actual native effects. A public-proof fold alone does not hide its constructor's map. |
| Existing note/KDF/domain/profile/setup and seed recovery | New RFC/ADR and synchronized architecture/threat model before protocol implementation; independent seed-derived receiving, change recovery and direct Exit must work under the new rules. No migration or old-proof compatibility is assumed. |

## Frozen questions for the later implementation experiment

Use the existing observer definitions: public egress includes unaccepted and
orphaned proposals; the active observer additionally knows owner cohorts,
sessions and its colluding wallet's material. Preserve the existing failures.

| Control | Required interpretation |
| --- | --- |
| Two honest owners, one batch | Under the declared opaque-field model, neither honest NF assignment nor its exact output pair is unique: the existing model has 2 NF / 6 pair candidates. These are consistency counts, not probabilities. |
| Plain constructor, pair tags, individual Delta | Expected mapping disclosure; retain as negative controls. |
| One honest owner plus one colluder | Colluder subtraction leaves one honest intent: no multi-owner anonymity claim. An active-observer comparison needs at least two honest remaining owners, such as ABC with colluding C. |
| ABC egress, C wins independent Exit, changed known ADE retry/reorg | Existing A mapping collapse remains a failure. Correct private proving does not erase stable NF/output intersections. |
| Sticky ABC→AB | Conditional 2/6 ambiguity only while A/B remain honest and durable global history survives. B exits while C stays, history loss/bypass and cross-service enforcement remain unresolved; refusing private progress is a liveness cost. |
| All servers disappear | Before acceptance, the original note still permits direct Exit. After acceptance, seed plus complete authenticated public data/software/parameters must recover received/change notes and exit without a private partition or pending-intent journal. |

Do not publish a transaction under a new privacy claim merely because the
single-batch control passes. The native settlement race, known-cohort retry,
data availability and service censorship remain separate limitations. No
always-online-owner requirement or operator freeze of independent exits fixes
them.

## Cost gate

Measure matched work separately from privacy: owner work, collaborative work,
native verification/mass, deposits, retries, nine independent exits and actual
fees for the unchanged 21-KAS workload. Its 2% budget is 42,000,000 sompi.
Under the selected two-public-input Groth16 Exit charge and checked default
100-sompi/gram rate, nine verification charges alone imply 132,750,000 sompi,
before other costs. Payment batching alone cannot meet that budget while those
exit paths remain. This is a conditional source-derived lower bound, not a
new fee measurement or universal consensus minimum. See [native costs](../fees/NATIVE-VERIFICATION-COST-01.md)
and [fee units](../fees/FEE-FLOOR-01.md). Existing 2% **FAIL** remains.

## Evidence identities used

All public bodies were read through unchanged helper09. No actual Original,
private plan/state/log/truth, key, runtime, network or financial action was used.

| Evidence | SHA256 |
| --- | --- |
| Collaborative source memo | `5f8ccd7e1834be152dfba9ee88a78c73748026201946cd8d92fff98bddea9959` |
| Predicate plan | `42900a915b5e61078597cef42ad351819605276db20bd4f96e661816af757ac2` |
| Hidden-partition design | `5825670bd730a4ff65c39e40068d1f6676c93a0a8a370d535f44cf9eede6fe2e` |
| Baseline report | `b4b36d1ddd1396c8f28015523d62cfb692ed36566f95ea8dadaeb18a3d338d31` |
| Sticky outcome / addendum | `202df3fe2dcc83e8317191449e40648a24585005fd80bf88bd834941f6fd6c6d` / `d5fe6a501466fb818e58d000ec6d3fcc0ec9ad1b3a8a08e386ed1411509be018` |
| Current Spend/Exit circuit | `e13fa9bd6ba33bd01b71e824d10944b3d8561854b3c026f997b282cf57fde4b0` |
| Spend statements / wallet payment / common verifier | `bcd3f5f947904fe6fecc4e747b93e0f85a5c611390d0331651e3a1884004e123` / `5ff0774fd1bb67ebc5ed5ec246ce2434082bfc4ce82dad9e58047b34232d2bda` / `949452a43d9db837067a818e09f9660bf5f6ff9a3adac82094120e532aca6d5d` |
| Native verification cost / fee floor | `efe66fd50a4200273ab101b1c566307253259093497b1ceb8cad543dbb7fabe6` / `cdb6cb4cc83673a67350f28296c6bea75d7399ae8fa7a23105a28d4a654e25ac` |

This note records a proposal, not a selected architecture or new execution
freeze. It does not amend any prior immutable evidence or authorize setup,
proving, MPC implementation, native-profile changes or a trial.
