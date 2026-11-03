> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Peer review: public-field reconstruction specification

2026-10-22, Australia/Sydney. Source-only review on Forge. Reviewed specification: [/home/luke/projects/kpi-orchestration/2026-10-22/native-surface-review/PUBLIC-FIELD-RECONSTRUCTION-SPEC.md](../native/PUBLIC-FIELD-RECONSTRUCTION-SPEC.md), SHA-256 `8b02cc63e10c965941d3d44b131863edca4391f4e665973ef3f4d29d9a70ca92`.

**Validation: no material mistake found in the stated singleton-deletion result. Do not run the proposed audit merely to establish that result: the cited source and elementary accounting already establish it.** A computation could check a newly implemented reconstruction/certificate tool, but would add no evidence about private-payment inference, the price experiment, native observability or a proposed mitigation.

## Coverage of the exact reconstruction claim

All project sources below are in `/home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/`.

| Case | Source-supported derivation | Review conclusion |
|---|---|---|
| Any event deposit, payout or fee | `R_i = R_(i-1)+D_i-P_i-F_i`; invert for the sole missing flow term | Holds for ADMIT, both zero/nonzero-payout SPEND, and DRAIN; it does not require knowing the hidden event purpose or owner. `working_balance_model.py:209-244`; `working_balance_observer.py:95-108`. |
| First or later reserve | First predecessor reserve is explicitly zero in this model; then use that event's retained flows. All missing reserves follow by cumulative conservation | The initial-boundary premise is supplied, rather than guessed. `working_balance_model.py:169,239-240`; `working_balance_observer.py:81`. |
| Separate whole event columns | With only payouts or only deposits removed, each row has adjacent retained reserves and the remaining flows. With all reserves removed, accumulate the retained flows. Fees are also declared constants | Correct for each named column separately. It does not imply arbitrary joint-mask invertibility. |
| Bridge total or any one source amount | `I = sum(s_j)`; a missing individual source is `I - sum(other sources)` | Works for multiple sources as well as the singleton fixture; no directory or payout-reference resolution is necessary for this singleton mask. `working_balance_model.py:294-299`; observer:114-118. |
| Bridge deposit, fee or change | `I = D_b+f_b+C_b`, plus `D_b=D_i` | Correct, including zero change. The bridge fee and pool fee are distinct and correctly separated. model:296-304; validator:197-217. |
| Carried-forward bridge change | A later source with the exact previous `change_ref` has the previous change amount; payout-source references similarly carry exact payout values | Generated histories preserve these equalities. The public observer validates local sums but does not itself establish every cross-reference equality; the specification correctly derives B3 from the generator/independent validator and requires its own reference checks. model:266-267,294-300; validator:200-217. |
| DRAIN, including terminal zero reserve | Payout recovery still follows E1. `P_i+F_i` is the total private input consumed by this DRAIN | The report correctly does not identify the note(s), an earlier economic payment or a person from this aggregate. model:224-231; observer:283-299. |

The handwritten fixture amounts and the proposed C6 pair check out by inspection: `3,960,000,000 + 5,920,000,000 = 4,060,000,000 + 5,820,000,000 = 9,880,000,000`. Increasing the first payout by `100,000,000` lowers only its masked intermediate reserve by that amount; decreasing the second restores the retained final reserve. Both remain positive and within the declared bounds. The specification properly limits this to two completions of the stated public arithmetic rules, not two proven private/native executions.

## Controls and information provenance

The separation is adequate:

- Exact answers require retained-field/constant derivations; C7 rejects the 45-tKAS prior or a guessed payment-flow link even when numerically correct.
- Empty/permuted directory controls query the same event pointer. The directory may change identity association, not its numeric deposit. D2 explicitly identifies the separate initial-admission order convention. S1 identifies the first-four tagged payment convention instead of calling it transaction-derived arithmetic or an ordinary price prior.
- N1 is correctly limited to this model's one-positive-note admission convention. It is not generalized to all valid native two-output admissions.
- Zero-payout SPEND exposes only its fee through the reserve change. C5 and the explanatory equations do not turn that change into a private payment amount. The spec also retains self-merges as possible observable zero-payout events.
- C6 and the `unresolved_by_rules` status prevent “could not reconstruct” from being called privacy. Duplicate bridge copies, prefixes and unmasked-hash equality oracles are explicitly addressed.

## Remaining limits, not reasons to expand this audit

1. `R_-1=0` and both fixed fees are declared model facts. Do not extend them to an arbitrary native pool, unknown starting checkpoint, missing earlier history or different fee policy without supplying those premises.
2. The minimal O-base/O-split/O-bridge suite does not exercise every topology: O-partial is named but excluded from the minimal three, O-bridge has one source, and it does not consume a prior bridge-change reference. It also does not reach terminal zero reserve. The algebra covers those cases; a completed run should claim only its actual fixture coverage, not exhaustive implementation coverage.
3. The handwritten fixtures are public arithmetic interfaces, not native accepted transactions or full private-ledger witnesses. A source-level redundancy proof does not establish native-field parity, attack success, realistic behavior or cryptographic privacy.

Recommendation: retain the specification and this review as the result. If a reconstruction API is later needed for another concrete task, test that implementation then. Do not introduce a coordinator/reconstructor framework solely to recompute these identities.

## Pin verification and side-effect boundary

All eight SHA-256 entries in the reviewed specification matched the live named files: model, observer, validator, their two named test files, both trial files, and the allowlisted older public development audit receipt. The receipt's recorded source identities also match; no bulk archive was opened. Named fixture construction and cited source ranges were read directly. The active evaluation was not accessed, code was not imported, and no audit, experiment, build or proof was run. Only this new review file was written.
