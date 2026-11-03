# Early privacy gate before major prover work

Date: 2026-10-20. Source baseline: `bf4505c16bd3f55ee6e4b534b14fece4281c963a`.
This note records the work order and evidence limits; no experiment has been run.
No external source refresh was performed for this note.
Existing invariants and RFC-0012 targets stand;
no protocol change or new ADR is proposed.

## Start with M2's actual observable surface

The gate must describe the implemented wallet before constructing an observer.
M2 completed a bounded offline lifecycle, not a privacy qualification or accepted
chain trace ([M2 boundaries](../poc/shared-pool/WALLET-LIFECYCLE.md#evidence-boundaries)).

| Surface | Information and treatment |
| --- | --- |
| Native transaction bytes | Public input/output references, amounts and scripts, reserve movement, fees, sizes and transaction order; add only explicitly available timing observations. Preserve actual common funding/address associations when public. |
| Authorization | Domain, count, anchor, two nullifiers, two output commitments, mode, payout, fee, payout script, deposit, funding outpoint/script, bootstrap value and ciphertext hash are explicit fields. |
| Bundle and settlement | Authorization, proof and two ciphertexts; settlement also publishes state and transition-witness bytes. Do not confuse these public witnesses with private selected-note membership paths. |
| Shared receive envelope | Format, pool descriptor hash and receive identity (`owner`, `incoming`); repeated sharing can expose equality to its recipients. Availability is declared per observer, not assumed chain-visible. |
| Wallet result | Transaction/bundle plus descriptor, base head, validation flag, metrics and component timings. Auxiliary CLI output/timings are not automatically native C inputs; include them only in the declared disclosure profile. |

Sources: [authorization and bundle](../poc/shared-pool/src/two_input/mod.rs#L52-L135),
[settlement payload](../poc/shared-pool/src/two_input/mod.rs#L194-L240),
[receive envelope](../poc/shared-pool/src/two_input/wallet.rs#L73-L89),
[receive identity](../poc/shared-pool/src/protocol.rs#L158-L163),
[result wrapper](../poc/shared-pool/src/two_input/wallet.rs#L614-L627).

The current payment policy puts the recipient in private output 0 and sender
change in output 1 ([code](../poc/shared-pool/src/two_input/wallet.rs#L452-L482)).
Model that known policy separately from the broader circuit-valid relation.
Zero padding does not add people. Encryption alone does not establish receiver
privacy; hiding, unlinkability and setup assumptions require separate review.

The published M2 narrative contains planned values and owner labels, while result
files contain process names ([trace](../poc/shared-pool/WALLET-LIFECYCLE.md#observed-complete-trace),
[process records](../poc/shared-pool/evidence/2026-10-20-wallet-lifecycle/result.json#L91)).
The whole evidence directory is therefore **not** a blinded chain-observer input.
Treat those labels/values as scored experiment truth, not chain-derived facts.
Use existing disclosed fixtures for calibration; fresh held-out evaluation must
keep its assignments private until predictions finish. A separate disclosure
profile may explicitly assess information revealed by a published narrative.

## What is already known, and what is missing

- **H16 failed its frozen screen:** participant records forced two additional
  early payment-source links. Records were disclosed separately, never pooled;
  owner identity and hidden-amount ranges were not measured
  ([result and limits](../poc/shared-pool/PARTICIPANT-PRIVACY.md)).
- **H18 failed its frozen screen:** the strongest tested source-guessing attack
  was unchanged in all four comparisons. Sparse timing paired all 48 common
  payouts with their tails and recovered the original note values under the
  declared model ([results](../poc/shared-pool/SCHEDULED-PAYOUT.md#result-and-decision),
  [pairing](../poc/shared-pool/SCHEDULED-PAYOUT.md#what-the-observer-learned)).
- **Still open:** owner-level guesses, undisclosed payment-amount ranges,
  explicit pooled collusion, active tagging/Sybil traffic and infrastructure
  observations. The old solver's anonymous `owner` symbols constrain equality;
  they are not a measured owner-anonymity result
  ([model](../poc/shared-pool/participant_privacy_observer.py#L98-L120)).

Retain exact integer accounting, independent tiny enumeration, isolated observers,
separate scoring, prefix checks and native-byte calibration
([controls](../poc/shared-pool/PARTICIPANT-PRIVACY-SPEC.md#targets-metrics-and-controls),
[calibration](../poc/shared-pool/TWO-INPUT-PRIVACY-SPEC.md#paired-policies-and-genuine-calibration)).
Extend their targets and disclosure inputs; do not rename source-set ambiguity
as identity privacy. Known singleton controls should reconstruct their sources:
they show expected absence of anonymity, not a newly discovered protocol failure.

## Smallest useful gate and its decision

1. Freeze and review a byte-derived M2 projection and observer-access manifest.
   Check it against existing native evidence and tiny exact controls before
   drawing privacy conclusions. Add explicit sender/recipient/control targets,
   exact feasible payment-value queries and pooled participant/active records.
2. Compare persistent balances with prompt cashout under the **same user payment
   intentions and resources**. Match economic obligations, starting funds,
   participation and attacker budget; expose residence, timing and operation-count
   differences. Count every fee, change claim and final tail through drainage.
3. Attack predeclared supported targets first. A smaller workload can falsify a
   claim it actually instantiates, but cannot pass the 32-role qualification.
   Passing calibration or finding no attack is permission for further bounded
   research, not evidence of useful privacy or a reason for major M3 investment.

Full qualification retains **32 roles, eight active/colluding adversarial roles**,
with C, C+P and C+P+A scored separately at payment, subsequent individual cashouts
and complete drainage. Specify individual disclosures and pooled collusion;
score sender and recipient separately as well as relationships
([adopted profile](../docs/rfc/0012-useful-privacy-requirements.md#adopted-privacy-targets)).

| Target | Unchanged absolute gate |
| --- | --- |
| Uninvolved sender or recipient identity | Strongest evaluated full-coverage accuracy ≤10% **and** ≤ strongest frozen prior +5 percentage points. |
| Undisclosed payment amount | Success within ±10% ≤20% **and** ≤ frozen prior +5 percentage points; integer test: `10 * abs(guess - amount) <= amount`. |
| Selective relationship attack | Precision ≤50% at **each** of 5%, 10% and 25% coverage of the full predeclared eligible set. |
| Forced disclosure | Zero independently reproducible, logically forced unauthorized identity, relationship or exact private-value disclosures on supported targets. |

A relative gain over prompt cashout cannot waive an absolute failure. A supported
counterexample stops the affected claim and major optimization premised on it;
preserve it and revise the hypothesis before investing further. Small/singleton
failure controls are reported separately under frozen support rules. No privacy
minimum, waiting rule or cooperation requirement may restrict independent exits.

A complete early pass requires every frozen gate, control and eligible case.
A synthetic pass remains a bounded research screen, not real-world anonymity,
cryptographic/security assurance or fee/latency qualification.

## Freeze the remaining experiment contract before execution

Freeze workload rates, amount/timing distributions, balance residence, control
matrix, adversary traffic/value share and scheduling powers; eligible targets and
legitimately already-known exclusions; stable candidate identities and genuinely
public funding-to-owner associations; strongest public-prior baselines; attack
development/holdout split, selection/ranking/ties; independently sampled sessions,
sample sizes and one-sided 95% upper confidence bounds with multiple-comparison
handling ([contract](../docs/rfc/0012-useful-privacy-requirements.md#adopted-privacy-targets)).
Candidate identities must be usable observer inputs, not secret harness labels.
Do not drop targets made easy by the transcript or hide an adverse public prior.
Unknown solver results, invalid controls, timeouts or insufficient samples mean
incomplete evidence. Report raw denominators, uncertainty and every failed case.

Offline C/P/A results establish no network anonymity. The private witness boundary
is mandatory now; later I-profile work must observe actual scanning, RPC,
broadcast/retry and recovery traffic. Do not export keys, openings, selected-note
indices or membership paths to services, logs or hosted provers
([boundary](../docs/rfc/0012-useful-privacy-requirements.md#leakage-and-trust-register),
[qualification limit](../docs/rfc/0012-useful-privacy-requirements.md#adopted-privacy-targets)).
