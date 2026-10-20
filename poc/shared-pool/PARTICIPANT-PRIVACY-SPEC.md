# H16: reconstruction after one participant discloses its records

Frozen before implementation or observation, on `shared-pool-four-wallet` at
baseline `73b553a`. The owner authorized executing the proposed offline insider
test, comparison and design decision. Keep code, results and journal on this
branch. This does not authorize a protocol change, network trial or publication.

## Hypothesis and decision

**Hypothesis:** in the unchanged H14 workloads, disclosure by one participant
does not turn any previously ambiguous, uninvolved fresh-policy payment into
a uniquely determined source-transaction set. At least half of the eligible
payments in every case/participant combination must remain ambiguous after
complete drainage. Fresh must retain a strictly larger sum of marginal source
alternatives than saved in at least one matched case/participant pair.

These are a diagnostic screen for resistance to this disclosure, not a privacy
guarantee or a replacement for Stage 2's population thresholds. Any additional
forced payment link falsifies the first claim, even if the other clauses pass.
Report clauses separately. Failure requires identifying the leak and choosing
a bounded wallet-policy/design investigation before expanding wallet features;
it does not justify changing L1 consensus or abandoning independent exits.
A pass supports broader varied-workload evaluation, not a real-world claim.

Reuse the four economic cases and eight public transcripts frozen in `1bf14d0`
byte-for-byte, plus the original private plans/truth. Rotate the disclosing
participant through all four wallets, without pooling their records. Each
rotation is a separate adversary, not four colluding participants. Predictions
for every case must finish before the separate scorer opens that case's truth.
The researcher knows the recipes; technical blinding applies to observer access.

## What is disclosed, and when

The adversary has the H15 `wallet` chain-only model plus one complete, honest
wallet record, conditional on this known client. The record is a projection
of the frozen private plan, not a dump of it:

| Information | Justification and limit |
| --- | --- |
| All positive receipts: commitment position and integer amount | `protocol.rs::Wallet::decrypt` validates the recipient, value and commitment. A complete scan identifies this account's own receipts, including change. Zero padding is made for a fresh throwaway wallet and is not a receipt. |
| The wallet's own authored transactions: exact real inputs and both created output values | The sender constructs the witness and output plaintexts in `two_input/harness.rs::authorize`. Include its deposit, self-transfer, payments, partial withdrawals and full exits. |
| Recipient-address equality for positive outputs it authored | `Wallet::receive` returns a stable domain-bound receive address. Replace those addresses with local anonymous handles, with handle 0 for self. Distinct handles are distinct spending authorities, not people. Do not disclose addresses or labels for other parties' outputs. |
| The wallet's own note spends, and absence of any other spend of its notes | Its retained records and secret-dependent nullifiers identify these uses. The account is assumed uncompromised and complete, with no joint spending/key sharing. This is participant knowledge, not a chain-only inference. |

Receipt knowledge starts at note creation. Authored-transaction knowledge starts
at that transaction's appearance. At each observation prefix, remove all future
receipts and authored records before constructing constraints. No later
disclosure is retroactively supplied to an earlier observation.

An incoming receipt does **not** disclose the sender, input set, other output
amount or change owner. Knowing an output one sent does **not** disclose its
later spend/nullifier: v6's real nullifier uses the recipient's spending secret
(`two_input/circuit.rs`, `compact/mod.rs`). The model must infer such later uses.
No global wallet IDs, four-owner bound, workload labels, future schedule,
arm label, private proof, unused fallback, key, or unrelated note plaintext is
an observer input. RPC, IP, network timing, external identities, active probing,
multiple insiders and compromised keys are outside this experiment.

## Two nested comparisons

1. `records`: H15 wallet assumptions plus the exact disclosed amounts and
   authored inputs. Undisclosed transactions cannot consume the discloser's
   notes. This uses no ownership propagation between other accounts.
2. `wallet` (primary): additionally apply the known client rules that selected
   inputs belong to one spending authority, normal payment output 1 is its
   change when positive, and partial-withdrawal output 0 is its retained value.
   Bind only disclosed recipient handles; all other owners remain arbitrary.

The latter rules come from `two_input_privacy_generate.py::build` and
`two_input/harness.rs` construction. They are not enforced same-owner rules of
the v6 circuit and are not facts about all possible clients. No oldest/largest
coin-selection rule is invented. Anonymous owner assignments may use as many
otherwise unknown authorities as needed; four simulated wallets do not imply
four possible real users. Known-client ownership without any account labels did
not remove histories in H15; the disclosed handles can make it consequential.

Run 4 cases × 2 exit policies × 4 separate participants × 2 profiles = 64
observations. Reuse H15's stored `wallet` predictions as the chain-only baseline
on the exact same eligible targets. Require primary candidates to be a subset
of `records`, and `records` a subset of H15, at every observation point.

## Targets, metrics and controls

The observer predicts every spend's input/source sets. Only the scorer applies
the eligibility rule: a target transaction has no real input or positive output
owned by the disclosing wallet. Exclude bootstrap and admission from payment
metrics. Exclude its own withdrawals. A later transaction spending a note
previously sent by the discloser remains eligible: that later use is not a
disclosed fact. Explain this boundary in the report.

Report private payments, partial withdrawals and full exits separately. Preserve
H14 horizons: each target at appearance and complete drain, and each payment
after every full exit. Report forced links and their precision/coverage,
additional forced links versus matched H15, the existing deterministic recency
guess, exact input-set and deduplicated source-set counts, and narrowing during
drainage. Report each participant and case, both exit arms, and both profiles.
Aggregate rotated wallet-target observations only with an explicit warning that
these are overlapping targets, not independent payments or a population sample.
Candidate counts are logical marginal alternatives, not probabilities or people.

Controls must cover:

- agreement with independent exhaustive tiny integer/ownership ledgers, for
  CP-SAT, integer SMT and the exact hybrid engine;
- exact records, incomplete/malformed/contradictory records, and an unrelated
  amount or input choice not leaking through the projection;
- receipt-only knowledge not becoming sender-input or recipient-spend knowledge;
- zero padding, same-owner/change rules versus protocol-valid alternatives,
  owner-label symmetry and no assumed population bound;
- prefix isolation, nested candidate sets and all true sets surviving;
- replay, stale/current anchors and existing H14/H15 controls.

Unknown or unfinished solver results are inconclusive, never extra privacy.
The observer receives only public input, one projected view, code and solver
libraries inside the existing filesystem/network sandbox. It cannot read full
plans, truth, other participants' views, wallet keys or the controller. Pin
inputs, baseline evidence and code. Retain failures and corrections.

## Completion, cost and preservation

Complete all 64 observations and controls; report the hypothesis clauses and
the decision, costs, limitations and adversarial second-pass review. Preserve
the original circuit, covenant, setup, prior tests and native evidence. This is
an observer-only experiment: actual funds and new proofs are zero. The same
synthetic fees, schedules and prior independent-exit evidence are inherited,
not revalidated. No extra delay or native fee is introduced by the observer.

Projected participant records and original private files stay outside Git.
Export source/input hashes, isolation receipts, eligible-target predictions,
scores and summary metrics, not the disclosed records or a full inferred copy
of already-known wallet activity. No note opening, key or exit capability is
needed or exported.

Source check, 2026-10-20 UTC: the existing v6 files above are the controlling
source for this projection. [ZIP 310](https://zips.z.cash/zip-0310) distinguishes
incoming/outgoing/spend visibility; [ZIP 315](https://zips.z.cash/zip-0315)
(Draft) treats wallet behavior as a privacy concern. These motivate careful
knowledge boundaries, not a transfer of Zcash's security properties to v6.
The prior [source review](../../research/compact-policy-study-sources-2026-10-20.md)
remains applicable: no Kaspa dependency or protocol implementation is changing.
