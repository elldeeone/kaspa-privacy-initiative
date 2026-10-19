# Native-KAS privacy research journal

This is the living record of our independent experiments: what we believe,
what would falsify it, what we observed, and what changes next. Update it when
evidence or a decision changes. Keep earlier results and their limits intact;
link detailed specifications, measurements and exact transaction evidence.

North star: private native-KAS payments, correct backing, and exits that users
can complete without privileged cooperation. No new token. Work within current
Kaspa L1; consensus changes are a last resort. Testnet only, no real funds.

## Current position

Current L1 can execute the bounded direct-pool payment and withdrawal layouts
we tested. Four wallets can receive, re-spend and withdraw their own claims,
paying miner fees from those claims. This is evidence for continued direct-L1
research, not a production architecture decision or proof of general liveness.

Partial withdrawal with private change and equal first payouts preserved more
amount ambiguity in our synthetic workload. It did not improve unique-source
identification or deposit-origin ambiguity for the four selected withdrawals.
Cryptographic confidentiality, chain inference and network privacy remain
separate questions.

The immediate gaps are protocol-level prevention of tiny unexit-able claims and
recovery when another transaction consumes the shared reserve before a wallet's
proof is accepted. Missing public history, fee changes, setup compromise,
reorgs, contention starvation, scalability and independent cryptographic review
also remain open.

## Hypotheses and decisions

| ID | Falsifiable claim | Evidence/status | Decision |
| --- | --- | --- | --- |
| H1 | A private native-KAS payment and authorized exits can pay their own fees on existing L1 without a sponsor or privileged withdrawal key. | Supported for one funded two-wallet sequence; four native transactions accepted. | Continue direct-L1 experiments; no need demonstrated for a vProgs runtime in this bounded case. |
| H2 | Private withdrawal change increases feasible consumed-note candidates relative to whole-note withdrawal in the paired four-wallet workload. | Supported for all four selected exits initially and three after complete drain; input amounts remained non-unique for 4/4 partial exits versus exact for 4/4 full exits. | Retain partial change for further study. Equal 0.25 tKAS payout policy was bundled with the change mechanism. |
| H3 | Enforcing a protocol-level note minimum can prevent the tiny-liability obstruction at the tested fee rate without privileged rescue. | Pending design, boundary tests and native validation. Wallet filtering alone is insufficient. | Compare a fixed floor with alternatives, derive it from native mass/fees, and enforce every creation path. |
| H4 | After two wallets race on the same reserve, the losing wallet can discover accepted state, rebuild its proof and exit using its own keys and public data. | Pending funded simultaneous-exit test. Earlier proofs were precomputed for a sequential schedule. | Test real contention and recovery; require payout confirmation, no winner secret or operator-selected successor. |

Candidate counts are marginal logical possibilities, not probabilities, people
or joint-history counts. Synthetic results must never become claims of
real-world anonymity. Passing tests is not proof of cryptographic correctness.

## Experiment record

### Earlier foundation: reproduction and recovery

We reproduced upstream's four outer proofs on an RTX 3070 8GB and posted the
results on P11/#11. That evidence remains on `upstream-reproduction`.
The separate `p10-recovery-research` work recovered a fresh synthetic instance;
reproduction of the archived instance depends on unpublished public parameters.
P10 was not posted. These results motivate explicit artifact-availability
assumptions; they do not dictate which architecture our own experiments choose.
See the [recovery report](../research/p10-recovery/REPORT.md).

### 2026-10-19 — Self-funded private payment and exits (H1)

- Question: can native claims pay the actual L1 fee while preserving backing
  and allowing the recipient to withdraw without the sender's secret?
- Observation: funding, one private payment and both exits succeeded on TN10.
  Total fees were 0.492620 tKAS; no experimental reserve remained.
- What changed: the basic current-L1 mechanics are demonstrated for this
  layout. Sponsorship and an operator withdrawal signature are unnecessary for
  this case.
- Limits: single-party setup, small fixed state, retained public artifacts,
  unaudited implementation, two synthetic participants and sequential execution.
  This is not an anonymity measurement.
- Evidence: [report](../poc/self-funded/README.md),
  [RFC-0003](rfc/0003-direct-self-funded-trial.md),
  [ADR-0015](adr/0015-direct-self-funded-tn10-trial.md).

### 2026-10-19 — Four-wallet full/partial comparison (H2)

- Question: what can a chain observer reconstruct, and does private withdrawal
  change preserve ambiguity after everyone exits?
- Observation: 19 full-arm and 23 partial-arm transactions were accepted;
  every wallet drained and both reserves were spent. Fees were 2.849380 and
  3.517918 tKAS respectively. Public ledger accounting reconciled exactly.
- Inference: after drain, the selected full exits each had five possible source
  transactions; partial exits had five, six, seven and eight. All had four
  possible deposit ancestors. Full input values were exact in 4/4 cases;
  partial input values remained non-unique in 4/4 cases under the model.
- What changed: retain private change, but do not claim that more change
  outputs create more independent participants. The initial singleton spend
  remains linked, public deposits/payouts remain visible, and the four wallets
  share publicly visible funding.
- Limits: one fixed paired workload, no background users or network/RPC-client
  observation, precomputed proofs, no competing exits, wallet-only dust policy.
  The supplementary amount test was added after the first graph result; its
  timing and solver refinements are recorded in the methodology artifacts.
- Evidence: [report](../poc/shared-pool/README.md),
  [comparison](../poc/shared-pool/evidence/2026-10-19-tn10/comparison.json),
  [RFC-0004](rfc/0004-four-wallet-shared-pool.md),
  [ADR-0016](adr/0016-four-wallet-shared-pool-trial.md),
  [adversarial review](../poc/shared-pool/ADVERSARIAL-REVIEW.md).

### 2026-10-19 — Checkpoint and authorized next experiment (H3/H4)

The owner authorized a local commit of code, documents and sanitized evidence
on `shared-pool-four-wallet`, followed by the tiny-note fix and simultaneous
exit test. No push or upstream posting is authorized by this checkpoint.
Wallet secrets, note randomness and proving parameters remain outside Git.
The original worktrees and earlier transaction evidence are preserved.

Next result must record: the exact floor and fee assumptions; creation-path and
native boundary rejections; competing submissions against the same outpoint;
which transaction was accepted; how the losing wallet found and verified the
successor; proof regeneration; both actual native payouts; remaining reserve,
cost and elapsed time. A precomputed alternate winner/loser schedule alone is
insufficient evidence of independent recovery.

## How to extend this journal

For each bounded experiment, append its hypothesis, falsifier, assumptions,
observed result, interpretation, decision, remaining uncertainty and evidence
links. Update the status table without erasing contrary results. Put resolved
design decisions in an ADR and open choices in an RFC. Keep accepted-chain
evidence, local validation, source analysis and recommendations distinct.
