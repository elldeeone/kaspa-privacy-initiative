# Shared shielded history and withdrawal linkage — measured result

**Date:** 2026-11-01  
**Experiment:** `wallet-local-shared-history-v1`  
**Decision:** **unrelated activity preserved the frozen privacy gate while the
target chain withdrew and six unrelated notes remained. Full drainage still
recovered sensitive payment facts. No observed result requires MPC.**

## What ran

- One depth-four ledger; eight independently keyed same-host wallet contexts.
- Four genuine credits, two unrelated two-payment/re-spending chains, and eight
  owner-authorized exits: 16 accepted Groth16 operations in 78.657 seconds.
- Both first recipients restored backups, discovered received notes, and spent
  them again. Every remaining note later exited from an owner backup; final
  reserve and private liability were zero.
- Wrong-domain, wrong-root, replay, unauthorized discovery and diverted-payout
  controls rejected. The unchanged default wallet suite passed 9/9 tests.

Proofs took 72.203 seconds total (4.446–4.734 seconds each); setup took 5.808
seconds. No network, Testnet, funding, real users, paid compute or MPC was used.

## Sealed joint observer result

Predictions consumed the single complete public history jointly and were sealed
at `22965f4cf9a2a9b1d9d51a061c0ac29eacabce9130043cbb8b24bc4761b3f046`
before the scorer read owner-local truth.

| Checkpoint | Known payout identities | Unmapped payouts | Gate |
|---|---:|---:|---|
| pre-cashout | 16 topologies / 6 schedules | 16 / 6 | pass |
| target cashout, six notes remain | 8 / 6 | 16 / 6 | pass |
| full cashout | 1 / 6 | 4 / 6 | **fail** |

At target cashout, every payment still had at least two candidates for sender,
recipient, relationship, amount, historical origin and output grouping in all
four public/service views. The public and neutral-service results were identical.

After full cashout:

- Known payout identities left one joint topology. For both chains, P1, P2,
  original funder, recipients and relationships were unique.
- Without payout-owner mappings, both original funders and both P1 values were
  still unique. Each P2 retained two values, each first recipient retained two
  candidates, and four joint topologies remained.
- Output grouping stayed at two candidates and the second historical input at
  six because exits were not linked to commitments under the declared opacity
  assumption.

Thus shared unrelated activity helped through the measured partial-withdrawal
checkpoint, but did not survive complete transparent drainage. This experiment
changes activity count, credit count and scheduling together, so it does not
isolate which difference caused the improvement.

## Controls and limits

- The exact coupled truth, transfer schedule and exit-role assignment survived
  enumeration in all four views. This post-seal check publishes booleans only.
- All observer controls and the public-safety audit passed: 16 exact
  capture/event pairs, eight `0600` backups, no detected backup encoding or
  copied workload in public evidence, and no published truth values.
- The predecessor manifest remains unchanged at
  `adb0da8835e82db929bcabf3d94ab7b189cb70df7b0f8eded4f41486138b0ce5`.
- Same-host independent keys are not independent administration or adoption.
  Deposits, exits and payouts are authenticated offline fixtures, not consensus.
- Cryptographic opacity is an observer assumption; passing tests and genuine
  proofs do not establish cryptographic correctness or production safety.
- MPC would not hide public exit values, conservation equations or known payout
  owners. There is no concrete MPC requirement from this result.

## Reproducible evidence

- frozen policy: `SELECTION.md`
- pre-wallet commitment: `WORKLOAD-COMMITMENT.json`
- genuine runner: `runner/`
- frozen observer/scorer: `observer.py`, `score.py`
- controls and safety audit: `controls.py`, `audit_run.py`, `joint_truth_check.py`
- public evidence: `run/public/`
- public manifest SHA-256:
  `1a9463269ef5647a1ce22b0af6b8e2121f236950fe2333873107c204f49677d9`

Owner-local workload, truth and backups remain outside Git under `/var/tmp`.
