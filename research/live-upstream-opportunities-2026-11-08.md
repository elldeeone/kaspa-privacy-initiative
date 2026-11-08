# Live upstream contribution opportunities — 2026-11-08

## Decision

The strongest substantial contribution is a **replaceable fee-sponsor path for an already proof-authorized exit**. It directly targets open [issue #23](https://github.com/olafweller/kaspa-privacy-initiative/issues/23), preserves the existing private/native design, and can be completed with a falsifiable current-L1 transaction test rather than another architecture essay or recovery rehearsal.

This was a read-only upstream review. No GitHub comment, reaction, branch, issue, pull request, message, or other external write was made.

## Live upstream snapshot

- Olaf's `main` was `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1` at this check, matching the [current default-branch commit](https://github.com/olafweller/kaspa-privacy-initiative/commit/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1).
- The [open pull-request list](https://github.com/olafweller/kaspa-privacy-initiative/pulls?q=is%3Apr+is%3Aopen) was empty.
- The latest merged work is recovery-heavy: [#55](https://github.com/olafweller/kaspa-privacy-initiative/pull/55) prepared user-held recovery and terminal exits, [#58](https://github.com/olafweller/kaspa-privacy-initiative/pull/58) proved the local recovery lifecycle, [#60](https://github.com/olafweller/kaspa-privacy-initiative/pull/60) prepared the six-stage TN10 run, and [#61](https://github.com/olafweller/kaspa-privacy-initiative/pull/61) recorded actual TN10 recovery and full native withdrawals. Repeating that work would have high duplication risk.
- The roadmap still says the target is a private transfer through a native payout, with fees, discovery, privacy leakage, and permissionless exits treated as coupled requirements ([roadmap](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/docs/shielded-kas-next.md#first-work-package-define-the-private-payment-statement), [RFC-0001](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/docs/rfc/0001-state-architecture.md#privacy-analysis)).

## Shortlist

Scores are 1–5. Higher is better except **duplication risk**, where 1 is lowest risk.

| Rank | Concrete task | Privacy impact | Novelty | Feasible on unchanged L1 | Duplication risk | Falsifiable completion |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Replaceable fee sponsor for a proof-authorized exit ([#23](https://github.com/olafweller/kaspa-privacy-initiative/issues/23), [#8](https://github.com/olafweller/kaspa-privacy-initiative/issues/8)) | 3 | 4 | 5 | 2 | 5 |
| 2 | Wallet-independent full-log note scanner ([#12](https://github.com/olafweller/kaspa-privacy-initiative/issues/12), [#13](https://github.com/olafweller/kaspa-privacy-initiative/issues/13)) | 4 | 4 | 4 | 3 | 5 |
| 3 | Property-based economic lifecycle state machine ([#6](https://github.com/olafweller/kaspa-privacy-initiative/issues/6)) | 2 | 3 | 5 | 3 | 5 |

All three issues are open, have no assignee, and the directly named issues #23, #12, and #6 have no comments at this check.

## 1. Replaceable fee sponsor for a proof-authorized exit — recommended

### Exact unfinished question

Can a user keep the same proof-authorized principal, recipient, reserve and permission, but replace an underpriced exit transaction with a higher-fee transaction funded by a different unprivileged sponsor?

Issue #23 explicitly requires safe fee contribution/substitution, replay and reorder tests while forbidding principal haircut, reserve diversion, treasury access, or an admin rescue. The current builder already calculates a rate-dependent fee entirely from sponsor change ([transaction builder lines 516–588](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/recovery-tn10/src/transaction.rs#L516-L588)). That is a useful base, not completion of #23: the current focused test builds one payout from one sponsor and mutates underpayment, recipient and lane ([test lines 350–413](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/recovery-tn10/src/tests.rs#L350-L413)); it does not demonstrate post-authorization sponsor replacement across fee levels.

### Bounded implementation target

1. Make the payout builder accept a replaceable sponsor UTXO/key and fee quote after the exit proof and permission are fixed.
2. Build a low-fee candidate, then rebuild the same exit with an independently generated sponsor and materially higher fee.
3. Prove that principal, recipient, rent refund, permission, selected reserve, exit ID and private proof bytes are unchanged; only sponsor input/change, fee, signatures and transaction ID may change.
4. Exercise actual transaction scripts against sponsor substitution, input/output reordering, replay, reserve diversion, recipient substitution, underpayment and fee-from-principal attacks.
5. Keep the result local/unfunded unless a later, separately approved TN10 trial is needed.

### Falsifiable completion

The task passes only if the replacement validates at the higher quoted rate without regenerating the private proof or changing the user's payout, and the ledger discharges the liability exactly once. Every prohibited mutation must fail at the enforcing script/state layer without partial state change. If Kaspa's signed layout cannot support that replacement, record the exact binding that prevents it and stop; that is also a useful result.

### Honest limit

This can show a safe fee-bump mechanism under declared rates. It cannot guarantee miner inclusion under arbitrary censorship or prove production cryptographic security.

## 2. Wallet-independent full-log note scanner

### Exact unfinished question

Can wallets discover their notes from one canonical public record stream without making owner-specific, tag-specific, commitment-specific, or address-specific queries that expose wallet interest to an RPC/index service?

The existing wallet correctly trial-decrypts a supplied record list and validates commitment membership and spentness ([wallet lines 87–109](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/private-note-wallet/src/wallet.rs#L87-L109)). The specification says scanning covers public accepted records ([SPEC lines 79–98](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/private-note-wallet/SPEC.md#L79-L98)), while its adversarial review says independent data availability was not qualified ([review lines 34–44](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/private-note-wallet/ADVERSARIAL-REVIEW.md#L34-L44)). RFC-0001 also says private server queries are not assumed solved.

### Bounded implementation target

Implement a deterministic scanner and trace harness over canonical accepted lane records. Alice, Bob, and a wallet owning no notes must fetch the same ranges and bytes, perform all trial decryption locally, authenticate discovered commitments against accepted state, and fail closed on omission, reordering, corruption, or a mismatched checkpoint. Measure bytes and scan time as the public record count grows.

### Falsifiable completion

The three wallets must produce byte-identical fetch transcripts while finding different owned notes, with no wallet key, owner, tag, note commitment, or result-dependent retry in requests. Corrupt or incomplete history must never produce a spendable balance.

### Why it loses to #1

It has higher direct metadata-privacy value, but more of its cryptographic core already exists and the remaining work crosses into synchronization/data-availability design. It also does nothing about public withdrawal amounts or timing. #1 closes a narrower named blocker with less new infrastructure.

## 3. Property-based economic lifecycle state machine

### Exact unfinished question

Do conservation and single-spend invariants hold across many valid and adversarial deposit → credit → transfer → exit → payout sequences, including u64 boundaries and changing sponsor fees, rather than only the hand-authored lifecycle cases?

Open issue #6 requires explicit ranges, fees, unpaid-exit accounting, duplicate deposits, partial exits, replay, overflow and diverted/underpaid payout rejection. Current `main` has strong targeted cases, but the public acceptance criterion is broader than one frozen two-user sequence.

### Bounded implementation target

Build a small independent integer-sompi oracle and a generated state-machine test over the current ledger/native transition APIs. Generate valid and invalid sequences, shrink failures, retain deterministic seeds, and assert after every operation that native reserve equals private liabilities plus explicitly separate rent/sponsor domains; rejection must leave the full state hash unchanged.

### Falsifiable completion

All generated valid traces must match the oracle. Duplicate spends/deposits, stale anchors, overflow, wrong recipients, underpayment, replay and reserve diversion must reject atomically. Any minimized counterexample is retained as a regression test rather than retuning the generator.

### Why it loses to #1

This is valuable safety work, but it primarily increases confidence in accounting; it does not materially improve payment ambiguity or exit usability by itself. It also overlaps more with the existing deterministic adversarial suite.

## Deliberately not recommended

- **More recovery/prover-disappearance artifacts (#9/#10):** recent PRs #55–#61 already dominate this area. The remaining production claims need independently administered users and durable external state, not another local recap.
- **Another exit-correlation write-up (#13):** the issue now contains a concrete 2026-11-08 result showing that sequential service-controlled withdrawals linked the three users, coordinated later approvals removed that timing link, and payout amounts remained public. A new task should change an implemented mechanism or test a new fact, not restate that result.
- **More proof-system reproduction (#11):** the issue already contains two contribution comments with RTX 3070 measurements and current `main` includes the completed private/native proof path. This is claimed work unless a new matched workload question is frozen first.
- **PQ, legal, general funding, or documentation cleanup:** important later, but not the strongest immediate contribution to end-to-end private native-KAS payments on today's L1.

## Recommendation

Proceed only with task 1 first: write the exact immutable-vs-replaceable transaction fields and stop conditions, then implement the smallest local replacement test. Do not open a PR or contact Olaf until the result exists, survives adversarial review, and the user separately approves external interaction.
