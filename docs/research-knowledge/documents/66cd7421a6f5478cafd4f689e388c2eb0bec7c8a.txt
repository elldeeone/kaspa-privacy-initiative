# Research history and archived branches

Use [project status](PROJECT-STATUS.md) for current work and [lessons](RESEARCH-LESSONS.md) for corrected findings. This index preserves the relationship between experiments without importing their incompatible source trees.

## Current references

| Reference | Role |
| --- | --- |
| `main` at `7ffe8353` | Unmodified upstream baseline, including its final recovery features and CI. |
| `research/native-kas-withdrawal-privacy` | Current wallet-local research and consolidation; production architecture remains open. |
| `research/shielded-kas-feasibility` at `4d54dc02` | Frozen historical direct-L1, cost, recovery and private-construction reference. Read its owner-paused handoff before any reuse. |

## Retrieve a historical result

Every original local branch tip has an annotated `archive/2026-11-03/BRANCH` tag. The [machine-readable receipt](research-history/2026-11-03.json) includes each full commit ID. For example:

```sh
git show archive/2026-11-03/shielded-kas-research:poc/shared-pool/PRICE-LEAKAGE.md
git show archive/2026-11-03/research/shielded-kas-feasibility:docs/checkpoints/2026-10-27.md
```

The tags retain exact source/evidence identities; they do not qualify an old implementation for a new domain, key, wallet or trial. Original remote branches remain historical upstream/fork references. Local lane retirement is recorded in the final consolidation receipt.

## Every original branch

| Original local branch | Preserved tip | Purpose / disposition |
| --- | --- | --- |
| `docs/kpi-orchestration-2026-10-22` | `596d800706af` | Local tip is nine commits ahead of its GitHub counterpart. |
| `main` | `7ffe83534376` | Keep the upstream baseline unchanged. |
| `offline-wallet` | `b41141733ed0` | Unique offline wallet implementation and four real GPU receipts. |
| `p10-recovery-research` | `e86e2a277ad5` | Its committed work is contained in the broad feasibility line. |
| `research/native-kas-withdrawal-privacy` | `5f8c8957e1c8` | Current entry point; original pre-consolidation tip preserved. |
| `research/shielded-kas-feasibility` | `4d54dc026098` | Frozen historical reference; paused MPC work and rejected local patch retained. |
| `self-funded-native-kas` | `e86e2a277ad5` | Tip aliases p10-recovery-research, so branch name is misleading. |
| `shielded-kas-research` | `ec6aa15d586b` | Committed history is contained in feasibility. |
| `test/native-admission-adapter-proposal-20261022` | `fde0c288d42f` | Independent side-branch tip; per-input admission controls. |
| `test/native-continuation-admission-20261022` | `c430dd8a18d7` | Native continuing payout/context checks; ancestor of admission-adapter branch. |
| `test/native-guard-controls-20261022` | `dd00ceed35a9` | Native payout/successor guard controls; ancestor of continuation/admission test branches. |
| `test/one-v6-input-binding-control-20261022` | `6fdc5fc61ddd` | 6fdc5fc6 has a real changed-public-input pairing rejection. |
| `test/one-v6-verifier-compatibility-20261022` | `acba8b04237e` | One-bundle host/reference adapters; ancestor of 6fdc5fc6. |
| `test/relation-controls-20261022` | `2251864a7f89` | Range/ownership/padding controls; ancestor of tree-capacity branch. |
| `test/tree-capacity-controls-20261022` | `67793fa4b849` | Independent side-branch tip covering capacity and no-mutation refusal. |
| `upstream-reproduction` | `a0ef8fb82263` | Unique RTX 3070 reproduction; four outer receipts in 10m27s, po2=19 adaptation, CPU/native controls. |
| `work/intensive-research-20261022` | `85e39398fd97` | 85e39398 is an ancestor of feasibility. |
| `work/native-observation-20261022` | `ec6aa15d586b` | Tip equals shielded-kas-research. |
| `work/outer-proof-compatibility-20261022` | `6fdc5fc61ddd` | Tip equals 6fdc5fc6. |
| `work/privacy-source-review-20261022` | `ec6aa15d586b` | Tip equals shielded-kas-research. |
| `work/protocol-binding-review-20261022` | `ec6aa15d586b` | Tip equals shielded-kas-research. |
| `work/public-binding-fixtures-20261022` | `ec6aa15d586b` | Tip equals shielded-kas-research. |
| `work/s7-owner-lifecycle-20261022` | `68d7b039f606` | 68d7b039 is an ancestor of feasibility. |
| `work/two-bundle-binding-20261022` | `6fdc5fc61ddd` | Tip equals 6fdc5fc6. |

## How the histories diverged

Both main refs were at 20 October. The broad feasibility line forked earlier at `cde2b88d` and has 97 commits outside current main; main has 11 commits absent from that line. The latest wallet-local line instead began from current main and added `33af388f` and `5f8c8957`. A newer date is not evidence that a checkout contains every earlier result.

The audit covered 363 commits, including original/squashed histories from 42 merged upstream PRs and two otherwise unreachable commits. These are not 363 separate experiments. Seven local branch names were additional aliases of the same tips; their unfinished worktrees still differed.

## Resolve numeric document references by lineage

| Number | Current wallet-local line | Frozen feasibility line |
| --- | --- | --- |
| RFC-0003 | Depth-four multi-user TN10 profile | Direct self-funded trial |
| RFC-0004 | Native-KAS payment/transparent-exit boundary | Four-wallet shared pool |
| ADR-0018 | Depth-four private-spend experiment | Reusable private authorization |
| ADR-0019 | Depth-four multi-user TN10 trial | Compact public settlement |

The separate offline-wallet line reuses some numbers too. Use exact commit, path and title when citing those records. ADR-0100 uses the next number above all audited lines. The distinct I-2 clarifications on offline-wallet and feasibility are not merged into current SECURITY-INVARIANTS.md.

## Retained private material

Public source histories and the private unfinished-file archive have separate manifests. Wallets, proving parameters, raw observations and ignored runtime state remain private. The [preservation checkpoint](research-preservation-2026-11-03.md) states what was verified and the same-machine limitation. Generated build outputs and raw runtime directories are not publication candidates merely because their branch is archived.

