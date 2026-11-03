# ADR-0100: Research consolidation and the transparent-exit boundary

**Status:** Accepted for repository consolidation and research posture only.
**Date:** 2026-11-03.

## Problem

Research has diverged across incompatible profiles and many branch/worktree
snapshots. Later corrections can be missed when an old result or branch name is
treated as current authority. The owner requested a complete audit followed by
preservation, consolidation, logical commits and retirement of completed lanes.

The original strong financial-privacy requirement still includes legitimate
known-owner/full-drainage observations. This authorization does not silently
relax that requirement or select a production protocol.

## Decision

1. Use [PROJECT-STATUS](../PROJECT-STATUS.md) as the current evidence/next-work
   entry point, with [lessons](../RESEARCH-LESSONS.md) and
   [history](../RESEARCH-HISTORY.md) disclosed through links.
2. Preserve all audited branch tips under annotated archive tags and privately
   preserve unmatched unfinished files before retiring local branches/worktrees.
   Keep raw private/runtime material outside Git and retain failed experiments.
3. Keep current upstream main, the wallet-local research line and the paused
   feasibility source identity distinct. The active line contains the local
   [knowledge library](../research-knowledge/README.md) from all audited histories;
   the paused reference is an exact archive tag and detached/locked worktree.
   Reuse source-bound components selectively; domain, setup, codec, invariant
   and evidence differences preclude a bulk runtime merge.
4. Retain the strong privacy requirement. The current wallet-local/direct-inline-
   ZK flow is a reference for confidential on-domain activity and transparent
   exits, not a solution to confidential completed ordinary payouts. The next
   research deliverable for the stronger requirement is a source-bound native
   confidential/shielded value specification and specialist review.
5. Keep RFC-0001 and RFC-0004 open. MPC/private-construction work stays paused.
   Relevant CI repairs must preserve historical proof/binary/source pins and
   actual descendant-termination checks.

## Alternatives

| Alternative | Assessment |
| --- | --- |
| Merge all experimental trees | Reject: incompatible identities, duplicated numbering, large snapshots and older missing upstream features/checks. |
| Delete apparently redundant worktrees | Reject before preservation: identical HEADs conceal different unfinished and ignored files. |
| Treat transparent payouts as an accepted privacy exception | Requires an explicit owner decision. No such requirement change is inferred here. |
| Resume the aggregate MPC/runtime work to hide public payout values | No demonstrated mechanism changes ordinary native output fields; the registered aggregate path is also incomplete. |
| Preserve history, centralize corrected results, retain the privacy requirement | Selected: makes prior work reusable without inflating its evidence or restarting the paused programme. |

## Evidence and security implications

The knowledge-completion step on 3 November imports every distinct committed
Markdown/rst revision across the 369-commit source checkpoint and 15 selected
unfinished research notes. Task guides state what to carry, adapt or archive.
Every original branch and pull history is represented in a locally verifiable
ledger. The feasibility branch name is retired after that import; its source,
paused worktree and rejected patch remain preserved. This changes document
availability and repository organization, not protocol architecture or authority.

The [preservation receipt](../research-preservation-2026-11-03.md) binds the
audited tips and private file preservation. The [live correction](../../research/full-drainage-executed-lifecycle-2026-11-01/CORRECTION.md)
retains two complete histories and discloses some payment facts; the
[common-reserve experiment](../../research/full-drainage-executed-lifecycle-2026-11-01/NEXT-PRIVACY-RESULT.md)
failed to improve direct-payment inference. [RFC-0004](../rfc/0004-native-kas-private-payment-boundary.md)
pins the native output/validation boundary and mature-protocol comparisons.

No spend authority, conservation equation, root/nullifier check, verifier,
wallet key derivation or withdrawal policy changes. SECURITY-INVARIANTS.md stays
unchanged. A local archive is not independent data availability. Retired source
is recoverable by exact tag; raw backups and parameters require their separate
private retention. New public documents contain summaries and source pointers,
not owner truth or recovery material.

## Reconsideration

Revisit the research direction if a reviewed current native-value mechanism
hides the required boundary, or if the owner explicitly changes the privacy
claim. Any actual architecture adoption still needs its own RFC review and ADR.

This decision authorizes no funded experiment, broadcast, mainnet deployment,
new MPC run or production-security claim.
