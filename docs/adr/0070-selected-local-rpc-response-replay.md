# ADR-0070: Selected local RPC response replay

Status: Proposed. A nonlive component exists; no financial profile or controller selects it.

## Context

The retained Borsh diagnostic completed 79 new history pages, then its next
`getServerInfo` failed because the transport was disconnected. Re-fetching those
public responses took roughly 33 minutes. The original SDK scan, discovery,
current-state checks and Native financial verification remain the acceptance path.

Two independent offline checks now bind all 79 captured pages: exact request/IPC
response identities and strict first-parent continuity across 69,820 groups.
They establish local capture eligibility, not financial acceptance:

- [IPC origin report](../../research/next-session/local-private-payment/review/RAW-DELTA79-IPC-ORIGIN-ELIGIBILITY-01.json).
- [First-parent report](../../research/next-session/local-private-payment/review/RAW-DELTA79-FIRST-PARENT-ELIGIBILITY-01.json).

## Proposed decision

Allow one explicitly selected local capture to supply raw Full RPC responses to
the unchanged scan. Preserve the original runtime, admission, financial SDK and
217-page admitted prefix. Replayed pages never increase `cache_reuse.base_pages`
and never produce a CACHE, HANDOFF or financial state by themselves.

The finite selector binds the original endpoint, descriptor, financial selection,
runtime/admission, baseline fetch/cache, capture source/results, and each page's
gzip, decoded and exact recorded IPC identities. Every served page rechecks those
identities and strict first-parent ordering.

Before the first replay, a live header-only `getBlock` must return the selected
retained tail on the selected chain. The unchanged old SDK recomputes its header
hash and the canonical header must match. Replay then supplies exactly 79
sequential Full/depth-20 requests. The next primary Full must successfully return
from the exact retained tail before any subsequent non-Full call is allowed.

Before saving a fetch, `assertResult` requires the actual returned fixed frontier
strictly beyond that tail, successful primary live continuation and unchanged
admitted-prefix identities. Current queries, post-query scanning, exact-point
requery, offline verification, whole Native CASE comparison and financial replay
remain mandatory. Rejection disables replay and raises `CACHE_STALE` into the
ordinary full-acquisition fallback. The module does not mutate fetch values.

## Trust and limits

This is a selected local transport capture under the existing trusted-controller
and remote-validating-node assumptions. It is not a generic untrusted archive
import, PoW/consensus proof, or independent authentication of accepted transaction
lists. Toccata's accepted-ID field is not a simple transaction-ID Merkle root.
The earlier [source analysis](../../research/next-session/local-private-payment/review/RAW-DELTA-CACHE-AND-RPC-DEADLINE-01.md)
continues to apply.

Only public chain data is read. No signer, owner backup or private key is added.
The component is optional and remains unselected until source review, guard
controls and a separately authorized rehearsal pass. Any future integration must
bind its additional source/selector through the outer acquisition closure and
public provenance sidecar without claiming new financial cache authority.
