# Operations and evidence lessons

[Knowledge guide](README.md) · [Current trial rules](../../AGENTS.md)

## Preserve these implementation lessons

| Area | Retained rule | Why it matters |
| --- | --- | --- |
| Amounts and RPC integers | Integer sompi and lossless u64/header parsing across SDK/RPC boundaries. | Rounded JSON or mixed types can invalidate identity, mass and accounting checks. |
| Native transaction construction | Commit exact storage mass and validate the final SDK-decoded transaction under the selected fee policy. | A hand-built estimate or partial native script check misses final transaction conditions. |
| Accounting and rollback | Validate full payout/authorization before economic mutation; keep pending liabilities, reserve and treasury separate; roll back scanner accounting atomically on reorg. | A valid local proof does not justify a mismatched payout or stale state. |
| Fresh trials | Use current AGENTS.md: a new identity is the retry boundary, and the complete terminal payout must succeed in rehearsal. | Old frozen notes contain superseded operational ceremony; they do not govern new trials. |
| Negative controls | Isolate the intended verifier/guard failure and retain exact error classes. | A resource or parsing failure can otherwise masquerade as a semantic rejection. |
| Archive handling | Bound expansion/member counts before parsing attacker-controlled tar metadata and retain interrupted/partial artifacts. | A valid outer archive hash does not replace safe extraction behavior. |
| Source qualification | Explicitly select the original source closure for old immutable proof packages; preserve all original pins. | Relabelling an old binary as built from new source destroys evidence integrity. |
| Process lifetime | Own a process group/session and retain a deadline independent of the caller; test real controller loss and descendant termination. | The installed uutils timer left a grandchild alive in the reproduced failure. |
| Parameter and output files | Authenticate exact parameter bytes, create required parents, publish complete results atomically and preserve failed attempts. | A successful partial copy or interrupted run must not appear as a complete package. |
| Environment and tool versions | Keep inherited standard environment names intact; SDK and component versions can use different namespaces. | The retained compression retry needed inherited HOME; SDK 3.0.3 selected component 0.1.0. |

The [repair record](../../poc/remote-cuda/CONSOLIDATION-REPAIR.md) records nine
historical source-binding repairs and two process-deadline failures. The
[configured verification receipt](../research-history/verification-2026-11-03.json)
supersedes the old checkpoint's red-CI statement: 177 Python and 13 Node tests
passed; two existing native integration tests needed explicit local configuration.
These results establish no new proof, provider action or chain observation.

The same-group deadline does not control a descendant that deliberately creates
another session; its provider lease guard is a separate boundary. Passing these
local controls is not provider, GPU, privacy or production qualification.

## Evidence handling

Keep source identity, actual observation, interpretation and unknown separate.
Do not rewrite old receipts when correcting a conclusion. Bind external image,
claim/journal and receipt identities before verification; an artifact's own
self-description is not an independent trust anchor. [negative-checker follow-up](documents/e4f3a80120580cb93def507a46537a250e411531.txt) preserves
concrete error-layer and consumed-buffer corrections.

[native/extractor publication review](documents/72c635d386564daabdab13261cc13ab0a8c3476a.txt) distinguishes source readiness from binary redistribution:
package manifests, locks, adapted native policy attribution and actual linked
notices differ. A dependency appearing in a lock is not proof of linkage. Keep
that unresolved historical publication assessment with its components.

The local archive preserves original worktree data and rejected patches. It is
on the same machine, not an off-host backup. Neither frozen text here nor its
checksum authorizes funding, broadcasting, rental or restarting paused MPC.

## Busy prover jobs

The [executed queue/cancellation test](../../research/busy-pool-payment-flow-2026-11-06/RESULT.md)
adds two operational lessons. Copy an executable before self-spawning from a
long campaign: rebuilding the live path produced a deleted `current_exe` and
stopped the first preflight. Cache already fully checked public parameters inside
each wallet process; do not reload/recheck them for every routine request.
No cryptographic check was removed.

Freeze a prover work item, retain its original request age on retry, and never
promote projected children to accepted state before their parents validate.
Pending requests do not stale proofs. When an authenticated bank advance makes
work obsolete, terminate only the owned isolated process group; record child
identities and confirm owned CUDA workers stop before replacement work starts.
The measured process control stops after 30.398 seconds, cleans up in 0.135,
and produces a fresh fully reverified replacement without new owner approvals.
Its timer replays an already retained real race; it is not another chain event.

Native IDs exclude proof witnesses, enabling exact-body replacement and child
reuse only when input/image/journal/body/payload remain identical. The published
replay checks this across the complete native history. Preserve original failed
work and separate source epochs. Frozen documents are retained byte-exact as
`.md.txt` snapshots so relocated historical links do not become live doc links.
