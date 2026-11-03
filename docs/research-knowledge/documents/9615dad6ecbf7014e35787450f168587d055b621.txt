# Public four-wallet orchestration handoff

Source freeze02: `c14ae7f00beb0f78f21b2c28f50daa79a9cc54407dc51053ad737145cb91e402`.
Baseline: `b7b41ab066807d7859499b3491a663ab110fedf9`.

Implemented fixed public acquisition, full accepted-prefix reconciliation,
durable one-attempt submission, independent owner send attempts, and complete
integer-sompi arithmetic checks. The source adapter uses only explicitly staged
selected SDK bytes; the historical host SDK-cache dependency was corrected
before execution. Source freeze01 remains a superseded implementation record.

20 public Python controls and nine public SDK/mock-RPC groups pass. They cover
duplicate/concurrent sends, unknown responses, immutable exact SDK/native case
joins, u64 preservation, all-four backup alias exclusions before reads, stale
heads, financial-effect substitution, replay refusal and coordinator-free owner
attempts. Mocked acceptance never represents an actual accepted transaction.

This lane performed no actual Native execution, private proof generation,
original-backup/key/witness read, network acquisition, funding or submission.
No confirmed GN2/W payout or complete-rehearsal readiness is claimed. Genuine
local integration and the complete four-payout testnet rehearsal remain the
execution gates; root schedules the private/outer proving workers separately.

`RUNNER-CLI.md` and `SUBMIT-CLI.md` describe the fixed entry points. The richer
lifecycle ledger additionally binds original-backup owner results and final
recovery scans; arithmetic inspection alone is insufficient for that result.
The host, selected read-only installation and trusted non-atomic validating
TN10 node remain premises. Financial privacy and independent public-history
retention remain separate gates.
