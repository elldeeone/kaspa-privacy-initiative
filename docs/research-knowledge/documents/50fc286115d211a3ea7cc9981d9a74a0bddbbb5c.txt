# RFC-0005: Note-floor and exit-contention validation

Design: [ADR-0017](../adr/0017-note-floor-and-independent-exit-retry.md).
Research: [journal](../RESEARCH-JOURNAL.md), hypotheses H3 and H4.

Status, 2026-10-19: implemented and tested in fresh version-3 pools. A complete
funded rehearsal and measured race passed; the losing wallet independently
reproved and confirmed its payout after the winner stopped. The recipient won
both races. See [results, costs and limits](../../poc/shared-pool/CONTENTION.md).
The open questions below remain unresolved.

H3 fails if a valid version-3 proof can create a real note below the immutable
minimum, if a minimum note cannot exit at the configured fee rate in either
position, or if another permitted claim leaves an inadmissible native reserve.
Check below/equal/above boundaries for deposits, both transfer outputs, partial
change, bootstrap/input and native payouts. Preserve authorization, backing,
range, replay, wrong-state, cross-domain and capacity tests.

H4 fails if the losing wallet requires another wallet's key, an operator-chosen
successor, a precomputed alternative, a rebroadcast of the stale transaction, or
cannot complete its actual payout after the winner stops. Mempool acceptance
alone is not a completed exit. Both candidates must spend the same reserve;
record submission timestamps and actual accepted order, not an assumed winner.

Smallest useful workload: one shared reserve, two separately isolated wallets,
one transfer assigning the exact-minimum note to the recipient, two competing
full exits and a new proof from the loser against accepted state. Run a fresh
complete rehearsal, then a fresh measured race. Report all accepted fees,
rejected submissions, payout amounts, proof-generation time, parameter startup,
retry time, final balances and observation boundaries. Keep wallet secrets and
private note material outside Git; retain public receipts and source hashes.

Open after the test: fee repricing and long-lived minimum notes; fairness under
continuous contention; arbitrary reorgs; independently verified consensus views;
public-history/parameter availability; scalable state; cryptographic review.
The note minimum is an economic restriction, not a privacy improvement. The
race test is a liveness experiment, not an anonymity measurement.
