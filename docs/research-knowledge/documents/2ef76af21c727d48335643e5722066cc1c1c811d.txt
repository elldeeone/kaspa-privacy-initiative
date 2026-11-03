# ADR-0017: Protocol note floor and independent exit retry

Accepted for an owner-authorized TN10 experiment, 2026-10-19. Baseline
`62c8550` preserves the earlier version-2 trials and sanitized evidence.

The version-2 wallet rejected tiny notes, but another prover could create them.
An outstanding tiny claim could leave a native reserve too small to satisfy
Kaspa's storage-mass limit when someone else exits. Paying more fee does not
remove that limit. A wallet-only filter is insufficient.

Use a new version-3 domain/state/transcript and fresh experimental Groth16
parameters. The proof enforces these immutable rules:

- Every real private input and new private output is at least 26,713,000 sompi
  (0.26713 tKAS), including bootstrap, deposits, both transfer outputs and partial
  change. Inactive zero-valued dummy notes remain allowed.
- Every public withdrawal payout is at least 10,000,000 sompi (0.1 tKAS).
- Every nonterminal reserve is at least the note minimum. A proven terminal
  exit still leaves exactly zero reserve and works at commitment capacity.

For the unchanged fixed transaction layout at 100 sompi/gram, the larger full
exit fee is 16,713,000 sompi. The note floor covers it plus the payout floor.
Native fee calculations must fail a compatibility check if this relation stops
holding. No promise is made about arbitrary future fee rates. No existing
version-2 reserve is upgraded; the earlier pools were already drained.

Both plain P2SH and P2PK outputs here have storage plurality one. With storage
parameter C=10^12, a continuing exit has storage mass bounded above by
floor(C/note_min)+floor(C/payout_min)=137,434, below 500,000 and the exit compute
mass even before input subtraction. The terminal bound is 100,000. Backing and
the note floor make any remaining liability large enough for this argument.
Verify with native mass code and boundary cases, not just this arithmetic.
A smaller context-specific minimum is rejected because it has little operating
margin. Sponsorship, privileged dust sweeps and confiscation are rejected.

For contention, fund a fresh two-wallet domain and make one private transfer.
The recipient receives exactly the minimum note. Each wallet independently
builds a valid full exit against the same accepted reserve. Two isolated wallet
agents submit once after a common test start signal; the coordinator then only
observes. The start signal arranges the race and does not authorize withdrawals.

Each agent has only its own wallet file, public software/parameters/history and
RPC access. Its prover has no network access. Wallet and prover run in separate
sibling sandboxes with direct per-wallet FIFO communication: this avoids the
host's restriction on nested namespaces without changing its security policy.
The launcher neither reads nor forwards their private protocol messages.
The wallet discovers successors by
scanning all accepted transaction bodies returned by
getVirtualChainFromBlockV2, matching the tracked reserve input, checking canonical
bytes/full hashes and native validation, and verifying the successor UTXO.
No future transaction IDs, winner labels, private selections or precomputed
recovery transactions are supplied to the losing agent. It rescans its notes,
rebuilds against the accepted successor, proves locally and submits the new
transaction once. The economic nullifier stays the same; state/outpoint and
proof change. The winner exits its process after confirming its payout.

The rejected conflicting candidate is an expected part of this experiment,
not permission to rebroadcast it. Every distinct transaction is submitted once.
An unexpected failure starts a fresh trial identity, retaining the old evidence.
Run the whole path as a fresh funded rehearsal before the measured trial.

Success requires both native payouts, no remaining reserve, exact accounting,
and evidence that the loser obtained the winner's accepted transaction from RPC
and produced a fresh proof afterwards. A precomputed sequential alternative is
not sufficient. Reorg recovery, hostile RPC consensus views, indefinite
contention, pruning, unavailable public parameters and setup compromise remain
out of scope. Ordinary full-node availability and one opportunity after the
winner stops are explicit liveness assumptions.
