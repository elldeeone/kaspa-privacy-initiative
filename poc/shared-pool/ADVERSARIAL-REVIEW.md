# Four-wallet trial review

Reviewed against ADR-0016, RFC-0004, AGENTS.md and SECURITY-INVARIANTS.md.
The baseline is the prior uncommitted self-funded trial on e86e2a277ad53b28fc3bfc4aea40c24d858259fb.
This is an AI source review and local test evidence, not an independent audit.

## Standards review

The runner mounts only the selected wallet's secret file, public parameters and
history, and its writable output directory. It validates and pins the complete
sequence before funding. Every live submission has a durable one-use receipt.
Native input contexts come from live UTXOs; final accounting includes all fees
and confirmed remaining outputs.

A deposit mutation could fail only because its ordinary signature was invalid,
without testing reserve binding. Fixed: outpoint, amount and owner mutations now
also execute reserve input 0 alone and require rejection. This is additional to
Full validation, not a substitute. Remaining controls are aggregate transaction
rejections and are labelled accordingly.

The wallet minimum is not a circuit minimum. Malicious tiny claims may obstruct
later exits via native storage mass. This limitation is explicit in the RFC and
threat model; no general adversarial liveness claim follows from the trial.

## Specification review

Fixed a forged initial descriptor that could skip bootstrap backing: wallet
history requires exactly one initial commitment and no nullifiers. A dedicated
regression rejects an otherwise structurally valid forged state.

Fixed acceptance of notes too small to pay their own configured exit. Wallets
quarantine them, while usable notes remain available. Boundary and mixed
valid/dust regressions cover the policy; new private outputs are checked before
proving. Future fee changes remain outside this fixed-rate policy.

The observer creates a fresh prefix-only integer solver at each horizon. It
excludes unborn and already-consumed notes and propagates deposit ancestry.
The scorer alone sees hidden truth and rejects any excluded true candidate.
Analytic controls cover singleton bootstrap, multiple histories, future
information, partial-change ambiguity, inconsistent balances and relabelling.
Candidate sets are marginal logical possibilities, not joint-history counts or
anonymity probabilities. The model uses protocol-positive amounts, not the
wallet-specific minimum-note policy.

The original export contained submitted bodies confirmed through UTXOs. A
separate read-only retrieval now compares Full accepted-chain transaction bodies
and full hashes before producing the observer transcript. The observer runs in
a namespace exposing only its software and that transcript, with no wallet,
manifest, private plan, truth or RPC access.

Precomputed independent proofs establish separate spending authority for the
chosen sequence. They do not establish recovery through arbitrary competing
transactions, missing history, reorgs or setup compromise. The experiment's
coordinator knows the synthetic schedule and truth; it is not an anonymity user.

The supplementary amount attack checks for a second distinct input amount and
the scorer checks any forced amount against truth. It also pins all true note
values and choices simultaneously: the complete true history satisfies each
prefix model. This is stronger than checking only marginal candidate inclusion.

Reviewed solver accelerations add only implied inequalities: each positive
child is bounded by the largest possible parent less public costs and positive
siblings; each deposit's descendants cannot spend more than its public credit,
and must spend exactly that credit on complete drain. The final observer source
SHA256 is `d7f8176c9691738855dddbd3afe6b83a9e53b81d0e73d151c65d74b8488f246c`.
All eight analytic controls pass and every full-arm event/candidate set matches
the original solver. The accelerated partial solver completed all queries;
stopping redundant profiling runs supplied no privacy evidence.

Both funded runs completed: 42 accepted transactions, 118 native mutation
rejections, four drained wallets per arm, no remaining reserve, exact final
accounting, and accepted-chain body/full-hash matches. Final evidence exports
omit keys and private witnesses and include known-secret scans. These checks
do not remove the setup, dust, contention or availability limitations above.
