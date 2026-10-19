# Version-3 floor and exit-retry review

Reviewed against checkpoint `62c8550`, ADR-0017, RFC-0005, AGENTS.md and
SECURITY-INVARIANTS.md. Two AI source-review passes covered specification/security
and standards. This is not an independent cryptographic audit.

The note minimum is enforced in the relation with bounded 64-bit nonnegative
slack. Every active input/output and withdrawal payout is covered; inactive zero
padding remains valid. Existing backing equality, authorization, nullifiers,
domain/state binding and terminal capacity behavior remain enforced. Fresh
domain/version/VK avoids silently changing existing claims.

Each agent receives one key file, public seed history and parameters. Its prover
has no network, other wallet file or host home. The agents independently verify
seed acceptance, build against the same unspent reserve and record each one-use
submission before RPC. The loser discovers an unknown accepted successor by
reserve outpoint, validates native body/proof/history, rescans and reproves.
The stale-proof control tests actual verifier rejection on the rebuilt body.

Review fixed three runner defects before funding: success now requires winner
termination before the loser's payout; explicit unexpected RPC rejection fails
instead of polling forever; failure cleanup stops and reaps remaining agents.
Ambiguous transport responses are labelled unknown and reconciled by observation,
never by resubmission. The focused second pass found no remaining concrete
blocker. Eight native tests and five chain/runner tests passed.

The first funded rehearsal then exposed a launcher portability defect: the
Node executable was outside the mounted `/usr` tree. An explicit executable
mount fixed it. A separate cleanup attempt exposed Ubuntu's AppArmor restriction
on nested Bubblewrap namespaces before either exit was submitted. The launcher
now starts wallet and prover as sibling sandboxes, connected directly through
per-wallet FIFOs. The host controller neither reads nor forwards those messages.
No host security setting was changed; prover network/PID isolation and key
separation remain intact. A real-launcher fixture test checks the round trip and
EOF shutdown, and a focused source review found no remaining blocker. Interrupted
attempts remain failed evidence; cleanup does not qualify as a rehearsal.

Final accounting must include every confirmed ordinary change/payout and all
accepted fees. Live confirmation and accepted-chain retrieval are distinct from
local native validation and default relay-policy checks. Funded results are
recorded in [CONTENTION.md](CONTENTION.md).

Remaining assumptions: single-party setup, unaudited cryptography, fixed fee
rate, retained public artifacts, correct RPC consensus view and one eventual
opportunity. Reorgs fail closed; continuous contention can still prevent an exit.
These changes address bounded liveness, not payment privacy.
