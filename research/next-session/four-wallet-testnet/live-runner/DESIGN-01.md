# Four-wallet public orchestration and one-attempt submission

Design at parent baseline b7b41ab0 under RFC0025/ADR0060. This lane owns only
new `poc/four-wallet-live` and this evidence directory. It does not read owner
backups, keys or witnesses, run a proof/VM/GPU, fund an address or submit a live
transaction without root's later execution release. The runner is research
automation, not an on-chain operator authority or new withdrawal condition.

## Fixed interfaces and authority

The caller externally selects the financial profile SHA, software-source
inventory SHA, original trial directory and descriptor SHA. Source entrypoints
are a closed list below fixed repository paths; public data supplies no command,
module path or callback. The final source selection is frozen after sibling
interfaces are reviewed. Hashing a JSON receipt never makes its assertions true.

The coordinator sees only constructor public exports and public operation
outputs. Before any public-path read, compare its canonical path/inode against
all four known owner backup paths and reject traversal, symlinks, hard-link
aliases and descendants of private owner directories. Owner operations execute
only the selected one-backup launcher. Never capture private argv or publish raw
worker stdout/stderr; exact public schemas/count-only summaries are exported.

1. `four-wallet-bootstrap/new_trial.py` creates four owner directories and only
   public `TRIAL.json`/owner exports. Reuse its one-command constructor; setup
   is not part of identity creation. Local controls and the live trial differ.
2. `entry_cli.py prepare`, `run_signer.py` for A/C independently, then
   `entry_cli.py combine` derive actual fee/allocation and exact signed GN2.
   The coordinator never opens either signature worker's backup.
3. Fixed `four-wallet-chain/fetch.mjs` obtains Full accepted-prefix/current
   observations. Fixed `chain_replay.replay_bundle` performs SDK page/body/
   context/header checks, strict GN2 and fresh financial/native replay. Neither
   `FETCHED_PENDING_REPLAY` nor submission acknowledgment is confirmation.
4. Fixed lifecycle owner launcher produces two public components and B/D local
   pending-receipt count ACKs. Root's approved scheduler owns private and outer
   proving. The runner accepts only exact selected final public outputs.
5. After accepted settlement and coordinator/proving-service loss, launch four
   independent owner recover/prepare operations. Each uses its own backup and
   a freshly acquired accepted head/context with real DAA. Stage ordinals need
   not disclose owner order; the private controller's mapping is not published.

## Journal and transitions

An exclusive, durable intent precedes the only network submission. Journal and
raw control records stay outside Git under the fresh trial directory. Each
intent binds trial/profile/descriptor, stage, complete native validation case
SHA, recomputed transaction ID, exact fee/body-budget data, prior accepted-head
evidence and selected submit source. Transaction ID alone is insufficient:
version1 excludes compute budget and signature bytes from that identity.

Use one intent record per closed stage, protected by a process lock. Under the
lock, read existing records, reject corrupt/partial intents and duplicate case
IDs/stages, create the new file exclusively and fsync file+directory. A crash
after reservation leaves an attempted/unknown operation that cannot be sent
again. No automatic resubmission, marker deletion or journal reset exists.
Read-only reconciliation validates the actual complete accepted body. The
immutable intent digest remains a send/audit record, not recovery authority.

Normal stages are `funding`, `settlement`, then `exit-01` through `exit-04`.
Each next spend requires its immediate predecessor's verified accepted physical
head. A source mode or arbitrary receipt JSON cannot replace that validation.
After settlement, four accepted independent exits and reserve zero are required.

An explicitly chosen abort branch permits original A/C private fallback after
accepted funding, with fresh accepted state and no assumption that a failed
RPC means no transaction was accepted. Its stages are `fallback-01/02`; it may
close the initial owners' reserve but cannot count as a four-wallet payment
rehearsal. It creates no admin path and never reuses a failed broadcast attempt.

## One-shot submit preflight

Before durable intent, execute the exact generic native validator on the whole
public signed case. Require Full/all input engines and recomputed official
ID/mass/SDK roundtrip. For GN2 also call the strict selected entry contract; for
W require actual selected W prior context and fixed semantic replay against the
fresh accepted prefix. Retain all budgets, signatures and input context bytes.

Connect only to selected credential-free WSS TN10 RPC. Verify synced/indexed
selected network/runtime, query exact input UTXOs immediately before submit and
match outpoint, amount, script, DAA, noncoinbase and no-covenant fields. Capture
a recent accepted birth anchor before funding. A preflight connection/query
failure performs no submission and does not invent empty state.

Only then reserve the intent and make one `submitTransaction` call with
`allowOrphan:false`. A transaction-ID response is `RPC_ACK_ONLY`. Any error or
uncertain response is `RECONCILE_READ_ONLY`; intent remains. Confirm exclusively
through the existing accepted-prefix/currentness pipeline. Exact actual accepted
case bytes (including v1 budgets/witnesses/contexts) must join its retained Full
pages and pass fresh native and financial semantics. A same-txid valid unsigned
budget or witness variant may differ from intent bytes while preserving all
intended source/header/profile/roots/NoteCF/output/fee/conservation effects.
Record `INTENT_VS_ACCEPTED_BYTES_DIFFER`, both complete case SHAs, actual
mass/budget and the matching financial projection; never mutate the intent or
resubmit. History has no reference100/new-budget fee-equality rule. Txid alone
is still insufficient proof of actual accepted-body integrity.

## Completion and accounting

Record only integer sompi. Ordinary sources equal ordinary change plus entry,
settlement and all exit fees plus native payouts. Require original two inputs,
two genuine components, four distinct final owner recoveries and four accepted
private exits, zero reserve, final A/C historical counts2 and B/D counts1, all
spent and one actual derived payout key per owner. Raw owner-to-position/payout
maps and private filesystem paths remain private controller data.

Node views are non-atomic and trusted; this proves no independent consensus or
permanent currentness. A lifecycle success is separate from the failed privacy/
2% targets and independent retention. The source-only tests exercise public
stage/lock/duplicate/stale-head/accounting controls; they are not chain/native
acceptance or genuine proofs. Live readiness requires actual confirmed payouts.

## Before code/run

Root and independent lifecycle reviewer ACK this interface before new code.
Then meaningful public controls cover duplicate/concurrent reservation, crash
uncertainty, same-txid changed budget/witness, wrong trial/profile, stale heads,
invalid branch order, forged acceptance, corrupt/missing journal and complete
fee accounting. Actual submit/owner/proof/network execution stays separately
released by root after the full local rehearsal and source/asset review.
