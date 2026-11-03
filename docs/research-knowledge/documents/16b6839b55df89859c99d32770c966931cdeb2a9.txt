# ADR-0016: Four-wallet shared pool and withdrawal comparison

Accepted for an owner-authorized bounded TN10 experiment on 2026-10-19.
No production architecture choice, mainnet, commits, pushes or posting.

Extend ADR-0015 using the same pinned Kaspa v2.1.0 native primitives and standard
P2SH reserve. One reserve, 24 append-only commitment/nullifier slots, five private
transfers, three later deposits, and full or partial withdrawals. Slots bound
this experiment; full exits remain possible when commitment capacity is reached.
No operator signature, sponsor, new token or consensus change is introduced.

Bootstrap: Alice funds the sole initial note and makes the first valid private
spend. Only then can independent depositors join. The first spend still proves
initial note value equals the native reserve. A deposit before this proof is
rejected: joining users never need Alice's secret to check initial backing.
Wallet history validation requires exactly one initial commitment and zero
nullifiers; a forged descriptor cannot skip this bootstrap check.
This initialization dependency is explicit; it gives Alice no later authority.

A deposit consumes reserve input 0 and the depositor's ordinary signed input 1.
It preserves all existing notes/nullifiers and creates one encrypted note with
value = external input - transaction fee. The reserve increases by exactly that
credit. Native signatures authorize the depositor's input; the proof binds both
outpoints, amounts, input-1 script and actual new reserve. No existing claim pays
the depositor's fee. Other operations have only the reserve input.

A transfer consumes one private note and creates two. A partial withdrawal
consumes one note, creates one private change note, and pays a public P2PK output.
A full withdrawal creates no private note. Each balances private and native
values including the actual fee. The last full exit proves exhaustion and leaves
no reserve. Payout keys are independently derived per domain/step with standard
HMAC-SHA256 and valid secp256k1 rejection sampling, avoiding address reuse.

Each wallet process validates public history, scans ciphertexts itself, proves
locally and receives only its own wallet file and public artifacts in a network
and PID-isolated namespace. Public parameters are loaded and validated once per
process, never trusted by bypassing curve checks. Public transaction relay needs
no wallet secret. This is artifact-dependent recovery, not history availability
after arbitrary pruning. Single-party Groth16 setup remains experimental.

Pair two fresh instances with the same private workload. Fund four test wallets
from the same known synthetic source; do not call them independent real users.
Alice→Bob 4; Bob→Carol 3 using the received note; Carol→Dave 5 using Carol's
deposit; Dave→Alice 2 from the received note; Alice→Bob 1 from the received note.
Each participant first withdraws one selected note: fully in arm F, or 0.25 tKAS
with private change in arm P. Then everyone independently drains their remaining
notes. Fees differ because P requires extra withdrawals; this is part of cost.

Observer sees actual chain transaction bodies and public spent-output context,
and the protocol encoding. No manifest wallet labels, private schedule, keys,
notes, note-selection records or process logs are inputs. Scoring alone reads
hidden ground truth. Analyze first-withdrawal and complete-drain horizons using
integer conservation/temporal candidate constraints, plus a recency heuristic.
Score exact consumed-commitment and deposit-ancestry candidates, not human-name
anonymity. Count singleton coverage, correctness, remaining candidates and ties.
State separately what timing sensitivity assumes, versus actual TN10 timestamps.

Require circuit/adversarial native validation, exact SDK round trips, all exit
proofs and isolated wallet execution before any funding. Run actual TN10 payouts
and preserve exact receipts and fee totals. Stop a used identity on failure and
start a fresh identity for a retry; never weaken accounting or proof checks.

Reuse established note/nullifier/encryption patterns from ADR-0015 and mature
protocol sources refreshed in the research note. Defer trees, batching, padding,
network anonymity, services and wallet UI until the bounded result warrants them.
Full-vs-partial leakage is an empirical hypothesis, not a promised improvement.

Wallet acceptance rejects any unspent note or new private output smaller than
the larger configured full-exit fee plus 0.1 tKAS. The positive payout floor
avoids native storage dust at the observed 100 sompi/gram rate. This is a wallet
policy for the trial, not a circuit guarantee under future fee conditions.

Execution evidence: both funded arms completed on 2026-10-19. The bounded
comparison supports retaining private change for further work; it does not
resolve adversarial liveness or establish real-user anonymity. Results, costs
and the precise observation boundary are in the
[trial report](../../poc/shared-pool/README.md).
