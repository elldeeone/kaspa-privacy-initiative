# Three-owner ordinary TN10 acquisition

This is free test-KAS acquisition for the fresh ADR0064 identity. No real funds,
mainnet, old wallet keys or experimental reserve are inputs. Pool founding and
all pool broadcasts remain separate from ordinary mining/consolidation.

## Fixed workload and release

- Fresh trial: `2a93ba31-0220-47d8-a845-369adadd0c95`, three isolated original
  seed backups under the already declared whole private parent. Admission is
  exactly 2,000,000,000 sompi per owner. The private-payment workload remains
  5 KAS per owner in round one and 2 KAS in round two; fees do not retune demand.
- Typed public identity: `public/live-01/FUNDING-IDENTITY.json`, SHA256
  `3a119ca2cf6c71324dd35f5063000179620066f03800cf70933e128da5ef127a`.
  SDK-derived addresses match each owner's public funding key at existing
  invoice index `0xffffffff`. The ordinary funding key is distinct from note
  payout keys. No seed, backup hash or private scalar is in this document.
- Mine separately to each of the three ordinary P2PK addresses. Target is
  3,100,000,000 observed coinbase sompi per owner: at least 93 free test KAS in
  total, including ordinary change and fee headroom. Mining does not admit money
  to the experimental pool.
- Run one party at a time with 12 existing SDK CPU workers; do not overlap three
  twelve-worker miners. Root releases this only after the round-two CPU proving
  jobs have ended. No GPU software or node daemon is installed.
- A positive source review is not a live release. Root explicitly releases
  mining; later consolidation and pool founding each retain their own release.

## Mining checks and restart behavior

`run_miner.py` defaults to preparation. `--plan` only reads the current template;
`--execute-mining` enables block submissions. The child receives only selected
Node/SDK/source, the fixed public identity and its own fresh block journal. No
wallet backup, seed, funding key, proving key, host home or Docker socket mounts.

The live child checks synced/indexed TN10 version 2.1.0, verifies the template's
coinbase reward script against the selected own address, preserves the entire
raw block except nonce and independently rechecks found work before submission.
Each block hash has a durable intent and at most one RPC submission. Unknown
responses are queried by hash; the original block is never resent. Observed own
UTXOs, not submission acknowledgements, decide whether the reward target exists.

Before starting a mining child, the parent durably consumes the trial/party
attempt in `private/funding-registries/TRIAL/party-N-MINING-USED`. A new controller
directory cannot reset it. Marker and new ancestor directory entries are synced
before the child starts. An interrupted used attempt permits read-only reward
reconciliation; a new mining attempt requires a fresh unfunded trial identity.
The child stops at its observed target and terminates every owned worker.

## Maturity and ordinary self-consolidation

`collect_funding.mjs` is read-only. It retains exact current coinbase outpoints,
amounts, P2PK scripts and birth DAA, and requires at least 1,000 DAA maturity.
RPC integer amounts cross the JSON boundary as canonical decimal strings and
are converted exactly once to Python integers before financial comparisons.

`run_consolidation.py` mounts one original owner backup and public observation
in a network-off child. The owner verifies all source scripts, unique points,
coinbase flags, maturity and the exact reference-rate-100 native fee. It derives
only its own reserved funding key and signs every input with Schnorr ALL.
The only output is ordinary change back to that same funding key; no other
owner, pool covenant or foreign destination is permitted. SDK safe roundtrip
and actual Native Full/all input engines must pass. Only the signed public
case and typed metrics are exported; the parent never reads backup bytes/hashes.

`chain/submit.mjs` runs the fixed native preflight, rechecks the exact current
inputs and coinbase maturity, durably reserves trial/stage and transaction ID,
then makes one submission request. Fresh controller directories or a different
stage cannot forget the same trial transaction. Both reservations precede the
network write. Unknown responses require read-only reconciliation. A successful
acknowledgement does not establish confirmation.

Every ordinary acquisition fee is retained separately and included in the
complete lifecycle ledger. Actual fresh ordinary outputs become the three GN3
sources only after confirmation/readback. GN3 publicly includes all three full
initial Note168 records; its strict parser recomputes each CM, initial roots and
native reserve from those actual values before accepted-history admission.

## Evidence and limits

Three genuine local seed-owner consolidations each signed eleven supplied
coinbase inputs and passed actual SDK/Native Full checks. These are nonexistent
local source contexts, not mined funds or accepted transactions. Actual live
read-only template plans verified all three fresh funding reward scripts.
Boundary controls reject immature, wrong-owner, duplicate, malformed and wrong
domain sources; restart controls reject consumed mining/submission attempts.

Validating RPC, authenticated transport, selected software/host, non-atomic
observations and retained public data remain assumptions. Distinct endpoints
do not prove independent administration or consensus. None of this establishes
financial privacy, long-term data availability or a completed pool lifecycle.
