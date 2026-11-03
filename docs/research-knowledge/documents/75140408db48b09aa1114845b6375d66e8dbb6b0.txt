# GN3 and owner-private native accepted history

ADR0064 is a separate new-domain client. The KPX7 unfunded prototype and prior
GN2/W profiles remain unchanged. These tools never read an owner backup, seed,
spending witness or proving key.

1. `anchor.mjs` selects a recent confirmed pre-funding birth anchor from the
   selected synced/indexed TN10 version2.1.0 node.
2. `fetch.mjs` captures complete decoded Full accepted pages to a fixed confirmed
   frontier, follows unique actual reserve successors and queries exact funding,
   reserve/change and payout outpoints. It reconciles a confirmed post-query
   delta and repeats every exact current query to catch near-tip races. Its
   status is **FETCHED_PENDING_REPLAY**.
3. `verify_bundle.mjs` freshly verifies official SDK transaction/header IDs and
   all complete body/context joins to those retained pages. Version1 IDs omit
   witness/budget, so matching the ID alone is insufficient. Missing, pruned,
   conflicting, substituted or partial data never becomes an empty wallet.
4. `replay.py` runs that fixed SDK stage, strictly derives GN3 from the public
   Note168 records and exact native backing, and executes actual Native Full
   and every input engine on **every** accepted case. It recomputes the selected
   native codec projection and all CM/NF/history transitions, then agrees on
   the exact SDK head/current checkpoint. Outputs are `HISTORY.json`,
   `CHECKPOINT.json` and the retained `RESULTS.json`.

The chain profile argument is the externally SHA-selected GN3 selector. Its
internal `financial_profile_sha256` identifies the selected financial profile;
`selection_file_sha256` identifies that separate selector file. The descriptor
pins the actual initial redeem, trial UUID, funding output0 and birth anchor.
Initial roots are rederived from actual founding bytes, never accepted merely
because an RPC/JSON says they are valid.

Public JSON uses canonical decimal strings at the RPC boundary. `native_case`
converts once to exact Python integers for native financial comparison. SDK,
native executables and fixed application source identities are independently
selected; input data cannot supply a verifier callback.

`replay(..., *, runtime_paths=None, sdk_directory=None)` and CLI
`--crypto/--node/--native-validator/--sdk-directory` allow restored public copies
of the **same pinned bytes**. No hash or financial check is weakened. Defaults
remain compatible, while cold recovery need not depend on original host/cache
paths. The metadata guard checks actual selected paths before the first read.

## Once-only native submission

`submit.mjs` defaults to preflight only. `--execute` additionally connects to the
selected public TN10 RPC. The fixed Python preflight verifies exact native
body/fee/ID/mass and Full/all-input execution. Genesis additionally requires
strict signed GN3; ordinary consolidation permits only mature own coinbases
back to the same P2PK key. Lifecycle submission reruns the fixed accepted-prefix
replay and checks its exact current point/state/reserve against the candidate.

After SDK roundtrip the live process checks exact current inputs and maturity,
durably reserves both trial/stage and transaction ID, queries again and sends
one RPC request. Registries are independent of temporary controller paths.
Unknown response or interrupted used stage permits read-only reconciliation,
never automatic retransmission. The response does not claim confirmation;
fresh accepted-prefix replay and exact payout observations are required.

The fresh `live-01` GN3 transaction `f4aedd3f4221768f16f0898d3f65db5d7519428b9b024ecbb20feb6b0c3a758f`
was submitted once, observed in a confirmed Full accepted page, and passed the
fixed native/financial replay. Its output zero backs 6,000,000,000 sompi; the
founding fee is 668,900 sompi. The retained authenticated handoff is
`public/live-01/CONFIRMED-GN3-HANDOFF-01.json` beneath the selected trial parent.
It pins the exact fetched prefix, replayed history/checkpoint and observed
reserve birth DAA for the next candidate. This establishes this recorded
founding observation; later payment/exits require their own confirmations.

The first semantic replay refused the shared codec's mode0555. The selected
codec bytes were copied, after public metadata/hash checks, to a separate
mode0500 file at `assets/replay-codec-01/native-codec`, preserving the original
shared file and fixed runtime check. The second replay passed. Both the failed
public run and copy receipt are retained; no transaction was resent.

## Confirmed transition handoff

`confirm.py` is the read-only continuation adapter. It calls the unchanged
fresh Full acquisition and fixed SDK/native/financial replay before producing
`HANDOFF.json`. It accepts the same selected public inputs as replay, plus
`--expected-transaction-id`; it acquires the prefix itself rather than accepting
an asserted confirmation. No transaction submission method exists in it.

The expected transaction must be the last accepted pool transition. Every
accepted input must now be spent, and every native payout must be observed at
its exact point, amount and script. The current reserve entry comes from the
newly queried UTXO and must match the replayed point, roots, reserve and selected
policy. Its actual birth DAA is carried as an integer. A terminal replay has
zero reserve and an explicit JSON `null` current entry.

The immutable handoff binds the raw Full prefix and every retained compressed
page, history, checkpoint, native replay result, current entry, public session
set, selector, descriptor, parameters and source pins. It also records measured
acquisition time. An ambiguous submission uses this same read-only path with
the same expected transaction ID; absent or incomplete evidence produces no
handoff and never authorizes retransmission. Subsequent construction consumes
only a handoff whose expected transition and count agree with the campaign.

## Completed TN10 lifecycle observation

The fresh trial `2a93ba31-0220-47d8-a845-369adadd0c95` completed its actual
native-KAS path: three ordinary funding inputs established the 60 KAS pool,
two genuine private-payment batches were confirmed, and nine independently
authorized direct exits paid native test KAS. Each payment batch used the
selected genuine outer proof and actual Native Full execution. The second
batch followed seed-only restoration against the confirmed first batch.

After the second batch, the original coordinator, shared prover and original
writers were stopped. Fresh seed-only clients used the downloaded public
software and accepted data inside closed namespaces to make their direct
exit proofs. A replacement relay submitted each exact candidate once. The
approved public observer retained raw protocol data; the clients and relay
independently replayed it with the downloaded fixed software. This separates
the original-service outage result from any claim of independent RPC
administration or permanent data availability.

The final confirmed transaction is
`c0561fd7a124484476d746a9fbfdc5f8c47e7da43a02c7aa021d2b0dd5c158dd`.
Its handoff, `public/live-01/confirm-exit-09/HANDOFF.json`, has SHA256
`8b3188822050fcaee2ffb69870184420da5cc47e91831757c3487e9ae84d3e6c`.
The complete twelve-transaction pool prefix passed the unchanged SDK,
financial and Native Full checks. All nine payout UTXOs were observed with
their exact amounts and scripts, unspent at that observation. Reserve is zero,
current entry is explicitly `null`, and there is no successor pool output.
The sibling `EXACT-CASE.json`, SHA256
`2d76278601030dac072c858748251e1eea69ebdc02f5d160b629e9e47d7741e3`,
also binds the last accepted case to the exact submitted witness, budget,
gas and populated input entries.

Three further fresh clients then restored the original seed-only backups,
replayed the complete final prefix and passed all three final wallet scans.
They recognized all claims as spent and rederived the native payout keys.
The neutral terminal receipt has SHA256
`1873565f1ad27b9e600a187f39a59a384527f301f3561f6e699f57c1302ed6f9`.
The campaign operator and all 45 owned child jobs completed; no further send
is pending.

Final actual accounting balances 96.15864283 KAS mined into 36.11321183 KAS
ordinary change, 57.888496 KAS native payouts and 2.156935 KAS total fees.
Those fees include ordinary acquisition, founding, both batches and all nine
exits. Against the preselected 21 KAS useful-payment workload, fees are
10.271119%; the 2% target failed.

## Read-only acquisition revisions

The initial full observer retained about 1.59 GB for the first exit. The
reviewed incremental collector reuses only authenticated, completely consumed
MAIN pages and refetches the boundary page. It acquires fresh Full overlap,
current input/payout queries, post-query reconciliation and repeated queries.
Removed blocks, cache substitution, gaps or incompatible coverage require
fresh full acquisition. Every resulting complete prefix still goes through
the same SDK/native/financial replay and exact accepted-case comparison.

Transport failures during exits three and four are retained. A fresh read-only
retry completed exit three; the unchanged full collector on fresh sockets
completed exit four. The next transport revision moved cache preparation
before connection and opened a fresh client for fallback. Its fifth-exit
capture succeeded, but a fractional timing diagnostic was refused by the
frozen integer-only recovery parser before any sixth candidate or send.

The original fifth capture remains unchanged. A reviewed derived copy replaced
only that diagnostic with integer milliseconds, and the downloaded closed
replay reproduced the exact fifth-exit history, checkpoint, native cases and
payouts before fresh clients resumed. Collector Source03 then emitted integer
milliseconds directly for exits six through nine. Neither repair changed a
financial verifier, proof, transaction, fee, workload or once-only reservation;
no transaction was retransmitted. Source freezes, negative runs, the original
and derived captures, and their provenance are retained separately.

## Evidence boundary

These are observations of the selected validating node with retained public
data, not independently verified PoW/GHOSTDAG consensus or perpetual currentness.
Transport, selected host/software, non-atomic views, available replacement
provers and public data remain assumptions. Distinct endpoint names do not
establish separate administration or durable storage. Local/synthetic SDK and
native controls do not establish actual funding, confirmed payouts, anonymity
or a passing fee target.
