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

## Evidence boundary

These are observations of the selected validating node with retained public
data, not independently verified PoW/GHOSTDAG consensus or perpetual currentness.
Transport, selected host/software, non-atomic views, available replacement
provers and public data remain assumptions. Distinct endpoint names do not
establish separate administration or durable storage. Local/synthetic SDK and
native controls do not establish actual funding, confirmed payouts, anonymity
or a passing fee target.
