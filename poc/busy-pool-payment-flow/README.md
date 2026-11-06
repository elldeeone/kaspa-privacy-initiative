# Busy-pool payment flow

Offline research harness for [ADR-0112](../../docs/adr/0112-busy-pool-withdrawal-scheduling.md).
It has no RPC, funding-provider or broadcast command. Supplied source UTXOs are
synthetic. Native Full validation is not accepted chain settlement.

Four separate wallet processes keep their own backups and cache the unchanged
public proving parameters. The coordinator receives public wallet operations,
not note openings or spend/view keys. Wallet processes are restarted before
signing spends of their actual native payouts. This is one research controller
on one host, not independent people or a hardened isolation boundary.

The real experiment uses the existing complete depth-four wallet circuit,
fixed-key reusable-intent program, native covenant and genuine RISC Zero
Succinct-to-Groth16 compression. No new guest, setup or consensus rule. Existing
reuse/attribution is recorded in
[the preceding package](../reusable-withdrawal-approvals/SOURCE-REUSE.json) and
[the sources](../../research/busy-pool-payment-flow-2026-11-06/SOURCES.md).

`queue.rs` is an application scheduler, not a bank lock. It freezes each work
item, retains its age on stale retries, and batches contiguous waiting payments.
Only a complete validated transaction can acknowledge an active batch. Another
operator can still win the current-bank race. The harness exercises one such
accepted update during actual proving, rather than pretending pending arrivals
invalidate receipts.

Run with the existing **public** proving-parameter file (not wallet backups):

```sh
python3 poc/busy-pool-payment-flow/run.py /absolute/path/to/proving-parameters.bin
```

The runner copies its executable and freezes its source before creating a fresh
ignored `.local` identity. It measures all proof work, including the genuine
competing proof prepared before the timed race and the discarded stale receipt.
The two scheduler continuations run sequentially on the same GPU; the reference
reuses the exact accepted prefix and original request bytes, preserving recorded
arrival times in its comparison clock. Both continuations cash out completely.
Group wait starts when the first withdrawal proof starts. Cold setup/preparation
and competing-proof work are reported separately, not silently discarded.

The original race deliberately finishes the obsolete proof as a negative control.
The [additive cancellation check](../../research/busy-pool-payment-flow-2026-11-06/CANCELLATION-SELECTION.md)
tests the operational fix: stop the owned stale worker, then generate and fully
verify the current replacement using the original approvals. It starts only after
the main GPU campaign finishes:

```sh
python3 poc/busy-pool-payment-flow/run_cancel.py /absolute/main/runtime /absolute/main/monitor
```

Its process/detection timing is separate from the original complete arrival
comparison. Public replay swaps only the fresh native proof witness in a temporary
copy and verifies that every native ancestor, child and payout spend still fits.

This queue experiment uses identified local calls. The complete call transcript
is retained; its payout-owner mapping is known. It does not repeat or supersede
the earlier protected-registration experiment or grant it stronger anonymity.
Compare known-owner financial histories separately from payout-key permutations.

Public replay needs no wallet backup, proving parameters or GPU:

```sh
bash poc/busy-pool-payment-flow/check.sh
```

The frozen selection, outcomes and retained attempt history are under
`research/busy-pool-payment-flow-2026-11-06`. A finite fifteen-leaf experiment
cannot establish sustained-load performance, independent recovery or readiness
for a funded testnet trial.
