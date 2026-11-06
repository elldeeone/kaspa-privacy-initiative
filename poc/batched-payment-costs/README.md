# Batched private-payment costs (offline experiment)

This uses the existing private-note wallet, real encrypted receiving/re-spending,
its complete digest-packed proof relation, real RISC Zero proofs/compression, and
pinned Kaspa Full transaction validation. Every funding UTXO is explicitly
synthetic. There is no RPC, broadcast, paid provider or consensus modification.

The two-payment workload credits Alice 3D, pays Bob 2D, then has Bob decrypt and
pay Carol D. All three restore their backups and finish with D. The comparison
retains separate named exits, batched named exits, and batched whole-set exits.
D is 10 KAS and then 25 KAS for the larger candidate. It is not a general wallet,
a live-chain demonstration or a cryptographic audit.

Read [the frozen selection](../../research/batched-payment-costs-2026-11-06/SELECTION.md)
and [ADR-0109](../../docs/adr/0109-complete-cost-and-batched-payout-test.md).
The complete source relation is copied unchanged from the earlier isolated
payment-set experiment. The original wallet and security invariants are intact.

## Running

The local runner uses the existing checked SDK 3.0.3 CUDA worker and cached
Groth16 compression assets on Forge. Paths and binary hashes are explicit in
`run.py`; a different machine needs those dependencies, not a paid allocation.
No development mode, old image, placeholder seal or unresolved assumption is
accepted as a positive proof. There is no automatic retry or unbounded loop.

```sh
python3 poc/batched-payment-costs/run.py
python3 poc/batched-payment-costs/run.py --resume .local/batched-payment-costs/OLD_RUN
python3 poc/batched-payment-costs/run.py --extras .local/batched-payment-costs/CORE_RUN
```

Each command creates a new ignored UUID runtime and resource monitor. A resume
loads the same synthetic wallet fixture and may reuse a completed genuine receipt
only after checking its exact full public input, current image, journal, SDK
claim and native proof. It never reuses a receipt for changed inputs. Failed runs
stay intact. Receipt reuse is reported and its original proof work is still
charged to the counterfactual comparison.

The extra campaign tests withheld approval followed by a fresh registration
round, restored solo exits, owner-only pending-deposit refund, replay, changed
native effects and boundary cases. A withheld round pays no native fee, but its
actual proof/registration time remains a cost.

Public replay needs the program and public evidence only:

```sh
.local/ci-target/release/kpi-batched-payment-costs replay PROGRAM CORE_RUN NEW_REPLAY_DIRECTORY
.local/ci-target/release/kpi-batched-payment-costs views CORE_RUN NEW_PUBLIC_VIEW_DIRECTORY
python3 poc/batched-payment-costs/score.py CORE_RUN PUBLIC_VIEW_DIRECTORY NEW_SCORE_DIRECTORY
python3 poc/batched-payment-costs/costs.py CORE_RUN EXTRA_RUN NEW_COST_DIRECTORY
```

`score.py` seals baseline and candidate predictions before reading private truth.
Participant disclosure controls then receive their stated extra facts. It retains
all actual native outputs, fee refunds, public state and prover inputs. The
baseline and candidate are separate counterfactual worlds sharing a fixture;
combining a previously published individual destination map with the candidate
is an explicit failure control. Do not claim privacy against someone who already
knows the recipients.

Native fees are exact offline default-relay quotes at the pinned policy, not paid
fees or promises of current inclusion. Prover time, sampled GPU power/memory and
process RSS are measured. USD hourly rates, electricity tariffs and storage
allocation are explicit sensitivities. GPU power is not whole-host power; local
hardware has no provider invoice and still consumes resources. Cold startup,
independent peers, anonymous transport, service margin and retained availability
must not be silently priced as zero.

Keep private backups, native secrets and parameter/runtime files out of Git. The
proving key is public protocol data but is retained only in ignored local storage
for this test; this is not a test of independently available recovery packages.
