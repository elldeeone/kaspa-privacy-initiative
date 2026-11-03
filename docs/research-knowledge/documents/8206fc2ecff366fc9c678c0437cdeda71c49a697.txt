# Offline admission and recovery evidence

See [result and reproduction](../../WALLET-LIFECYCLE.md).
Six positive v6 proofs complete the lifecycle; a seventh proof tests malformed
delivery on a separate fork. All ancestry is synthetic and chain acceptance
is unverified. These files establish no real-world privacy or cryptographic audit.

- `positive/`: seven native transactions, including founding; six pool proofs;
  final reserve zero and 32 = 29.6 payouts + 2.4 pool fees.
- `malformed-delivery/`: four native transactions sharing the positive prefix;
  the final genuine proof binds an unusable encrypted receipt. Its additional
  fee is separate from the positive trace.
- [Result](result.json): integration controls, process-isolation observations
  and explicit limitations. Private backup identity is omitted.
- [Synthetic funding parents](synthetic-funding-parents.json) and
  [terminal payout spend](payout-spend.json): public transactions/input contexts
  and separate ordinary fees. No source wallet secrets.
- [Component timings](component-timings.json): preparation, proof and load
  observations; not target-device/p95 qualification.
- [Before](candidate-hashes-before.json) and [after](candidate-hashes-after.json):
  exact candidate hashes relative to `poc/shared-pool`. The first manifest was
  captured during the first parameter load, before the first proof completed;
  all 17 hashes remained unchanged. These manifests cover the executed candidate,
  not a subsequent documentation commit.

From `poc/shared-pool`, replay either directory without private keys or the PK:

```sh
cargo +1.95.0 build --release --locked --offline --bin kpi-two-input-replay
KPI_REPLAY=evidence/2026-10-20-wallet-lifecycle/positive
target/release/kpi-two-input-replay check \
  "$KPI_REPLAY/descriptor.json" "$KPI_REPLAY/vk.bin" \
  "$KPI_REPLAY/lineage.json" "$KPI_REPLAY/parents.json"
```

Set `KPI_REPLAY` to `evidence/2026-10-20-wallet-lifecycle/malformed-delivery`
for the separate fork. Both exported lineages were checked against their recorded
summaries. Public replay checks transaction/proof validity; it cannot establish
private receipt usability, isolation or backup recovery without rerunning the
fresh-wallet experiment. The private diagnostics remain outside Git.
