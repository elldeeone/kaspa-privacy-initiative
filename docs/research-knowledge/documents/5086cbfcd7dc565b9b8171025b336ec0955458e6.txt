Unposted draft for P11/#11:

We reproduced the four-batch outer workload from PR51 at `2525d804` on our RTX 3070 8GB.

The unchanged po2=20 credit-transfer run failed with CUDA out of memory. Capping the host's segment size at po2=19 fixed that; deposit and reconciliation stayed at po2=16. We used the SDK3.0.3 CUDA build for sm_86. The guest image, public inputs, existing inner Groth16 proofs, expected journals, join control and CPU verifier stayed unchanged.

All four fresh Succinct receipts passed separate CPU verification, including 60 cryptographic negative controls. The new exit receipt also passed the local native issuance and restricted payout checks.

- Deposit: 27.7s
- Credit-transfer: 361.5s
- Exit: 172.6s
- Reconciliation: 63.7s

The complete run took 10m27s. Peak sampled matching-process VRAM was 6,096 MiB. Commands, source/build hashes, receipts, raw telemetry and the original OOM are retained with a CPU recheck script.

This is the fixed upstream outer workload with smaller segments, separate from our earlier Orchard wallet experiment. It uses synthetic native fixtures: no funding, TN10 transaction, chain payout or independent recovery was performed.
