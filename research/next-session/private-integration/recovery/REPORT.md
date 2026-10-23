# Recipient and recovery result

**25/25 checks passed in one frozen offline run.** The reference restores a
receiver from its pre-payment seed, decrypts genuine sealed-box receipts,
independently regenerates both private/native ownership fields, rejects unsafe
normal credits and reconstructs current membership/NF witnesses. This is not a
confirmed exit, a proved private payment or independently accepted KAS backing.

Baseline: `0c2f4c788a4274b381c4838e05cce5e9c32e8536`. New domain:
`9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c`.
The [shared contract snapshot](CONTRACT-SNAPSHOT.md) was reviewed before the
[nine source/test members were frozen](PRE-RUN-MANIFEST-01.json), SHA256
`1c5d9f720762d3485b710fdc8f99982d5333d72ba35746ec1eac6390345ff27a`.
The runner rehashed all nine members before and after execution; no drift.

## What was checked

- Established crypto: RFC4231 HMAC known answer; libsecp x-only known key and
  invalid scalars; real crypto_box seal/unseal with fresh ciphertexts, tamper
  rejection and wrong-recipient rejection. No Python elliptic-curve or custom
  encryption/authentication implementation.
- Old backup: seed saved before receipt recovers an encrypted invoice index of
  `2^64-1` without a public index tag, issuance log or index lookahead. All O,
  incoming, K and nativePK values are rederived before credit.
- Receipt acceptance: canonical lengths/magics, integer floor/MAX boundaries,
  substituted owner/incoming/K/nativePK/domain/index, sender-chosen K under a
  matching CM, wrong accepted CM and already-spent positioned NF. Decryption
  and CM equality alone cannot credit the sender-substituted credential.
- Reuse without freezing: distinct rhos or repeated CM at distinct positions
  retain every owned liability/NF. Only the earliest valid canonical position
  receives ordinary credit; later reuse is flagged. Earlier and later unspent
  positions retain owner action handles; a sender cannot revoke prior authority
  by publishing an unsolicited duplicate. Spent historical use is not forgotten
  on restoration. Duplicate positions and out-of-order archives reject.
- Current public data: missing receipts, substituted archive data, wrong roots,
  counts/domain, invalid indexed links/sentinel/duplicates and replay domains.
  The source uses new `m <=2*n+1` counters, with no inherited parity or `m<=n`.
- Exit witnesses: current CM path, authenticated current NF predecessor,
  intermediate root after predecessor replacement and empty append path against
  that intermediate root. Wrong domain, noncanonical/out-of-range position,
  explicit zero-NF boundary injection and invalid successor counters reject.

The [test log](attempt-01/tests.log) and [machine result](attempt-01/results.json)
retain all 25 methods. The zero-NF case is an explicit injected boundary test,
not a claimed real HMAC preimage. Independent review identified the four witness
boundary checks before the first run; they were fixed and reviewed, then tested
as methods23–25. The reviewer acknowledged the fixed source without rerunning it.

## Durable-data reference and observer exports

The static supplied snapshot has three genuine encrypted receipts: Bob indices7
and8, Alice index0. Restored Bob discovers positions0 and2, total360,000,000
sompi; the foreign receipt is not credited. Two current witness sets are rebuilt
after the modeled service-off point, with no service or withdrawal-authorization
input. They are independent reference witnesses against the same supplied state,
not sequential accepted transactions.

The accepted state and archive hash are explicitly
`SYNTHETIC_ACCEPTED_STATE_AND_ARCHIVE_PIN`. The out-of-band ciphertext archive
digest is not a native chain commitment. A real private operation must bind its
actual ciphertext hashes in Auth484; full accepted history, publication and
durable availability still require independent qualification. This reference
neither replays a ledger nor validates founding/backing history.

Observer inputs and truth are separate:

| Artifact | Role / SHA256 |
| --- | --- |
| [Public wire](attempt-01/public-wire.json) | Ordered CM/ciphertext data, synthetic historical NF entries and explicitly unbroadcast revealing openings. `ed9abae489e5f01104ae33257cbb8a33b1349930f6157be2d2cdaf877144a10f` |
| [Invoice directory](attempt-01/invoice-directory.json) | Separate named-directory observer; two Bob invoices and one Alice invoice. `7062d63058cc4eaf45ae45355ade4d4e67ab3e39cd01dbf75fd2f9afc9024571` |
| [Synthetic truth](attempt-01/synthetic-truth.json) | Public development secrets/labels, deliberately excluded from observer input. `ddcfc23d090c007d15bfcbd8c51ca28bc19b6b5f53f63443eceae13c71f0da49` |
| [Known answer](attempt-01/known-answer.json) | Public cross-language seed/key/CM/NF vector. `f2b5fdea19f26ac01f9b57c0eddbc589e821237184c381c984e6b00b7e743e47` |
| [Current witnesses](attempt-01/reconstructed-witnesses.json) | PUBLIC synthetic revealed-k data, no transaction/signature. `a63a734cadff3ab69b7680bf8356d9a7b4392bd2bb3c565799305bddaf290d3c` |

These files are public test fixtures marked DO_NOT_FUND. The trace is not a
private-proof history or a financial-privacy qualification. Arithmetic payout
fields are not relay fee quotes or accepted native outputs.

## Resources and retained setup failure

The first build launch failed before compilation because the user-systemd PATH
did not contain Cargo: exit127, ~7ms CPU. Its [unit record](build-01-unit.txt),
[resource output](build-01-resources.txt) and journal are retained. No tests ran
and no source changed. The corrected launch selected absolute toolchain paths.

| Work | Actual wall / CPU / memory |
| --- | --- |
| Corrected offline bridge build | 8.08s wall,15.86s CPU; max process RSS362.8MiB, systemd group peak671.3MiB |
| Frozen tests and trace export | 0.88s wall,0.89s CPU; max process RSS33.4MiB; swap0; network namespace isolated |

Both launches and the run had2CPU/2GiB caps with swap disabled. No GPU was
needed for receipt validation. The compiled bridge is outside Git, binary hash
`6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff`.
[Cleanup](CLEANUP.json) records all three main PIDs zero and cgroups empty or
removed. The test run exited0; no failing semantic result was discarded.
The initial cleanup collector mistakenly resolved an empty systemd ControlGroup
to the cgroupfs root. Its misleading inspection is retained separately in
`CLEANUP-INITIAL-CGROUP-PATH-ERROR.json`; the corrected collector treats the empty
unit group as removed and records no remaining unit processes.

## Remaining limitations

The domain-stable delivery key links observed invoices and revealing openings.
Reused k can reveal associations for multiple positioned notes. Seeds plus
accepted-chain data cannot recover orphan-only secret publication or guarantee
that a restored invoice issuer never reuses an orphaned index. A monotone
disclosure/issuance journal and actual archive availability remain requirements
to investigate; this run does not qualify clean privacy after reorg.

The selected receive protocol uses interactive one-time invoices. It does not
solve an asynchronous reusable private address. Passing checks establish tested
reference behavior; they do not establish cryptographic correctness, production
safety, mainnet suitability, testnet readiness or a complete native KAS private
payment lifecycle.
