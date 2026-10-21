# Native funding/exit key separation

Status: bounded offline retest passed on 2026-10-20 UTC (2026-10-21 Sydney).
Fresh v2 wallets remove the tested funding/exit script alias and its conditional
payment disclosure. Original-backup recovery and native payout spending passed
for v2 and genuine old-CLI-created v1 backups. Legacy v1 retains the old leak.
This is not general privacy or cryptographic security qualification.

The completed [address-reuse finding](ADDRESS-REUSE.md) is preserved at
`b62cfd1910d77f9962882b1088d6cc718e7df1b2`. The owner authorized the subsequent
wallet correction and offline rerun. [ADR-0030](../../docs/adr/0030-separate-funding-and-exit-keys.md)
records the decision, [the source review](../../research/shielded-kas-native-key-separation-2026-10-21.md)
records reuse and limits, and [the prospective specification](ADDRESS-KEY-SEPARATION-SPEC.md)
fixes the workload, observer and success/failure criteria before execution.

## What changed

Fresh v2 backups derive native funding keys with `KPI/funding-key/v1\0` and
retain `KPI/payout-key/v2\0` for exits. Exact domain/index/retry encoding and
scalar rejection stay unchanged. ADMIT and founder funding use the funding
purpose; EXIT and native payout spending use the exit purpose. The original
backup still contains all required secrets, without an extra recovery sidecar.

Explicit v1 backups retain their old behavior, including the known reuse risk.
There is no automatic migration, metadata reinterpretation or fallback to a
different key purpose. Unsupported format/profile pairs reject. Relabeling an
old backup cannot erase historical funding-to-exit links.

The proof relation, covenant, public replay, note keys/encryption and parameter
identity are unchanged. This is a wallet correction, not a new pool, primitive,
token, consensus change or privileged recovery path.

## Checks completed before the trial

- 18 wallet tests, two native derivation tests and 15 public replay tests passed
  using Rust 1.95.0 with locked, offline release dependencies.
- The three release binaries built; targeted Rust formatting and diff checks
  passed. Package-wide formatting reports pre-existing differences in unrelated
  files, which were preserved.
- A second author-team reviewer independently reproduced 14 HMAC known-answer
  vectors and 12 distinct x-only P2PK scripts. The legacy payout method body is
  byte-for-byte unchanged. Exact profile rejection, wrong-purpose admission and
  signed native recovery checks cover both profiles.
- The unit scanner fixtures explicitly use placeholder proofs. They test local
  selection/recovery behavior, not accepted pool transitions. The native trial
  below is required to supply genuine proof/replay evidence.
- The frozen evaluator passed seven control groups and replayed the historical
  leaking case. Its unchanged observer again forces sender 0, recipient 1 and
  1,920,000,000 sompi only in the final linked profile. These published control
  inputs are calibration, not a fresh held-out sample.

Finite vectors do not establish cryptographic security or cover the invalid
scalar retry branch. Author-team review is not an external security audit.

## Frozen native and privacy test

The trial uses ten fresh proofs: a shared founder bootstrap and three operations
per arm. The two v2 arms share fresh keys but use funding indices 3 and 0; both
exit at index 3. A third arm uses a genuine v1 backup freshly created by the
frozen old CLI, then admitted, restored and exited by the new wallet. No previous
wallet secrets are reused. The original backup must remain byte-identical;
fresh processes must scan receipts, generate an exit and sign a native payout
spend. Native UTXO/index discovery is outside this test: payout index 3 is supplied.

Each arm must reconcile 32 tKAS entering = 30.4 payout + 1.6 pool fees, with zero
reserve. Ordinary-parent/founding and later payout-spend fees are separate.
All ancestry and expected heads are synthetic/offline. No funds, broadcasts,
new setup or chain-acceptance observation are involved.

Each observer receives one arm's five public input files only. It sees neither
other arms nor backup version, private indices, selections, receiving envelopes
or truth. All three predictions must be sealed before any fresh truth scoring.
The later combined export is not a valid isolated observer view.

| Arm | Selected funding/exit scripts equal? | Original-backup recovery, exit and payout spend | Unchanged observer result |
| --- | --- | --- | --- |
| v2, equal index | No | Passed | Sender, recipient and amount ambiguous in all four profiles. |
| v2, different index | No | Passed | Sender, recipient and amount ambiguous in all four profiles. |
| Legacy v1, equal index | Yes | Passed | Only final history with the equality link forces sender 0, recipient 1 and exactly 19.2 tKAS. |

All ten genuine proofs, three native histories and their independent replay
passed. Each reconciles the stated 32 = 30.4 + 1.6 tKAS with zero reserve.
All original backups stayed unchanged, and old/new binaries returned identical
legacy funding information. Eight invalid requests were rejected; the two
wrong-purpose helper controls were separately checked for the exact intended
ownership error, not merely a nonzero exit code. All 45 native process guards
passed. The whole native experiment took 2,437.8 seconds, including nine fresh
prover loads; this is not a per-payment latency measure.

All three prediction files were sealed before the batch seal at
`2026-10-20T23:50:22.805686+00:00`. First private scoring began at
`23:50:22.877000+00:00`. Actual truth satisfies both original encodings in all
three arms. The historical public positive control also retained its expected
final linked disclosure. No solver timeout, unknown, disagreement or failed
native trial was hidden or resampled.

A second author-team review independently checked all 180 saved satisfying
assignments across the 12 fresh profiles and four historical-control profiles.
It reran candidate feasibility and unrestricted alternative infeasibility for
all six forced facts in both original encodings: 24 solver checks passed.
Direct script comparisons, all eight intended rejection causes, source pins,
process guards and prediction/scoring order also passed. The reviewer did not
read private truth or backups. This checks the stated experiment/model; it is
not an external cryptographic audit or a stronger privacy model.

The causal conclusion is narrow: the same economic schedule no longer gives
this observer a script-equality owner link for fresh v2. Its abstract alternatives
remain feasible. That does not assign anonymity probabilities or establish
protection against a stronger observer, other traffic or broader amount/timing
inference. Supporting artifacts are in the
[public evidence directory](evidence/2026-10-21-native-key-separation/README.md).

## Identity and reproduction

The tested candidate is base `b62cfd1` plus the frozen source manifest and patch,
not that commit alone. Source freeze covers 76 files, including the old/new
binaries, Rust, scripts, specification and design/source documents.

| Item | SHA-256 |
| --- | --- |
| Tracked source patch | `d5af81eba645a60c600d74a3608e57a9594b2295c80aae441bdb92ee7946595f` |
| Source manifest | `98becd821ba265ed646e5fe03637777251b2f934baf4286f70bf0ad2791cb115` |
| New wallet binary | `46881998a63c5fbb10bfc1dc1a4d3679cd29c7d1639cfb618eccee2cfe11b8b9` |
| New lifecycle binary | `0687afcf9cbdf0fdbf1b1cf418ef7239ca18e8b52a0813895e3c774abcc4a9ac` |
| New replay binary | `c129c62e22f55fed240660e49e28da6dcd247f3e3ab2f14c23a190d7b1b0c827` |
| Evaluation freeze | `f201c632b9a9211e6d7c0fc66c31444f1c362fc836386f7c5fa59afab8f750f2` |
| Prospective specification | `15693faa2814c5185568673a70754de57b9e7383a99f6837d0008c45eae02940` |
| Prediction batch | `f5ea751e217b0b5a4d3caa5aa15e0e52e5bc83468408dacf21e3a0c8e6d21c69` |

The [specification](ADDRESS-KEY-SEPARATION-SPEC.md#execution-order) gives the
execution order. Reproduction needs the pinned public proving parameters and
historical wallet executable, plus the exact frozen source revision. Preparation
completed at `2026-10-20T23:07:30.459701+00:00`, before fresh wallet generation.
The local native attempt is `bbecfb09-f68d-43da-9eb3-73af7a8e512b` and the local
evaluation directory is `/tmp/kpi-key-separation-eval-20261020-01`.
All 76 frozen source/binary files and the tracked patch matched before/after the
trial. Result documentation was updated afterward; copied prospective documents
retain their original identities in the evidence. Redacted export summaries,
freeze and batch are explicitly marked derivatives with original-source hashes.
Predictions and seals are byte-exact. Private backups, complete truth and wallet
views are not exported; declared fixture choices remain in the frozen spec/code.
An additional private comparison found none of the nine fresh master secrets or
the founder's note randomness in the public export. No secret values were
printed or saved by that check. Allowlisting and this check do not prove absence
of every possible side channel.

## Limits

The observer retains the prior diagnostic's funding-owner associations and known
self-bootstrap assumptions. Those are not general v6 circuit guarantees.
Without the startup assumption, the stronger sender-uniqueness conclusion does
not follow. Alternative arithmetic histories are not alternative openings for
fixed commitments, probabilities or a cryptographic indistinguishability result.

Removing this script alias cannot establish real-world anonymity, the 32-role
privacy target, general legacy compatibility, automatic native coin discovery,
honest setup, accepted-chain recovery or production safety. Amount/timing and
other ownership information remain separate attack surfaces.
