# Integrated owner-private native KAS lifecycle

**Financial completion: 2026-10-25. Research and TN10 only.** One coherent
profile completed actual native backing, two genuine private-payment rounds,
original-seed payment/change recovery, nine direct exits after original-service
loss, and further fresh terminal recovery. All nine native payouts are confirmed;
reserve and owned claims reconcile to zero.

**Final public verification is still pending at this prepublication checkpoint:**
the terminal payload/metadata audit, upload observation and public CI HTTPS/
SDK/native replay have not yet supplied their actual execution receipts.
Financial privacy, the 2% fee target and independently administered retention
are separate verdicts below.

## Completed bounded lifecycle

| Gate | Actual recorded result | Boundary |
| --- | --- | --- |
| Native backing | Three genuine ordinary owners admitted exactly 60 KAS under the new GN3/native policy | Test KAS only; selected validating-node observations |
| Repeated payment | Both genuine 3-spend/6-output rounds confirmed, using three 5-KAS then three 2-KAS requests | Frozen 21 KAS useful workload; change/refunds are not extra demand |
| Payment/change recovery | Three fresh original-seed clients recovered accepted R1 history and spent received notes/private change in confirmed R2 | No saved private ownership map required |
| Original-service loss | Original coordinator/MPC, shared R0 and writers quiesced; replacement clients used authenticated downloaded software/history/keys with original paths absent | Same physical host/isolated namespaces; public read-only chain observer remained available |
| Independent exits | Nine owner-local direct proofs settled without another MPC round/shared outer prover; every native Full/input script and exact payout query passed | Complete accepted public bodies, witnesses, budgets and populated contexts retained |
| Terminal recovery | Three further fresh original-seed restores/full-prefix replays/scans passed; all owned claims spent and historical payout keys rederived | Aggregate/cohort checks performed locally; no individual scan exports published |
| Conservation | Twelve pool transactions, 57.888496 KAS native payouts, zero reserve at CM15/NF16 | Not independently verified consensus or a cryptographic security proof |

The selected [financial profile](../../../poc/owner-private-lifecycle/financial-profile.json)
has SHA256 `69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f`.
[ADR-0064](../../../docs/adr/0064-owner-private-native-kas-lifecycle.md),
[RFC-0027](../../../docs/rfc/0027-owner-private-native-kas-lifecycle.md) and the
[contract](CONTRACT.md) define this experiment. Earlier profiles' payouts and the
ADR-0063 unfunded prototype are separate evidence.

## Complete actual fees

```text
9,615,864,283 mined sompi
= 3,611,321,183 ordinary change
+ 5,788,849,600 confirmed native payouts
+   215,693,500 complete fees
+             0 terminal reserve
```

| Fee bucket | Integer sompi | KAS |
| --- | ---: | ---: |
| Ordinary acquisition | 3,874,200 | 0.038742 |
| GN3 admission | 668,900 | 0.006689 |
| Both mixed batches | 39,828,200 | 0.398282 |
| Nine direct exits | 171,322,200 | 1.713222 |
| **All-in** | **215,693,500** | **2.156935** |

Against the unchanged **21 KAS** requested-payment workload, fees are exactly
`431387/4200000`, or **10.2711190476%**. The **2% target fails**. The earlier
supplied-context result remains separate at 10.086633%; it has no acquisition
fees. The denominator is the frozen requested workload, not an amount decrypted
by the public accounting observer.

The [fee-rate finding](fees/FEE-RATE-FINDING-01.md) identifies native compute mass
as the main charge: committed B1800 contributes 180,000 of 199,141 mass units
(**90.3882%**) in a mixed batch. A rate of 100 matches observed node estimates and
pinned standard policy; actual remote admission configuration remains unknown.
No arbitrary 100-fold rate premium was demonstrated.

[Eleven confirmed proof-case measurements](fees/CONFIRMED-ENGINE-BUDGET-01.json),
SHA `9cfb4ecb741c8fe7768a593fb4d36572f4320cc2d785ecbb9bf692b2d36e0289`,
show about 86.52% of allowed script units used by both mixed cases, 82.34% by the
eight continuing exits and 82.16% by the terminal exit. These measured shapes
leave limited trimming headroom; they do not qualify a safe lower budget. No
lower-budget/rate candidate or workload retuning occurred. Reducing verified
compute/withdrawal cost through a reviewed design remains substantive fee work.

## Reviewable public evidence

The [terminal snapshot](terminal-public-evidence-01/README.md) contains exact
copies of all twelve accepted native cases, native validation/metrics and
terminal public metadata. Raw gzip/decoded gigabytes stay outside Git.

- [Final neutral accounting](accounting/PUBLIC-LIVE-TERMINAL-01.json), SHA
  `20171bc5474dff30a70575c5153d04bcff5824f50b675276dc3a175843436079`:
  12 transactions, nine payouts and three terminal scans, exact fee buckets and conservation.
- Final confirmed handoff under external trial parent
  `public/live-01/confirm-exit-09/HANDOFF.json`, SHA
  `8b3188822050fcaee2ffb69870184420da5cc47e91831757c3487e9ae84d3e6c`;
  every actual payout observed and no reserve successor/current entry.
- [Terminal public INDEX](terminal-public-evidence-01/INDEX.json), SHA
  `a530cdfd6dfd8b880b7c9d6818f3cd1e35734a1680aa1430d80258c5bd8fb650`,
  and [public transport selection](terminal-public-evidence-01/transport/SELECTION.json),
  SHA `bdee89b718aa10db629b8260dab0a4ca5af1e4652ef149f2ea5715475bea0b42`:
  whole-byte references/placements, not availability proof before actual upload.
- [Initial complete recovery HTTPS retrieval](availability/ACTUAL-FULL-HTTPS-01.json),
  SHA `a9aa0c700582075e25f3ce7d1a9ed01f56cb4e19c8d4b54cf72aac374472a294`,
  and [cold accepted-R2 replay](availability/ACTUAL-HTTPS-CLOSED-R2-REPLAY-01.json),
  SHA `3f2c4e7ae45f8e06599da125cc55e25cd99e285ab09a090d2a28661b021c1f5c`:
  actual 64-payload retrieval and unchanged native replay, separate from the
  pending public CI terminal HTTPS/native replay.
- [Original-service outage aggregate](availability/OBSERVED-OUTAGE-AGGREGATE-01.json),
  SHA `11d361b4425f0bc877b429481d3bb1712c1845f0b9710c36826b8b573549aa84`.
- [Complete earlier local integration](../../../poc/owner-private-lifecycle/integration/RESULTS-01.md)
  and [native packet](../../../poc/owner-private-lifecycle/verification/native/selected-local-result-01/MANIFEST.json),
  SHA `fdb09d49d03418d0c259bdf36164f3e1cc4cb1fcffcee269f143090c5cba18dc`:
  supplied-context two-round/nine-exit rehearsal plus 16 native rejections.

Publication's `owner_client_associations_selected=False` means **no additional
private recovery-client-to-note/NF/exit/payout association artifacts selected**.
It does not mean public protocol IDs, ordered input labels or existing chain
linkage are absent. Individual READY/restore/scan outputs, their selectors/hashes,
private orders/configs/logs, Root inode baselines and the four raw acquisition
objects remain excluded. Literal canaries are finite checks, not general proof
of transformed-secret absence. See the [public evidence plan](PUBLIC-EVIDENCE-PLAN-01.md).

## Retained operational failures

Relocation/caller-directory startup refusals were retained and corrected without
changing selected financial payloads or weakening checks. After five confirmed
exits, a fractional cache-preparation diagnostic also broke the frozen
integer-only parser. The [separate one-input telemetry repair](availability/integer-telemetry-repair-operator/README.md)
preserved every other typed field and original Source02/v2 capture attribution;
unchanged downloaded complete SDK/native replay passed the eight-case accepted
prefix before three fresh clients resumed. Future Source03/v3 emits integer
milliseconds. This was the same financial trial, with no confirmed transaction
resent. Read-only observer retries/full fallbacks are retained separately from
successful submissions. Source-only control results are not substituted for
actual native acceptance or payouts.

## Privacy and availability remain open

**Financial privacy is unqualified.** The
[source-only marker/input trace](review/FUNDING-MARKER-PARTICIPANT-LINKAGE-SOURCE-01.json),
SHA `bf9f527d8f9fe33badeb57b99deeb75d111145e80e916bfc6e603beb8d3fcbef`,
shows an 88-byte harness payload `KPX8MF01|domain32|trialUUID16|participantID32`.
The same caller-supplied pseudonym enters the public session roster and ordered
READY-validated NF/CV serialization. The selected honest harness therefore
exposes funding→pseudonym→mixed-input linkage. This is not civil identity or
proof arbitrary same-label transactions belong to one person; the pseudonym is
separate from the random wallet seed. No actual participant/NF/payout map was
constructed, and this trace does not itself map shuffled outputs, change,
receivers or terminal payout owners. Omitting the raw ledger/three raw acquisition
cases from Git does not remove their existing chain visibility.

The equal-value workload also leaves a potential one-sompi change fingerprint:
19,914,100-sompi batch fees split 6,638,033/6,638,033/6,638,034. This is an
arithmetic/source finding, not a measured attack. Funding/session/input order,
coordinator admission pairing, fee remainders, timing, amounts, endpoints and
sparse ancestry remain separate channels; removing the MF01 marker alone cannot
close them or establish sender anonymity. The narrower output-grouping mechanism
retains its own honest-party assumptions. The expanded privacy study was not
selected in this execution batch.

Selected host/software, development setup/proof assumptions and validating-node
transport remain premises. Same-host namespaces do not demonstrate independent
custody; GitHub hosting remains under the same administrator. Durable public
history/parameter retention and separately administered storage remain open.
No mainnet, real funds, cryptographic audit or production-safety qualification
follows. The next design question is hiding public and coordinator input
associations while preserving sound Spend/effects/native authorization.
