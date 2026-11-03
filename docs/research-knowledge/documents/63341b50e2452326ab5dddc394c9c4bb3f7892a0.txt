# Complete confirmed TN10 rehearsal

**PASS: all six native transactions and both payouts confirmed on TN10.**
Trial `e406aff3-442b-4493-a778-68af2dec4cc7` uses fresh private OS randomness,
domain `42fab9c9042a1fbf0e0ef7755cb04df8a79ce32b6715bdd600a3deb100bfe827`
and a corresponding new development setup. No public fixture or old S7
identity/key/workflow was funded or reused. Only free test KAS was used.

## Actual lifecycle

| Stage | Accepted transaction ID |
| --- | --- |
| Ordinary source preparation | `62b5534d5131e1ea4f2ef3201a47d528ab93332a805031d89465748ac639b737` |
| Coherent singleton founding | `c465b6786e7e0e5de53cd75017a2916cc306ce6762956bcc4500eded1b0de635` |
| Native public admission | `3a60f18f6ae4aff91d36f2dfed67a61a44ee5e974cef5c910bf4b1004be13733` |
| Genuine private payment | `53332868b16c7969e8a8ba4ede79177773941df7c9108c132abddd298fba9190` |
| Bob continuing exit | `3f29dd0ff69656d73489b3f2dbb8b19606e44af7cbba74a05d88fdda39a4d809` |
| Charlie terminal exit | `bcef652b49c5bc04683623a18c772f97d86f455505f20128c5a18f380ee07a99` |

Each canonical accepted body matches the exact locally Full-validated body and
every populated input context matches its outpoint, amount, version-zero SPK,
noncoinbase status and absent covenant ID. All six exact prior-output links were
checked. Actual future input DAA scores are retained; local placeholder zero
was not falsely compared with an unknowable future acceptance score.

Bob receives **95,026,200 sompi (0.950262 KAS)** at exit output1. Charlie receives
**95,036,800 sompi (0.950368 KAS)** at terminal output0. Fresh terminal observations
requery both exact owned UTXOs and the consumed reserve inputs after a checkpoint.
Recorded final blue-score depths are 755 and 314, both above the chosen 20-unit
minimum. No removed chain blocks were reported. Final state has four CM records
and five NF records: sentinel, two private NFs and both original revealing NFs.
**Every positive liability and the reserve are zero.**

Both recipients recover their 100,000,000-sompi notes from seed-only backups
created before invoices. Five actual NETWORK recovery verdicts pass: both
recipients after private acceptance, Charlie after Bob's accepted exit and both
after refreshed terminal payouts. Each checker process mounts only its owner's
backup, public archive/identity, crypto bridge and public source. Neither payer
secrets, the other recipient, PK nor prover are mounted. The resident prover is
stopped before the separate native exit workers. A selected validating node and
retained public archive remain explicit trusted inputs.

## Exact accounting and resources

Source **306,866,100** = ordinary source change **79,848,700** + Bob payout
**95,026,200** + Charlie payout **95,036,800** + native fees **36,954,400** sompi.

| Operation | Fee, sompi |
| --- | ---: |
| Preparation | 3,198,300 |
| Founding, no change | 217,300 |
| Admission | 4,850,400 |
| Private payment | 18,751,400 |
| Bob exit | 4,973,800 |
| Charlie exit | 4,963,200 |

This is a separate **two-1-test-KAS-note liveness pilot** funded from the available
ordinary test-only wallet. It does not meet fee targets and does not replace the
favorable offline two-10-KAS/no-change fee result. All source change and exits are
counted; no liability was dropped or hidden subsidy added.

Fresh identity creation takes 0.13 seconds in the recorded runs. Fresh setup
takes 21.49 seconds, or 24.82 including official uncompressed serialization.
The resident fresh-domain proof takes 14.96 seconds with 14 workers available;
this is not four-core or p95 qualification. All six native Full checks and six
lossless SDK roundtrips pass before submission. Integer sompi is canonical;
native u64 values are converted losslessly before JavaScript/SDK use.

## Evidence and remaining limits

- [Complete result](accepted-01/CHAIN-COMPLETE.json),
  [exact release](accepted-01/chain-release.json),
  [extraction map](accepted-01/EXTRACTION-MANIFEST.json).
- [Independent recovery closure](recovery/network-closure-01/REPORT.md),
  [local body validation](accepted-01/local-native),
  [actual accepted bodies](accepted-01/chain-public/bodies).
- [Confirmation semantics](confirmation/CONFIRMATION-SEMANTICS.md),
  [activation source check](confirmation/ACTIVATION-V2.1.0.md),
  [adapter API](../../../poc/future-native-chain/API.md).

The exported observations omit unrelated `pages` of FullV2 chain history while
retaining each selected accepted body, populated inputs, accepting header,
depth, queried outputs/inputs and removal result. Exact original response hashes
are recorded; originals remain local. Derived archive hashes refer to those
explicit excerpts. No fresh private seed, private fixture/vector/rho, PK/cache or ELF is
published. Public verification keys, proofs and signatures are protocol data.

This closes the bounded native payment **mechanics** through confirmed test-KAS
payouts. It does not establish strong financial privacy, independent consensus
or network recovery, durable DA, reorg finality, setup honesty, a security audit,
general fee compliance, wallet resource targets or production/mainnet safety.
The prior privacy failure and all failed prover/fee/control predictions remain.
