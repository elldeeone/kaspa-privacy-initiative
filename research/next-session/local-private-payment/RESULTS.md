# Independent-wallet native KAS payment results

2026-10-25. Research/testnet only. [ADR-0066](../../../docs/adr/0066-local-native-kas-payment-prototype.md)
selects an experimental one-input/two-output candidate, not a production privacy
finding. Domain: `b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c`.

## Completed supplied-context evidence

- Fresh Spend, Output and Exit parameters and genuine proofs passed 42 relation
  checks plus six public-manifest refusals before witness input. Old-domain and
  old-role keys reject. Setup is local OS-RNG trusted setup without an independent
  ceremony; tests do not prove cryptographic soundness.
- A [complete payment](evidence/OUTER-NATIVE-01.json) passed genuine components, the new guest, GPU succinct
  proving, same-claim Groth16 compression and actual Native Full/every-input
  validation. The guest used 271,750,114 user cycles; proving took 1,018.496
  seconds and peaked at 6,096 MiB GPU memory. Its source result SHA256 is
  `23cfdb19575b34f31dcda917c06d9f30ab93f211c17ec0dc3dbb3867d0a61c26`.
  Only the intended native proof witness changed. The exact fee was 19,228,400
  sompi at the selected 100-sompi/mass policy and budget1800.
- All five recovered-note direct exits passed Native Full/every-input and
  independent mass/fee checks, including terminal reserve zero, without the
  outer host/program/prover. Continuing fee: 16,044,400 sompi; terminal:
  16,002,100 sompi at budget1500.
- The [matched public-fixture workload](evidence/MATCHED21-COMPONENT-01.json) completed six payments totaling 21 KAS,
  original-seed received/change re-spends and nine independent exits. Its
  6,000,000,000-sompi supplied reserve reconciled to 5,740,272,300 payout sompi
  plus 259,727,700 pool-fee sompi and zero reserve. This is not paid testnet fees
  or confirmed payouts; acquisition/genesis costs are additional.
- Independent controls include 23 host, 13 mixed-native and 15 direct-exit
  outcomes, plus wallet consent, malformed/replay/conflict/reorg, wrong-seed and
  transport checks. Tor/TLS public reads succeeded on both selected TN10 peers;
  the pinned official SDK also worked through the Tor Borsh bridge.

The native [budget probe](evidence/NATIVE-BUDGET-PROBE-01.json) and underlying retained results
do not change the paid fee: B1600 accepted the existing proof with 447,222 SU
headroom and quoted 17,228,400 sompi, while the supplied case still paid
19,228,400. This is potential, not a demonstrated paid saving. The old 21-KAS
workload and failed 2% verdict remain unchanged. The new six singleton payments
must be compared with the old two three-owner batches, not one against one.

## Retained negative results and testnet boundary

The first component fixture used 100,000-sompi demonstration fees. It remains
component-only evidence; its initial GPU attempt was stopped and retained.
Fixture02 rebuilt notes and authorizations using exact native quotes. A supplied
underfee exit can pass consensus VM checks while failing the source-adapted
default relay policy; these are not interchangeable admission claims.

The first live funding attempt found a mining delivery bug: slow Tor RPC could
replace a job before draining its valid nonce. Its trial, source preimage and
evidence are retained. The corrected queue preserves the original template,
rechecks nonce/body/reward and retains durable once-only submission. Three
independent regressions passed before a fresh trial identity was started.

Fresh trial02 is mining actual public-TN10 funding. At this snapshot it has not
established a confirmed shielded pool, private payment, downloaded recovery or
terminal payout. Those require actual accepted whole transactions, authenticated
history, nine confirmed cashouts, zero reserve and complete sompi accounting.
Local software unpacking and canary controls are not downloaded or off-host
recovery. No second physical machine or independently administered retention
destination has been demonstrated.

Privacy remains scoped: the candidate removes mandatory live co-owners but
retains visible NF/two-output grouping, network/timing/invoice limits and a
shared mutable reserve head. See the [privacy contract](contract/PRIVACY-AND-ACCEPTANCE.md)
and [prover study](proving/DIRECT-GROTH16-FEASIBILITY-01.md). No statistical
anonymity, production safety or complete private-payment-system pass is claimed.
