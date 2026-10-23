# Private owner recovery: fresh Auth528 testnet rehearsal

Status: **complete for this fixed TN10 workload**: both owner-generated private
payouts confirmed, final alternate-endpoint observation passed, and both
post-cashout seed-only restores authenticated their current native payouts.

This separate TN10 experiment joins the private cashout relation to public
network reconstruction and owner-local proving. It follows ADR-0053 and the
ordinary trusted-executable amendment in ADR-0054. It uses test KAS only.

## Identity and checked preparation

- Trial: `6b2b461a-f34d-41b2-a288-fbadc37a0b9a`.
- Domain: `caf85e3b34cd9b426559f57bb1ab647835c5dfaf255d17bf3d1291c0f7408470`.
- Public parameter manifest SHA256:
  `008689b84cd171187cc75d32402dbf13d6d4e3ed149d3349ecfbc418bfcaad54`.
- Fresh VK SHA256:
  `a82c94918d93008160ea9af4b709b05ce41ed5fe6e4b85d66d0fb310b02d94f5`.
- The complete local four-transaction rehearsal passed: three genuine proofs,
  four native Full validations with every input engine accepted, lossless SDK
  roundtrips, linked state updates and terminal reserve zero. Its public closure
  is `trial/local-public-01/LOCAL-COMPLETE.json`, SHA256
  `3639f08983f3c5d2656c56d727d6f4efe06316a8efd5b3529caeb4fae3066635`.
- The operator proving session stopped after those three proofs. Its precomputed
  recipient exits are excluded from the independent clients and live releases.

## Confirmed ordinary funding

Transaction `98580676726abeb9057de82f6a5e3c3077cd865aa8c8acad205b210d09fcdb7f`
merged four controlled ordinary test-KAS outputs, totaling **229,498,500 sompi**,
into one fresh-trial funding output of **228,999,900 sompi**, paying **498,600
sompi**. The first observation found all four inputs spent, the destination
output current, and accepting-block blue-score depth 74 under the explicit
greater-than-20 policy. This is a validating-node observation, not immutable
finality or independent consensus verification.

## Actual private lifecycle

The operator prover stopped after the local rehearsal. Each cold client then
received one seed-only backup, the authenticated public parameter blob and
selected software, and independently fetched public history. Neither received
an operator profile/archive, intended-value map, private receipt/index map or
precomputed exit. The second owner fetched again after the first payout.

| Native stage | Transaction ID | Fee, sompi | Result |
| --- | --- | ---: | --- |
| Founding deposit | `006d46b0fabbf551a50186d9e9edf2f873f39ba0d871342c3dd254c1b4a4fbbf` | 1,411,200 | 138,958,700 reserve; 88,630,000 ordinary change |
| Private payment | `16c8a7d82f10eeac0d3da4609c518ade73f7da3294ec26e91cb1ae1b47486fd5` | 18,958,700 | 120,000,000 reserve |
| First owner-local private exit | `71a1536f3a4824026c0d309d2a0f46e1a14103ba99a2e8db9b6013f7ac17a9b4` | 18,999,900 | 41,000,100 native payout; 60,000,000 reserve |
| Second owner-local private exit | `e7696fa34a50e759e630011bca08eec5a2283f22e59db200b7b2627a056e53ee` | 18,957,600 | 41,042,400 native payout; terminal reserve zero |

All four pool bodies were submitted once and observed accepted with exact
whole-body/input-context equality, consumed inputs and current outputs, removal
checks and greater-than-20 blue-score depth (113, 108, 104 and 75 respectively).
These are selected validating-node observations, not immutable finality.

The two cold clients generated genuine new proofs and passed native Full/all
input engines. Their complete wrappers took **12.735 and 12.711 seconds** with
a 14-CPU quota and an 18-GiB memory ceiling, then stopped. Parameter readiness
was checked before seed access. No revealing fallback or other-owner witness
was used. Distinct proof bytes alone would not demonstrate independence; the
reviewed source, issued mount boundaries and fresh network inputs establish
the tested process boundary.

Including the ordinary funding merge, the actual reconciliation is:

```text
229,498,500 source sompi
= 88,630,000 ordinary change
+ 41,000,100 first native payout
+ 41,042,400 second native payout
+ 58,826,000 total native fees
```

This small-value rehearsal does not meet the unchanged complete-fee target.
The [actual integer ledger](live/FINANCIAL-RECONCILIATION-01.json) binds these
amounts to the accepted bodies. Its
[additive final closure](live/FINANCIAL-RECONCILIATION-FINAL-02.json) includes
the successful final network and backup checks without rewriting earlier evidence.

## Final network and backup recovery

The final descriptor-only acquisition through Electron rediscovered all four
pool bodies among 86,619 accepted transactions. Seven exact queries showed all
former reserve inputs spent, both payouts and the ordinary change current, with
all three live points watched during post-query catch-up and no removals or
related spends. The capture SHA256 is
`4c137a71336dae9ed2dc2f613bbd9b4587010681bc08b3f3942fbb136b0794bf`.
Its [selected public packet](network/live-observation-03/MANIFEST.json) also
checks agreement with earlier Vector observations. This is alternate-endpoint
availability and consistency evidence, not independently verified consensus or
proven independent operator identities.

Both owners then restored separately from their original backups and that fresh
final history, with the PK blob, prover and cashout helper **absent**. Each
client freshly validated all four public bodies, recognized one historical
receipt as spent and authenticated one current default native payout. The
[first](wallet/final-recover-01/MANIFEST.json) and
[second](wallet/final-recover-02/MANIFEST.json) public exports retain only counts,
authentication booleans and public replay cases. Private receipt/position and
owner associations remain local. All owned rehearsal execution units stopped.

The two-recipient workload cannot establish financial privacy. Amount/timing
linkage, native fees, trusted development setup, public-data/parameter retention,
validating-node reliance and trusted host/software installation remain explicit
limitations. Passing tests and native acceptance do not prove cryptographic
correctness or production safety. Prior trials and frozen failure results remain
unchanged.

The [next privacy work](privacy/NEXT-BLOCKER-01.md) is owner-controlled private
change, subsequent private spending and backup restoration, followed by a
prospectively frozen stronger arithmetic-observer comparison. The current
one-real-input, no-positive-change wallet exposes that input's value as payout
plus fee. Hiding its opening does not remove that policy-level channel.
