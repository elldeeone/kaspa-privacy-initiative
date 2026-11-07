# A shared round blocks tagging, but service timing still reveals payout owners

**Decision: the privacy gate failed.** Wallets now reject different round IDs
before sending payout keys. A service using one valid common round can still
release the three blind-signature replies one at a time. It thereby matched all
three genuine claims to their payout keys, and the unchanged economic kernel
accepted the fully approved 30 KAS payout set. Do not begin the conditional
cost campaign or present this withdrawal service as a qualified privacy gain.
No Kaspa consensus rule changed.

## What was tested

Fresh, separate wallet and service containers on **one physical host** reused
the actual private note wallet, Testnet-profile proving parameters, four
proof-backed payment operations, RFC9474 blind credentials and three final
whole-set approvals. A supplied 40 KAS deposit fixture funded A→B 20 KAS,
B→C 10 KAS and A→D 10 KAS. A, B and C then each withdrew a 10 KAS note;
D's 10 KAS liability remained. The service never mounted wallet backups.

The new wallet check verifies a complete set of three distinct, genuine
eligibility proofs against the same public state, issuer, amount and round,
including the wallet's own exact issue request, **before** calling the existing
redemption path. Ten later read-only controls accepted the genuine set and
rejected omitted/duplicated claims, a changed round/issuer/state/value,
altered blind request, forged proof and malformed cohort. This check does not
give the service spending authority.

| Service behaviour | Exact claim-to-payout links | Result |
| --- | ---: | --- |
| Common round; all three replies released together | 0/3 exact facts; 6 possible mappings | Full payout accepted; fixed order guess still matched 3/3 in this sample |
| Different round ID per wallet | 0 payout keys sent | All 3 wallets rejected before redemption |
| Common round; release one reply, wait for its redemption, repeat | **3/3** | Full payout accepted; only 1 mapping remains |

The timing observer used only the service's actual issue/redeem log and the
service's declared release policy. Its prediction was sealed before owner-local
truth was read. The observed order was exactly `issue, redeem` three times.
The service can identify each claim from its held issue connection and the next
payout key from the only wallet able to redeem. Tor and an identical round do
not hide that causal link. This is stronger evidence than a lucky rank guess,
but it applies to this wallet/service protocol and workload, not every possible
current-L1 design.

## Practical limit and next decision

The test used real wallet proofs and existing economic checks but **no new
outer receipt, native Full validation, Testnet payout or chain broadcast**.
Native payout amounts remain public. Wallets and service were in different
containers on the same physical machine; this is not three independent people
or global network anonymity. A proposed two-machine extension was stopped
before a complete result at owner direction. It contributes no evidence and
must not be described as a successful trial.

The local privacy failure is enough to stop step 3's cost work under the
[preselected gate](SELECTION.md). Keep cached proof verification and optional
batching as separate cost/liveness improvements. Any renewed withdrawal-privacy
proposal must first make reply availability independent of the service's
per-client release schedule, then beat this same active observer with complete
wallet ownership, timing, known-owner and amount controls. No such mechanism is
demonstrated here. [ADR-0115](../../docs/adr/0115-service-release-timing-limits-blind-withdrawals.md)
records the decision.

The [public evidence](run/RESULT.json) has a finite hash manifest, public
payment/eligibility proofs, service logs, sealed predictions, unchanged-kernel
replay and changed-intent refusals. The exact producer driver epoch and private
owner truth remain local; the committed local-only runner reproduces its three
local arms. The read-only [checker](../../poc/round-agreement/check.py) verifies
the exported evidence without wallet backups, issuer secrets, proving parameters
or network access. Passing checks establish only the stated offline behaviour.

The first local attempt stopped before payment proving because its binary used
the wrong parameter profile. A second was interrupted while fixing the
observer's pre-truth sealing. The retained third local attempt completed all
three arms. These failed attempts and the unfinished second-host preparation
were not scored as privacy trials; their private files remain local.
