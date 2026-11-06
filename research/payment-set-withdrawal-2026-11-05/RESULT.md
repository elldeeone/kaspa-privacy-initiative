# Real-wallet test: ownership benefit survives; cheapness target fails

Date: 5 November 2026. Owner-authorized offline test, no consensus changes.

**Subsequent cost judgement, 6 November:** the owner challenged stopping at the
3.075% floor. The [additive cost review](../payment-set-withdrawal-2026-11-06-cost-review/RESULT.md)
keeps this frozen 2% failure but recommends continuing bounded complete-cost
work. This floor is not the total cost, and one small-workload failure does not
establish product unusability. The review also verifies that 100 sompi/mass is
the pinned default relay minimum; lower-price sensitivities are not a default-
relay saving.

**Decision:** the actual private-wallet relation can authorize the common payout
set without publishing each owner's destination. The bounded ownership benefit
survives genuine private payment and recipient re-spend. This direct-verification
layout is **not cheap enough for the frozen 30-KAS useful-payment workload at
100 sompi/mass**. Even an optimistic floor exceeds the existing 2% complete-cost
target. Keep the mechanism for integration with the shared effort; do not adopt
another direct runtime or claim a general current-L1 impossibility.

## Plain explanation

Alice starts with 30 KAS. She privately pays Bob 20 and keeps 10. Bob receives
and decrypts that payment, then privately pays Carol 10 and keeps 10. All three
finish with 10 KAS. They withdraw together, approving the entire transaction.
Their messages do not say which of the three payout addresses each owns.

The declared observer still has six possible owner/address assignments. If Alice
discloses her address, Bob and Carol can still be swapped. Two disclosed owners,
known payout owners or identifying service metadata remove that ambiguity.
These are synthetic wallets on one machine and an assumed protected redemption
interface, not three independent people or demonstrated internet anonymity.

## What actually ran

- The unchanged `poc/private-note-wallet` depth-four protocol, Wallet encryption,
  recipient discovery, backup restoration and Ledger kernel.
- Matched original and optimized real proofs for credit, Alice's payment and
  Bob's received-note re-spend; same wallets, notes and encrypted deliveries.
- Six original proofs and seventeen optimized proofs, including real wallet
  eligibility and whole-set/solo authorizations. Old source/profiles unchanged.
- Thirty-eight actual Kaspa script-engine cases: eight acceptances and thirty
  intended rejections; independent solo exits and complete solo drainage.
- Local kernel final principal, private liability and unpaid exit count all zero.
  A local UTXO model resolves actual joint/solo conflicts and repeated proposals.
- Separate processes for each observation and a prediction seal before reading
  private synthetic truth. New-process public-only proof/native/RSA replay.

The [selection](SELECTION.md) fixed the workload, comparison, observer, fee price,
2% target and stop rule before generation. The [source/reuse review](SOURCES.md)
and [ADR-0108](../../docs/adr/0108-real-wallet-common-set-integration.md) preceded
implementation. The [public run](run/MANIFEST.json) binds saved artifacts and
source identities. Earlier local execution is retained separately.

## Integration boundary: what this result does not establish

The actual wallet and atomic private ledger run locally. The finite native
reserve starts at their resulting root/eligible nullifiers, using a supplied
unfunded UTXO. Genuine wallet proofs authorize actual native outputs from that
reserve. This does **not** authenticate native deposit ancestry or prove the
complete kernel history to L1. Existing native permissions require individual
destinations and cannot execute this new common-set meaning unchanged; no new
complete outer guest/receipt or production adapter was built.

This is a wallet/kernel-to-finite-withdrawal integration, not a complete deployed
payment system or full-node/relay/chain acceptance. Current DAG/reorg/pruning
recovery, independent public proving/history availability, received-native-output
spending, actual network origins and proving-service prices remain unqualified.
Whole-lifecycle amount/relationship privacy is not established; known owner
totals and complete drainage retain conservation leaks. The two private payment
amounts in this workload are not an anonymity population.

## The cost reduction that was actually tested

The original wallet has fourteen public field inputs. Three checks alone cost
532,500 compute mass, exceeding the 500,000 block compute limit.

The isolated optimized circuit hashes the complete canonical 410-byte public
statement and exposes that digest as two canonical 128-bit limbs. Every original
ownership, hidden membership, economic-nullifier, range, conservation and delivery
constraint remains. Native code reconstructs and hashes the complete statement
from the policy and actual transaction. The statement stays public; this change
reduces verification cost, not public information.

| Measurement | Original relation | Optimized relation |
| --- | ---: | ---: |
| Public inputs | 14 | 2 |
| R1CS constraints | 924,455 | 1,209,100 |
| Verification-only compute mass per proof | 177,500 | 147,500 |
| Three-proof compute floor | 532,500 | 442,500 |

Verification floor improves 16.90%, at the cost of about 30.79% more proving
constraints. This is not a measured wallet latency/memory improvement. The
finite joint transaction quotes **457,671 compute mass**, about **91.53%** of
the current block compute limit; storage 2,672 and transient 26,364. It consumes
44,273,702 script units under its 4,500-unit committed budget. The largest subset
script is 5,893 bytes and joint signature script 6,287 bytes.

Four optimized checks alone cost 590,000 compute mass, before any overhead, so
this layout still cannot grow its cohort to four. This is a limit of this layout,
not every possible application using unchanged Kaspa rules.

## Whole-route cheapness: retained negative result

The useful denominator is Alice's 20-KAS payment plus Bob's 10-KAS payment:
**30 KAS**. Change and withdrawals add no useful payment value.

At the historical comparison price of **100 sompi/mass**:

| Scope | Fee floor or synthetic fee | Share of useful payments |
| --- | ---: | ---: |
| Six original direct verification checks only | 1.065 KAS floor | 3.55% |
| Six optimized direct verification checks only | 0.885 KAS floor | 2.95% |
| Actual finite withdrawal fee | 0.48 KAS synthetic fee | 1.60% |
| That withdrawal plus three other optimized checks only | 0.9225 KAS floor | **3.075%** |
| Existing complete-route target | 0.60 KAS maximum | **2.00%** |

Six checks are credit, two private payments and three exits in the selected
direct-verification route. Its last row omits other transaction bytes/guards,
funding, state rent, relay/proving services and retries. Those omissions make
the result optimistic; even this floor fails. No actual fee was paid. This is
not the fee floor of the separate based-app/outer-proof architecture.

The fixed native policy allocates 16,000,000 sompi fee per claim, totaling
48,000,000. Its current withdrawal mass quote at 100 sompi/mass is 45,767,100,
so that allowance covers the quote. Lower market prices do not automatically
refund this fixed allowance; repricing means a different fresh policy/context.

[Cost-frontier arithmetic](run/COST-FRONTIER.json) preserves 1/10/100 sompi/mass
sensitivities and the fixed-fee distinction. At 100, scaling this pattern requires
at least **15.375 KAS per final balance** just to fit the optimistic 2% floor.
Real overhead makes the necessary size higher. Larger payments/lower fee prices
were not executed or qualified as a cheap complete product.

## Decision about the next direction

Do not grow this one-proof-per-owner withdrawal implementation or describe it
as a cheap replacement for Olaf's direction. It establishes a useful application
relation, while its direct route misses the frozen fee target and remains limited
to three owners.

The existing shared architecture already studies outer proofs over public wallet
proofs. Reusing that batching is the relevant cost alternative: it does not need
owners to hand over spending secrets or new consensus rules. Its common-set
state/payout binding and complete costs remain untested here; the retained old
receipt cannot prove a newly changed guest. See the [bounded batching screen](BATCHING.md).
Any follow-up should be a change to that shared path with one matched complete
cost test, rather than another independent proving/runtime project.

## Reproduce and review

```sh
bash poc/payment-set-withdrawal/check.sh
```

The check verifies source preservation, artifact hashes, coupled truth retention,
ownership controls, real public cryptographic/native replay, full-relation
zero/MAX/overflow boundaries and malicious public-operation mutations. The
[adversarial review](REVIEW.md) records the trust boundaries and corrected direct
destination encoding. Setup is experimental and unaudited; never fund these scripts.
No old frozen evidence, invariant or consensus rule was changed. No funds, RPCs,
broadcasts, paid provider or paused MPC work was used.
