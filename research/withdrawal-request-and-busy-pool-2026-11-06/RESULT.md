# Withdrawal requester privacy and busy-state follow-up

**Decision: keep anonymous, proof-authorized requests and common-set withdrawals
as an optional improvement within the shared batching direction.** They remove
an avoidable service leak without changing L1. They do not qualify complete
financial privacy, independent-user anonymity or a production service.

The earlier prototype and complete cost evidence are committed at `6df8a28a`.
This follow-up follows [ADR-0110](../../docs/adr/0110-withdrawal-request-privacy-and-busy-state.md)
and its [frozen selection](SELECTION.md). [Sources](SOURCES.md) and
[implementation](../../poc/withdrawal-followup/README.md) identify established reuse.

## What the service actually learned

The coordinator now accepts a genuine proof of an unspent note instead of a
human owner/index. It checks the real wallet proof, accepted anchor, denomination,
round, blinded message and current nullifier; only one credential is issued per
eligible nullifier. Real RFC 9474 issuance, local unblinding and redemption ran
through both direct sockets and an actual Tor onion service to our own server.
Issuance and redemption use separate wallet/phase SOCKS isolation tokens. There
is no direct fallback. The first Tor attempt failed with SOCKS reply `0x06`; its
failure remains. A fresh round completed. All our Tor/service processes stopped.

Each completed counterfactual retains all 18 requests, including six successful
issue/redemption requests and twelve malformed, duplicate or barrier rejections.
Logs retain arrival times, actual socket peers and complete application data.

| Observer | Possible assignments of three payout keys to the three assumed honest owners |
| --- | --- |
| Direct service, with identified local source addresses | 1 |
| Onion service and all its application/socket logs | 6 |
| Onion service plus measured owner-labelled client request intervals | 1 |
| Onion service plus later disclosed payout owners | 1 |

The onion test covers eligibility and redemption. Approval proofs are produced
locally; anonymous approval delivery and operational separation of independent
clients remain unqualified. The complete native/prover public view is retained
in the observer packet, not discarded after registration.

This is a service-origin result from three logical wallet clients controlled by
one driver on one host, using one Tor client and our own onion service. Direct source addresses are deliberately
distinct loopback aliases with a declared identity map. We did not qualify real
independent users, malicious/Sybil cohorts, concurrent traffic or a global network
adversary. Six assignments do not imply equally likely owners or six independent
people. One person can control multiple eligible notes.

The direct and onion counterfactuals share a synthetic fixture. Combining their
published control data identifies the keys and reduces the candidate to one
assignment. That is an explicit failure control, not omitted information. These
public research destinations do not themselves remain anonymous after publication.

Known owner-to-nullifier information still reveals that owner's precise exit
amount. Blind registration can conceal its destination association; Tor cannot
erase an association the observer already knew. Distinctive public amounts also
identify payouts when an observer knows each person's expected withdrawal amount.

## Unequal payments and later disclosure

The actual private wallet executed Alice funding 60 KAS, paying Bob 23 KAS, and
Bob decrypting and paying Carol 9 KAS. Restored wallets privately split off 5 KAS
each, jointly withdraw those notes, then independently withdraw their remaining
32, 9 and 4 KAS. Twelve genuine wallet proofs independently reverify; the host
Ledger/effects path ends with zero reserve and zero liability.

The finite accounting observer knows the A-to-B-to-C roles and sole initial
funding. Without owner maps for the later change payouts it retains six gross
payment histories under the cryptographic privacy assumptions. Once the actual
later owners are disclosed, balances are 37, 14 and 9 KAS, revealing the original
23-KAS and 9-KAS payments exactly. This is a controlled known-owner attack, not a
claim that chain bytes alone reveal human identities. This unequal case tests
genuine wallet proofs and the host kernel; no outer/native acceptance is claimed.

## Proving and busy-state measurement

The exact-input comparison completed with genuine complete receipts: dynamic
loading took 540.883 seconds, fixed-key loading 428.762 seconds (20.73% less wall
time). Total guest cycles fell from 155,844,608 to 124,780,544 (19.93%). Both prove
the identical public input and journal. The dynamic receipt correctly fails the
fresh pinned bank's native verifier. This is one pair of measurements on the same
RTX 3070, with some concurrent CPU activity, not a general timing guarantee.

The first busy fixture then failed because the test attempted a one-output
TRANSFER. The unchanged full wallet relation requires two positive outputs.
The exact-fixture circuit regression reproduces that refusal and accepts the
corrected two-output self-payment. No wallet check was weakened. The original
successful receipts are retained and reused only after exact-input/image/journal
verification; their original proving costs remain charged.

The busy retry completed: Alice's genuine two-output self-payment changed the
bank while Bob and Carol's notes remained unspent. Their old approvals failed
both the local outpoint check and the real guest's full-effect authorization
check, including after the proposal was correctly repriced/rebased. Fresh proofs
succeeded. Restored Alice then independently withdrew both self-payment notes,
without the cohort or issuer. Five complete pinned receipts and six linked native
Full transactions end with zero bank reserve, private liability and active bank.

The two invalidated owner approvals wasted 18.465 seconds and no native fee.
The stress route quotes 0.821538 KAS in native fees: this includes Alice's added
private payment and two solo exits, so it is not the isolated price of a collision.
A state update can invalidate approvals again; this is safe recovery from one
collision, not a contention solution. Exact state/effect binding is unchanged.

The quiet three-owner counterfactual completed with the actual Tor-registered
native keys and matching eligibility notes. Public replay independently matches
registration state, eligible nullifiers and registered keys to the authenticated
native prefix and actual terminal payout set. All three restored client-local
native keys then successfully spend their actual payout outputs under native Full
validation. Native keys stay in client backups, not issuer/prover inputs. The
extra three post-exit key-spend controls quote 0.008007 KAS in fees, separately
from the private-payment/withdrawal route.

The two complete outer proofs total **860.745 seconds (14.35 minutes)**, versus
1064.054 seconds (17.73 minutes) previously: **19.11% less time**. Chain fees stay
**0.333552 KAS**, or **1.11184% of 30 useful KAS**. The 33-KAS synthetic source
reconciles exactly to 30 KAS paid principal, 0.996322 KAS ordinary funding change,
1.670126 KAS returned unused allowance and 0.333552 KAS fees. Final bank reserve,
private liability and active bank outputs are zero. Measured GPU-only energy for
the two proofs is 35.43 Wh; CPU/whole-host energy and depreciation remain unknown.

A genuine two-of-three withheld-approval control also fails the actual pinned
guest's complete-output check, with unchanged state and no fee/principal loss.
Changed pinned keys and malformed submitted proofs fail their intended real
Guest checks. The actual coordinator rejects a previously valid eligibility
proof against the busy chain's later active state because its note is spent.
The independent public check verifies seven distinct complete receipts overall,
ten distinct native Full transactions including the three recipient key-spend
controls, genuine wallet/RSA proofs and frozen observer predictions. The busy and
quiet worlds are separate counterfactual branches, sharing an exact verified prefix.

## Costs and next decision

The fixed-key optimization is shared proving work, not a privacy-specific saving.
It applies to named batches as well. The common-set mechanism still has zero
additional measured L1 fee relative to matched named batching; anonymous service
operation and extra client coordination have costs we have not fully priced.

Holding the earlier $0.13/hour reference, frozen KAS/USD snapshot and prior
non-outer overhead constant gives a **5.04% warm subtotal at 30 KAS**. Extrapolating
identical new work to 75 KAS gives **2.02%**, before unpriced transport/operator/
availability costs. The optimized 75-KAS case was not executed. These are
conditional subtotals, not invoices, current provider availability or complete
commercial prices. The two-percent complete-cost target remains unqualified.
[Machine-readable metrics](run/analysis/METRICS.json) retain all assumptions.

**Next engineering priority: reduce repeated approval work during unrelated
activity, while preserving owner-approved payouts, current spentness, backing
and independent exits.** Do not weaken exact bindings as a shortcut. Keep this
optional component within shared batching; do not start a competing architecture
or claim the stronger known-owner/full-drainage problem has been solved.

## Qualification limits

All native funding sources are synthetic supplied UTXOs. No funds, paid provider,
RPC/broadcast, mainnet, consensus change or paused MPC subsystem was used. A seed
alone still does not supply missing public parameters/history. Tor service cost,
operator margin, availability and cohort waiting remain unpriced. The unchanged
two-percent complete-cost target is not qualified by the requester result.
