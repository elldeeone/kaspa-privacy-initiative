# RFC-0005: Common-set withdrawal authorization under current L1

**Status:** Open; finite unfunded diagnostic authorized by the owner, no production
architecture selected. **Date:** 5 November 2026 (Australia/Sydney).

## 7 November common-configuration enforcement failure

The [separated-role test](../../research/separated-withdrawal-2026-11-07/RESULT.md)
checks the existing common-configuration requirement against an active issuer.
One public key and different per-wallet round IDs are enough to identify all
three payout keys from actual messages. Current wallets still authorize the
common set and the unchanged economic kernel accepts it. This is host-kernel
evidence, not a new native receipt or chain trial. The honest service view retains
six exact-fact mappings, but the selected order guess matched all three once.

[ADR-0114](../adr/0114-round-agreement-before-payout-disclosure.md) stops cost
work. Open requirement: enforce agreement on common configuration before wallets
disclose payout addresses, without silently trusting a shared bulletin or adding
consensus rules. Merely checking at final approval is too late. A separate timing
test remains necessary. No repair is implemented by recording this failure.

## 7 November static verification cache

The owner authorized [ADR-0113](../adr/0113-cached-wallet-proof-verification.md):
cache only complete wallet-proof validity, then execute every current economic
and native-effect check afresh. No host flag or conditional receipt is spending
authority. The matched supplied-state control measures 30.53-second fresh
settlement versus 445.73 seconds direct, after 419.00 seconds upfront work;
first use costs about the same. Complete native claims and fees are unchanged.
The [complete combined comparison and fresh TN10 rehearsal](../../research/cached-approval-verification-2026-11-07/RESULT.md)
now execute protected registration, unchanged approvals after an actual accepted
update, complete drainage and restored native payout spending. Cached current
withdrawal proof takes 24.18 seconds on TN10; all four test KAS principal exit.
The corrected cold reference retains the native fee/wait tradeoff. No stronger
complete financial privacy or complete-cost qualification follows.
The new bank/profile and fresh small TN10 rehearsal extend the original
unfunded-only scope by explicit current owner authorization; old results and
old trial identities retain their original boundaries. Complete costs/privacy,
independent users and sustained contention remain open.

## 6 November reusable owner consent

[ADR-0111](../adr/0111-reusable-withdrawal-intents.md) and the
[executed result](../../research/reusable-withdrawal-approvals-2026-11-06/RESULT.md)
add a new explicit optional intent branch. It commits fixed pool/config,
historical anchor, nonce, full distinct independently sorted claim/payout sets,
equal denomination and aggregate fee cap. The current Ledger checks unspentness;
a fresh aggregate/native receipt still binds exact current state/input/effects,
ordered packet and immutable successor. Original approval bytes survive three
unrelated updates, including a terminal-shape change. Changed economic consent,
spent claims, missing accepted anchors and insufficient cap/allowance still refuse.
Old exact-effect/solo/named/refund branches and historical failures remain.
Released consent is executable without a final timing confirmation while valid;
revocation requires accepted note spending. Backend contention and timing privacy
remain unqualified. No circuit/setup/consensus/invariant change or old-bank upgrade.

## Question and specific replacement

The [busy-payment experiment](../../research/busy-pool-payment-flow-2026-11-06/RESULT.md)
under [ADR-0112](../adr/0112-busy-pool-withdrawal-scheduling.md) retains the same
program and original approvals across an actual accepted advance during proving.
Request age survives retries and waiting payments batch through existing PAYMENT
semantics. The complete paired histories drain all principal; native quote and
withdrawal savings come with worse incoming-payment waits. A separate genuine
worker-cancellation/fresh-proof check preserves the entire native history and
original approvals. It is not a new full-arrival benchmark. Current spentness,
accepted anchors, complete fee/payout consent and fresh exact receipts remain
mandatory. Independent races, complete costs/privacy and live-trial readiness
remain open. Keep batching optional; no consensus, circuit or setup change.

Can wallets approve the same complete payout transaction without publishing a
per-wallet destination, while an actual registration protocol keeps that
assignment out of the coordinator's application transcript?

The [previous gate](../../research/joint-withdrawal-feasibility-2026-11-05/RESULT.md)
rejected wrapping the existing public EXIT statements. This replacement creates
new authorizations; it does not pretend old statements disappeared. Current
Groth16 verification and output introspection must suffice. No consensus changes,
new asset, privileged spending key, real funds, network trial or paused MPC work.

## 6 November actual-wallet batching update

The subsequent [requester/busy-state follow-up](../../research/withdrawal-request-and-busy-pool-2026-11-06/RESULT.md),
authorized by [ADR-0110](../adr/0110-withdrawal-request-privacy-and-busy-state.md),
tests identity-free proof-authorized eligibility over our own actual onion
service. This is a new unfunded application-message test beyond the original
5 November diagnostic's no-network scope. It removes the human-index roster;
current unspent-note authority and one credential per NF remain required. The
service-only ownership benefit fails with measured labelled client timing,
known output ownership and distinctive known expected amounts. A key-pinned
guest variant retains all original wallet/effects constraints and starts a new
synthetic bank image. Native Full busy-state/optimized cost results are separate
from the network/wallet-only evidence. The completed quiet path now links actual
Tor-registered keys/eligibility to Full-validated native payouts and restored
native-key spending. Complete proving falls 19.11% with unchanged native fees;
known-owner financial privacy remains unqualified. A real unrelated state update
invalidates old approvals safely, and fresh approvals/independent exits recover.
Reducing that contention without losing authorized payout/effect/state safety
remains open. Anonymous approval transport and independent clients remain unqualified.

[ADR-0109](../adr/0109-complete-cost-and-batched-payout-test.md) and the
[complete offline comparison](../../research/batched-payment-costs-2026-11-06/RESULT.md)
now exercise genuine wallet claims/payments and compressed complete outer
receipts with native Full validation. The finite synthetic-claim design below
remains the original diagnostic, not the new adapter's state/admission model.
The new adapter binds canonical before/after state, full actual effects and the
public operation payload; it retains every NF/deposit while removing only fully
reconciled paid bookkeeping. Fees use a separate refundable allowance.

Six payout-key owner assignments survive the declared common-set view at exactly
the same native fee as named batching. Identified eligibility still reveals each
claimant's withdrawal amount. This does not resolve complete financial privacy.
Open work includes protected/independent registration, active-state contention
and stale reapproval costs, variable balances/denominations, independent public
parameter/history availability and fee funding beyond the finite initial bank.
Reuse the existing checked/pinned parameter path as a separately measured cost
candidate; do not claim its saving before testing. No consensus change follows.

## Smallest testable instance

Use three explicitly synthetic, equal-principal native claims. Each has a public
commitment `SHA256(secret)` and publicly known input owner. The commitment is the
finite instance's claim identifier, not a new private-note or nullifier design.
One common Groth16 relation proves the claimant knows its preimage and computes
a domain-separated RFC2104 HMAC authorization over a full-effects context.
Public proof inputs are claim commitment, context and authorization tag, each
encoded by two canonical 128-bit limbs. There is no chosen recipient field.

All authorizers approve the same transaction. Each wallet separately checks
that **all** of its expected payouts, with correct amounts and multiplicity,
are present before proving. An untrusted coordinator cannot acquire spending
authority by registering, substituting, duplicating or inventing outputs.

The context binds genesis/domain, exact current reserve outpoint, active claim
set, principal and fee allowances, branch, all actual output values/scripts and
the complete successor policy. Native script reconstructs it from transaction
introspection. A host-computed digest alone is insufficient.

## Finite spentness and independent fallback

There is one reserve UTXO containing `n * (D + F)` for `n` active claims. `D` is
user principal; `F` is a separately declared per-claim fee allowance. No allowance
is counted as private principal. The finite diagnostic precomputes the seven
nonempty subsets of its three public claim identifiers:

- Joint branch: every active owner supplies a proof for the same complete
  effects; exactly `n` distinct recipient outputs of `D` are created, and the
  reserve fully drains. The native fee is exactly `n * F`.
- Solo branch: one active owner supplies a proof, receiving `D` plus a successor
  reserve of `(n-1)*(D+F)` under the exact smaller-subset policy. Final solo exit
  has no successor. The native fee is exactly `F`.
- Current input spentness resolves conflicting joint/solo proposals. A proof
  for a stale outpoint or different subset/context must fail. No other owner,
  registration server or issuer signature is required for a solo exit.

Every script must pin exact input/output counts, amounts, scripts, active claim
authorizations and successor. Test actual current native script execution and
report local supplied-UTXO/spentness evidence separately from consensus/chain
acceptance. This finite state enumeration is not a scalable pool or a completed
deposit/private-payment protocol.

## Output registration without issuing an asset

Exercise an existing RFC9474 RSABSSA implementation, using its randomized
SHA384/PSS mode and one common issuer key/configuration for the entire round.
These are ephemeral coordination credentials; they confer no claim to native
funds, are not a new token, and are not checked as spending authority by L1.

1. Each identified eligible claimant sends only a blinded registration message
   and an owner-local authorization binding its blind request and round. The
   coordinator verifies the claim and issues at most one credential per claim.
2. The client unblinds and verifies locally. Blinding state and message randomizer
   stay client-local during identified issuance.
3. Redemption supplies the signed canonical round/denomination/recipient message,
   final signature and randomizer through a separate logical interface carrying
   no owner identifier or issuance session marker. Reject duplicate/context-
   mismatched redemptions. Sort the final public outputs canonically.
4. Owners inspect the complete transaction and create their spending proofs only
   after their full expected entitlement is included.

Extra credentials, issuer loss and withheld registration can prevent a joint
round, but cannot release the reserve or disable solo exits. Cryptographic
blindness relies on the established primitive/library; successful local tests
are not a proof of blindness or an audit of that library.

Logical interface separation does **not** establish network anonymity. The
diagnostic must disclose that an observer joining IPs, authenticated cookies,
randomizers leaked at issuance, timing or retries can recover the assignment.
Do not claim protection from the trusted same-host test controller.

## Bounded comparison and controls

Record the exact observer/workload and stop rules in a selection before fresh
execution. Compare actual individually registered and blind-registered application
transcripts with the same sampled output keys and three known input owners.
Derive compatible owner-to-real-output assignments from observable constraints;
never count note labels, input positions or opaque proof slots as payment privacy.

Include one legitimate participant's output, all-but-one collusion, externally
known payout owners, deliberately linkable registration, leaked issuance
randomizers, original public EXIT records, and unequal-amount/solo-fallback
limitations. Do not silently remove truthful ownership data to obtain a gain.
Full known-owner drainage and the existing absolute privacy targets remain
unqualified; this screen measures only a named payout-ownership channel.

Required negatives include wrong owner/secret, changed complete output set,
diversion, duplicate payouts/authorizations, malformed proof/field encoding,
wrong root/claim set/domain/outpoint, replay/double spend, successor substitution,
principal/fee/range errors, server loss, and joint/solo conflict. Negative controls
must reach the intended proof/native rejection layer; unrelated build failures
are not successes.

## Open obligations

Integration with the actual shielded ledger's authenticated accepted roots and
nullifiers, ordinary deposits/private transfers, pruning/history recovery,
arbitrary denominations, independently operated clients, real network privacy,
proof/setup review, full native transaction validation/relay/mass qualification,
paid lifecycle cost and production security remain separate obligations.
No existing invariant is amended. The source/reuse review and experiment
decision must precede prototype execution.
