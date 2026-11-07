# Atomic public credential bundle: frozen local test

**Selected on 7 November 2026 before a new run.** The question is whether
publishing one complete set of blind-signature replies through a common
accepted-transaction payload can remove the issuer's per-wallet reply timing
control in the existing three-wallet private-payment withdrawal. This is an
optional current-L1 hypothesis, not a privacy or production claim.

## Source and feasibility screen

Kaspa's [transaction-payload guide](https://docs.kaspa.org/integrate/transaction-payload)
allows application data in ordinary transactions and reports a practical
payload ceiling of about 25 KB under standard mempool transient mass; the
exact ceiling depends on the rest of the transaction. The
[accepted-transaction guide](https://docs.kaspa.org/integrate/accepted-transactions)
shows how independent readers retrieve accepted transaction payloads with a
confirmation buffer and handle reorgs. The prior real-proof three-claim
[operator transcript](../round-agreement-2026-11-07/run/staggered/view/operator.jsonl)
encodes three issue requests plus three blinded replies in 10,686 bytes of
compact JSON. This is a size screen, not native transaction acceptance or a
complete fee estimate.

The candidate is one immutable payload containing the common round, three
genuine proof-backed issue requests and their three blinded signatures. The
public blinded-reply check uses the raw RSA public/private relation specified
for `BlindSign` in [RFC 9474](https://www.rfc-editor.org/rfc/rfc9474.html),
followed by the pinned library's full client finalization for the wallet's own
reply; it is not a new signing primitive. The
issuer may choose whether to publish or withhold the whole set. Wallets use
independent accepted-chain readers, verify the exact common state/round/issuer,
all three proof-backed requests and all three blinded-signature relations,
then find and unblind their own reply. No wallet accepts a private issuer reply
as permission to redeem. If the issuer withholds or publishes a broken set,
the wallet safely waits or takes the separate ordinary exit path.

The local test uses a single atomic file publication as a **simulation** of an
accepted transaction payload. It cannot establish real chain propagation,
reader independence, reorg handling, transaction acceptance or data retention.
These are separate gates if the offline result is favorable. It uses the
existing private wallet, RFC9474 implementation and unchanged withdrawal
kernel; it changes no chain rule, reserve authorization or proof relation.

## Frozen workload and adversary

Reuse the actual 40 KAS supplied-deposit fixture and four wallet payments:
A->B 20 KAS, B->C 10 KAS, A->D 10 KAS. A/B/C each issue one genuine blind
eligibility request for an equal 10 KAS payout; D retains 10 KAS liability.
The service knows the three request connections, proofs and its own scheduling
actions; it sees all redeem messages and public payout keys. It does not read
wallet backups, local blinding state or scoring truth. The observer's exact
links are predicted from service/public data and sealed before owner truth.

Arms, in this order:

1. A malicious issuer tries the old schedule: release only one usable reply,
   wait for that wallet's redemption, then continue. Every wallet must reject
   the incomplete bundle before revealing a payout key. A complete but
   deliberately invalid signature for another claimant must also be rejected.
2. Publish one genuine complete bundle atomically. All wallets verify it and
   redeem through the existing protocol. The unchanged full-set approvals and
   economic kernel must accept exactly 30 KAS of payouts, leaving 10 KAS.
3. The service-only observer runs on the actual issue/redeem transcript. It
   must have no exact claim-to-payout link from controlled reply timing. The
   number of compatible mappings and its fixed rank guess are reported
   separately. Known-owner, amount and network controls remain adverse.

**Stop rule:** if the service gets an exact link through its release policy,
or if an incomplete/invalid bundle prompts any key disclosure, reject this
candidate and do no cost work. If the local guard works, this is only enough
to justify further network/native validation, not enough to claim usable
privacy or start a fee campaign. Complete financial privacy and costs remain
open under the existing project thresholds. Do not add a new token, operator
exit key, mainnet experiment, real funds or consensus change.
