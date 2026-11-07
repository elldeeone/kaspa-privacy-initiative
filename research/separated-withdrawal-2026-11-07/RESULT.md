# Separation helps the honest service view; active tagging still identifies everyone

**Privacy gate failed. A dishonest registration service identified all three
payout owners by giving each wallet a different round ID. The real wallets still
approved the common payout set and the unchanged withdrawal kernel accepted it.
Cost work was not started. No consensus changes.**

## What ran

Four fresh wallets and the withdrawal registration service ran in separate
unprivileged containers, each with its own network/PID namespace and Tor process.
Wallet backups and blinding state stayed in individual wallet volumes. Actual
post-creation read probes showed the service could not read those backup files;
wallets could read their own files but not sibling host paths. No Docker socket,
host home or wallet proving parameters were mounted into the service.

The observer ran without networking or private volumes. It received full service
wire logs and public state/withdrawal data. Its prediction file was sealed before
the scorer read owner-local truth. Eligible claim identities are admitted known
roles; this counts claim-to-payout ownership, not hidden note labels.

Each arm used the existing private wallet, packed Groth16 relation, experimental
TN10-profile parameters and Ledger. A supplied 40-KAS deposit fixture funded a
real proof-backed credit, A->B 20, B->C 10 and A->D 10. The four wallets then had
10 KAS each. A/B/C registered three fresh 10-KAS payout keys and each produced a
genuine whole-set approval. There are ten genuine wallet proofs per completed
arm: four credit/transfer, three eligibility and three final approvals.

The unchanged economic kernel accepted the three approved 10-KAS payouts,
leaving D's 10-KAS reserve/liability intact. These are **offline host-kernel
results**. No new outer receipt, native Full transaction or accepted chain
payout was generated. The kernel check reconstructs supplied native effects;
it is not replay of an authenticated native predecessor. The allowance/fee
fixture in the report is not a measured commercial or chain-cost quote.

## Measured ownership results

| Observer/test | Exact correct owner/key links | Compatible mappings from exact facts | Fixed order guess, correct links |
| --- | ---: | ---: | ---: |
| Direct wallet-specific network origins | 3/3 | 1 | 1/3 |
| Separate Tor clients, honest common configuration | 0/3 | 6 | **3/3** |
| Separate Tor clients, dishonest per-wallet round IDs | **3/3** | **1** | 1/3 |

The honest service view no longer contains an explicit source-to-key join.
However, the frozen issuance-rank/redemption-rank guess correctly matched all
three in this one sample. One of six possible permutations will match by chance;
this sample neither estimates an attack success rate nor qualifies timing
privacy. Do not report the six structural allocations as a real-world privacy
pass or suppress this successful guess.

For the honest arm, disclosing one participant's own payout leaves two
allocations; two participants colluding leave one. Later disclosure of everyone
also leaves one. Those are additional observer facts, kept separate from the
service-only view. Amounts remain transparent throughout.

## Why active tagging worked

The issuer used **one public bank, one issuer key and one denomination**, but
gave each wallet a different round ID. Each wallet checked its own supplied
configuration and created a valid blinded eligibility request. Later, its signed
redemption message included that same round ID alongside its fresh payout key.

The observer recovered each request's round by checking the real eligibility
context hash against the service's configurations, then matched that round to
the actual redemption message. No owner truth, inserted response label,
controller schedule, private key or blinding secret entered this inference.
The recorded three exact predictions all matched the retained owner truth.

The wallets subsequently approved one shared intent containing all three actual
claims and keys. Their existing approval checks enforce ownership, full payout
entitlement, state and fees, but do not enforce common registration-configuration
agreement. The unchanged kernel therefore accepted the genuinely authorized
payout set despite the ownership leak. Changing an already approved intent is
still rejected; this finding supplies no operator withdrawal authority.

This is an application-level enforcement gap in the prototype. RFC-0005 already
requires a common round/configuration. The honest comparison assumed it; the
active comparison shows that the current client path does not enforce it against
a service supplying different configurations. This does not break RFC9474 RSA
blindness under one common context.

## Decision

Keep the previous cached-verification improvement and leave batching/privacy
optional. **Do not start cost optimisation from a privacy-pass claim.** The next
bounded privacy change should make wallets verify common round/configuration
agreement **before sending their payout addresses**, then rerun the tagging
attack and a separately selected timing test. An approval-time check alone is
too late to retract a tagged address already disclosed. No fix or reliable
timing protection is claimed here. No overall architecture superiority follows.

## Reproduction and retained failures

The [selection](SELECTION.md), [source review](SOURCES.md) and
[adversarial review](REVIEW.md) fix the scope. The [public evidence](run/RESULT.json)
has a finite [hash manifest](run/MANIFEST.json), exact producing source epochs,
sealed predictions, isolation probes, actual wire/proof data and case summaries.
Run the commands in the [PoC README](../../poc/separated-withdrawal/README.md).
Public replay verifies genuine eligibility, RFC9474 credentials, all private
payment transitions, current whole-set kernel checks and the conditional
service-side inference. Private owner-truth scoring remains retained locally;
its correctness is not a new public cryptographic identity proof.

This was not one uninterrupted run. A missing directory in the first isolated
image stopped before registration; it was fixed. Direct and honest comparisons
then completed. The first tagged attempt failed Tor CONNECT before any
application request reached its service. A fresh wallet/round identity completed
only that outstanding arm. Reconnection was added strictly before application
bytes are sent; requests with uncertain delivery are never automatically
replayed. A connection-only readiness probe sent no application message.
Both failures remain private and their aggregate provenance is published in
[FAILED-ATTEMPTS](run/FAILED-ATTEMPTS.json) and [COLLECTION](run/COLLECTION.json).
No completed result was rerun, and no privacy observer, workload or gate changed.

All roles share one physical host and Internet uplink. Host root remains trusted.
This is not independent people/machines, global-traffic anonymity, complete
financial privacy, independent recovery, production setup or mainnet readiness.
