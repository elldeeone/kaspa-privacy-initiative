# Wallet-local payment privacy selection

**Frozen:** 2026-11-01 before detailed artifact extraction or scoring in this
task. **Status:** selected offline analysis only; no proof, network, funding,
broadcast, Testnet or MPC execution is authorized.

## Question

Does the existing wallet-local native-KAS path keep the payer, recipient,
payment amount and historical spent note non-unique for a public observer and a
processing service, while preserving user-controlled recovery and native-KAS
exit?

"Zcash-like" is a target to define from primary sources, not an equivalence
claim. Cryptographic note confidentiality, payment unlinkability, network
anonymity and independent recovery are scored separately.

## Prior knowledge and independence limit

The analyst previously read the upstream headline report and therefore already
knows the named Alice/Bob roles, the 10/4/6 test-KAS lifecycle headline and that
the retained TN10 run was operator-controlled. This is not a blind selection.
To limit cherry-picking, the selected actual corpus is the complete tracked
public lifecycle evidence below, not a chosen subset, and attacks/thresholds are
fixed here before detailed field extraction.

## Selected actual corpus

At repository commit `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`:

1. all tracked files under `poc/tn10-live/evidence/`;
2. the source needed to decode those files under `poc/tn10-live/`,
   `poc/private-native-tn10/`, `poc/private-note-wallet/`,
   `poc/private-note-chain/` and `poc/private-note-proof/`;
3. the current public README/results/ADR material that states the evidence and
   operator boundary.

No ignored/private runtime root, wallet backup, key, unpublished observer
truth, paused-checkout evidence or later experiment may enter scoring.

## Scenario

Use the retained lifecycle as one sparse but realistic early-use payment:

```text
known transparent native-KAS deposit
-> private credit
-> rejected private-payment attempt
-> accepted wallet-local payment with change
-> recipient direct exit
-> native-KAS payout and remaining backed private value
```

The auxiliary identity universe is fixed to Alice, Bob, Carol and Dave. The
public contact graph is `Alice-Bob`, `Alice-Carol`, `Carol-Dave`, `Bob-Dave`.
The public observer is told that Alice controls the transparent deposit and Bob
controls the native payout address. It is not given plaintext invoice contents
or wallet secrets. These identity bindings and the contact graph are simulated
auxiliary facts; actual amounts, ordering, fees, timing and payload bytes must
come from the selected corpus.

The service observer is additionally told that its authenticated submission
endpoint belongs to Alice. It receives every byte, timestamp, order, retry or
failure fact the actual selected processing boundary legitimately receives.
The actual retained deployment's operator role access is scored separately and
must not be omitted. No service is granted private data merely because an
idealized future API could avoid it.

## Observers

### O-public

- complete selected public corpus;
- accepted/rejected operation order and verdicts visible in that corpus;
- deposits, settlements, payout transactions, reserve movement, public fees,
  operation shapes, nullifiers, commitments/ciphertexts and timestamps;
- the fixed simulated deposit/payout identity bindings and contact graph.

O-public does not see wallet secrets, plaintext notes, plaintext invoices,
network endpoints or unpublished operator files.

### O-service

O-public plus:

- every selected request/public package byte legitimately received by the
  processor, outer prover, settlement operator or relay;
- request order, timing, failures/retries and authenticated endpoint identity;
- actual retained operator custody/role facts stated by the source record.

O-service does not break cryptography or receive omitted wallet secrets by
assumption. If the actual operator held a role or secret, that is an observation,
not an excluded attack.

## Hidden truth and queries

Keep source-declared role truth separate until observer views are assembled.
For each observer enumerate assignments consistent with its view and answer:

1. Which identity supplied the accepted payment's input?
2. Which identity received the payment?
3. What was the payment principal?
4. Which earlier commitment or deposit-derived note was spent?
5. Which public output is payment and which is change?
6. Which later exit belongs to this payment?

Report candidate counts and the exact fields/auxiliary facts that remove each
candidate. Do not substitute proof-field secrecy for a payment-unlinkability
answer.

## Prospectively selected attacks

1. `A-plaintext`: search actual public/service bytes for plaintext owner,
   recipient, amount, note opening, spend key or direct commitment linkage.
2. `A-singleton`: enumerate eligible historical notes before the accepted
   payment; test whether sparse accepted history makes the spender unique even
   though the NF is cryptographically unlinkable.
3. `A-balance-exit`: combine transparent deposit, conservation, public reserve
   movement, payout principal/refund and remaining liability to infer payment
   amount and recipient.
4. `A-order-time`: use actual operation order, rejected/accepted attempts and
   payout timing; do not invent unavailable packet timestamps.
5. `A-service-origin`: use the authenticated submission endpoint and every
   legitimate service-side role fact.
6. `A-grouping`: test what the visible one-input/two-output group adds after
   the other facts; do not call grouping alone identification.

## Frozen success criteria

Score these separately:

1. **Field confidentiality:** no selected observer receives plaintext note
   value, recipient descriptor, note opening or spend key except through an
   explicitly identified deployment-role leak.
2. **Payment unlinkability:** for each observer, all of sender identity,
   recipient identity, exact payment amount and historical spent note retain at
   least two candidates, and at least two complete sender-recipient-amount-note
   assignments remain.
3. **Output partition:** at least two payment/change output assignments remain.
4. **Independent recovery/exit:** retained actual evidence must show a user who
   does not depend on the original operator can recover from user-held secrets
   plus authenticated public data and obtain native test KAS. Source design,
   local fixtures or same-operator roles do not pass this criterion.

A unique answer fails only the named property it reveals. The route fails the
selected overall target if either observer uniquely learns sender, recipient,
amount or historical spent note, or if independent recovery/exit lacks actual
evidence.

## Stop rules

- Do not change the workload, identity graph, observers, attacks or thresholds
  after extraction begins.
- Stop scoring a property once a unique assignment is established, but retain
  every leak already tested and still score the other properties.
- If a required decoder or artifact is absent, report the exact gap. Do not
  replace missing actual evidence with an idealized pass.
- Simulated auxiliary facts may constrain actual bytes; they may not be called
  observed network or chain evidence.
- Do not infer real network anonymity, production privacy, cryptographic
  correctness or live independent recovery from this offline analysis.
- Do not read or modify the paused MPC/private-construction checkout beyond
  final read-only status/hash verification.

## Fix classification

For every successful attack classify the smallest plausible response as one of:

1. wallet policy/software;
2. anonymous/replaceable public transport or processing;
3. public protocol/state-layout change;
4. joint private computation.

Joint private computation is required only if the named leak cannot be removed
while each wallet keeps its witness local and processors receive public data.
