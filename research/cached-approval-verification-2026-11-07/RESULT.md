# Keep cached verification; keep batching and payout privacy optional

**The first verification still takes minutes. A retry can reuse that work and
finish in about 30 seconds. The complete small-payment workload is still above
the cost target. No consensus changes.**

All three steps are complete: the matched verification test, the combined offline
payment comparison, and a fresh complete Testnet-10 rehearsal. Four test KAS of
principal were paid out; five actual restored-key payout spends are confirmed,
with zero bank value/liability. This remains experimental, same-host research.

## Decision

1. Keep cached proof verification for new experimental banks. It avoids repeating
   expensive work after an unrelated bank update, with essentially unchanged
   first-use cost. Keep all current balance, spent-note and payout checks fresh.
2. Keep batching and protected payout registration optional. Batching saves fees
   but delays the earliest incoming payment. Protected registration provides a
   limited payout-address ownership benefit; it does not hide amounts or survive
   all legitimate owner/timing knowledge.
3. Continue contributing these bounded improvements to the shared KPI direction.
   This does not demonstrate a competing architecture with stronger complete
   financial privacy, nor qualify mainnet, independent recovery or commercial use.

## Same-input verification test

The original three real wallet proofs are verified once in a separate RISC Zero
guest. Its unconditional Succinct receipt binds purpose/domain, pool, fixed
wallet-key identity and the entire canonical packet. The new settlement guest
pins that image, resolves the actual receipt and runs all current economic/native
checks. Final native verification remains ordinary unconditional Groth16.

| Measured work | Seconds |
| --- | ---: |
| Create the reusable proof-validity certificate | 418.999 |
| Fresh settlement using it, matched input | 30.527 |
| Direct full verification, same input and settlement image | 445.735 |
| Initial certificate plus first settlement | 449.526 |

The matched fresh retry is 14.60 times faster. Initial total is 0.85% higher;
savings start at the second attempt. Other current-state contexts take 23.538
and 25.728 seconds. All three composed cases and the direct control pass actual
native Full validation with identical 16,555,100-sompi fees and the expected
complete journals. These diagnostics use supplied predecessors, not accepted
ancestry or old-bank upgrades. They establish no general first-payment speedup.

## Complete payment comparison

Four wallet processes use their own backups and actual packed private-wallet
proofs. The history credits 40 synthetic KAS, privately pays 20/10/10, registers
three independent payout keys over an actual onion service, and collects three
whole-set owner approvals. A genuine unrelated private payment is accepted in
the local bank model while a fresh settlement job is active. Its owned process
group stops in 0.700 seconds. The certificate and original approvals survive;
the current-bank replacement takes 28.742 seconds and passes native Full.

Three genuine pending payments arrive at the fixed 90/330/570-second schedule.
The candidate immediately batches the first two available payments, then handles
the third when ready. It does not wait to force a three-payment batch. Five later
named payouts drain the remainder. Both histories end with zero principal and
private liability, and eight payout spends per history work after restoring keys.

| Complete 47-useful-KAS workload | Optional batches | Separate payments |
| --- | ---: | ---: |
| Complete native settlements | 6 | 7 |
| Native fee quotes, KAS | 0.992104 | 1.154087 |
| Native fees / useful payments | 2.1109% | 2.4555% |
| Original owner approvals / repeated approvals | 3 / 0 | 3 / 0 |
| Remaining principal / liability | 0 / 0 | 0 / 0 |
| Complete outer proof work, cold creation and cancellation included | 2,372.057 s | 2,386.691 s |

Native fees fall 0.161983 KAS, or 14.04%. The same withdrawal-priority prefix is
used in both arms; group withdrawal wait is 449.668 seconds. The post-wallet-proof
incoming waits are:

| Incoming payment | Optional batches | Separate payments |
| --- | ---: | ---: |
| First | 649.938 s | 506.217 s |
| Second | 410.188 s | 422.814 s |
| Third | 328.449 s | 340.528 s |

The first payment waits 143.720 seconds longer; the other two finish about twelve
seconds sooner. These are bounded, same-host proof-readiness observations, not
chain confirmation waits or an unbounded-contention qualification.

The original reference reused candidate-created certificates for its third
payment and final cashouts. Its fees and complete receipts remain valid, but its
queue times mix warm and cold work. Preserve that first result. The primary
reference above reruns **all four post-prefix certificates in an empty separate
cache**. Its native transaction IDs match the original reference, and all complete
receipts independently replay. This correction changes no protocol or threshold.

## Cost boundary

Using the same frozen illustrative USD 0.13/hour and KAS/USD 0.02987 references,
native fees plus measured outer work subtotal **8.2123% versus 8.5946%** of useful
payments. These are not current offers, paid invoices or complete service prices.
They charge each complete history's cold certificate creation and fresh
settlement/compression, including shared work and discarded cancellation.

Nineteen actual wallet proofs are counted: one credit, seven transfers, three
eligibilities, three approvals and five final exits. Their inclusive calls total
413.124 seconds, including cold parameter loading and onion calls. Some calls
overlap outer proving, so their wall times must not simply be added. Fresh
experimental one-party setup separately takes 48.647 seconds. Eight ordinary
restored-payout spend controls quote another 0.021008 KAS per history; they are
reported separately from receiving the original payouts.

The original paired run samples 114.377 Wh for the whole GPU device after its
controller starts, with peak sampled VRAM 6,217 MiB. This excludes the subsequent
cold rerun and live rehearsal. Process RSS sums peak at 16,111,060 KiB, with
shared-page counting and monitoring-start limitations. These are not whole-host
electricity or exclusive process-energy measurements.

Wallet CPU, onion/issuer operation, whole-host power/hardware, idle capacity,
availability, storage and commercial margin remain unpriced. Native fees alone
already exceed the unchanged two-percent target at this workload. No complete
cost pass follows. Larger-value amortization is not measured by this result.

## What privacy remains

Each wallet keeps its blinding state and random native payout key. It unblinds
and redeems internally over isolated onion circuits, returning no labelled
payout key to the driver. The actual registration transcript, original intent
and Full-validated payouts agree on all three keys and eligible claims.

| Declared observer facts | Compatible claimant/key allocations |
| --- | ---: |
| Registration service and public protocol data in the fixed cohort | 6 |
| One participant knows their own key | 2 |
| All but one participants collude | 1 |
| Labelled controller redemption order | 1 |
| Later all owners disclosed | 1 |

These are conditional allocations for three fixed eligible roles, not a real-world
population anonymity estimate. The whole same-host controller knows more than
the isolated registration service and can identify all three through request
order. No independent global-traffic timing experiment is claimed. Amounts remain
transparent. Combining the published auxiliary ownership controls also reveals
the experiment's keys. There is no complete financial-privacy qualification.

## Safety and replay

Thirty-one economic controls cover current spentness, accepted anchors,
pool/key/packet binding, changed consent, native effects/fees, zero/MAX/ranges and
checked overflow. Static proof validity for changed consent/unknown mode is
accepted as a mathematical fact, then rejected by fresh economics. Nine actual
receipt controls and four actual native wrong-proof/effect controls refuse.
Actual onion registration also rejects nine additive malformed/replay requests.

Independent public-only replay checks twelve retained authorization receipts,
both complete native histories, zero principal/liability and eight restored
payout spends per history. It reads no wallet backup or proving parameters.

The first unfunded rehearsal harness expected a conditional receipt from a
Claim-only assumption. SDK 3.0.3 instead rejects it before producing any receipt,
matching its pinned implementation and existing TODO982 test. The harness stopped
before any test-coin submission. Preserve that failure and use a fresh identity
with the correct expected SDK refusal. No actual conditional native proof was
generated/tested through this path; production complete-claim checks remain
unchanged. See the source addendum and [adversarial review](REVIEW.md).

## Fresh TN10 rehearsal

A fresh Testnet-10 identity completed the selected path:

```text
ordinary free test-KAS funding
-> new immutable bank
-> private credit and three genuine private transfers
-> protected registration and three original owner approvals
-> cached verification proof
-> actual unrelated private payment accepted on L1
-> same approvals and certificate, fresh current-bank withdrawal
-> final two owner payouts, zero bank reserve/liability
-> five actual restored-key payout spends
```

The current-bank joint withdrawal proof took **24.183 seconds** after the real
accepted update. Original approval bytes remained unchanged, with zero repeated
owner approvals. The issuer and Tor stopped before the unrelated update and final
withdrawals. This demonstrates that those services add no native spending key;
it is not an all-service-loss or independent-user recovery qualification.

All eleven submissions (ordinary funding, bank funding, four receipt-backed
settlements and five ordinary recovery spends) have exact retained accepted
bodies and at least ten observed confirmations. Two independent synchronized TLS
routes agree on the final UTXOs. No continuing bank output remains. Independent
public-only SDK/native replay verifies the funded bank, four complete receipts,
four cached authorizations, all five accepted recovery spends and zero liability,
reading no private key or proving parameter.

Paid fees total **67,820,400 sompi = 0.678204 test KAS**, including both funding
transactions and the five recovery controls. The four bank settlements consume
0.658358 test KAS from the separate two-KAS allowance; 1.341642 returns unused.
The four-KAS principal is fully paid before ordinary self-spend fees; the five
recovery outputs retain 3.986870 test KAS after their 0.013130-KAS fees. This
small four-KAS rehearsal checks function, not cheapness at that amount. It does
not replace the 47-useful-KAS offline economic comparison.

Old bank reserves and old trial identities were not reused. An owned old ordinary
sponsor-change UTXO supplied free test coins to new wallet/native keys. The earlier
unfunded negative-test expectation failure remains preserved, with no coin
submission in that identity. No mainnet, real funds or paid provider were used.

The dedicated TN10 profile uses the existing packed relation and fresh
experimental one-party parameters. It is distinct from the retained offline
profile. New guest images require new banks. Latest full backups, including
native payout keys, are used; seed-only, independent-user, all-service-loss and
production recovery remain unqualified.


## Public reproduction

[The finite manifest](run/MANIFEST.json) binds 413 selected public files, including
exact program bytes, receipt/native records, corrected/reference histories,
registration logs and producing source epochs. Wallet/native keys, private
blinding state, proving parameters and raw private RPC traces remain excluded.
Auxiliary ownership controls are explicitly broader than the service-only view.

```bash
bash poc/cached-approval-verification/check.sh
```

The check recreates no wallet proof and broadcasts nothing. It independently
verifies manifest hashes, the same-input control, economic/receipt/native refusal
controls, both complete payment histories, registration signatures and retained
actual-chain bodies/payout spends. The prior busy-pool packet/check also passes
without changing any original producing source file. Passing these checks is not
proof of cryptographic correctness or production safety.
