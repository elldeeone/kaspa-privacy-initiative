# Observer-input audit for prior full-drainage experiments

**Scope:** shared-history correction and private-change run. This audit does not
change or rescore either result.

## Classification

| Fact supplied to observer | Class | Notes |
|---|---|---|
| operation kind, count and chronological order | protocol-visible in the executed wallet kernel | TRANSFER versus EXIT is public; private owner/value is assumed opaque |
| anchors, commitments, ciphertext records and nullifiers | protocol-visible in the executed wallet kernel | equality/spentness/order visible; commitment/nullifier ownership link assumed hidden |
| deposit fixture amount and `deposit_owner` field | protocol-visible in this PoC | not evidence that an identical identity field exists in native consensus deposits |
| exit amount and destination | protocol-visible in this PoC and inherent to the modeled native payout | native payout amount cannot be hidden by MPC |
| mapping an exit destination to A-H | plausible external knowledge, simulated auxiliary evidence | legitimate in the known-payout view; absent only in the unmapped sensitivity view |
| possible contact edges and identity universe | plausible external knowledge when independently justified | prior runs supplied a complete synthetic graph; real observers may know more or less |
| service receive order/time/size | plausible service knowledge | neutral relay token had no admitted identity mapping; network origin was unmeasured |
| exactly two payment chains | experimental workload information | not implied by commitments, nullifiers or native payouts |
| sender groups `{A,B}` and `{C,D}` | experimental workload information | sharply restricted possible funding origins |
| one-to-one E/F first recipients and G/H second recipients | experimental workload information | knowing one chain's recipients determines the other chain's recipients |
| public P1/P2 sampling ranges | experimental workload information | valid observer evidence for those runs, not a protocol-wide wallet policy |
| exactly one first payment and one onward payment per chain | experimental workload information | excludes ordinary multiple receipts/payments |
| target chain chosen from those two chains | experimental workload information | hidden target index itself is not privacy; the correction fixed this |
| first two exits are exactly `P2` and `P1-P2` | experimental workload information | makes `P1` their public sum |
| self-splits target exactly those two role notes | experimental workload information | enables later requested+remainder sums to recover the parent values |
| requested/remainder/final checkpoint labels and boundaries | experimental evidence metadata | not produced by the cryptographic protocol itself |
| no other payments or receipts occurred | experimental workload information | eliminates alternative gross histories |

## Which deductions depend on which facts

1. **Direct target P1 is exact:** public exit amounts plus the experimental rule
   that the two exits are `P2` and `P1-P2`.
2. **Direct target P2 and relationship are exact in the known view:** public exit
   amounts, payout-owner mappings and experimental first/second-recipient roles.
3. **Unrelated relationship is exact in the known view:** payout-owner mapping
   plus the experimental one-to-one recipient assignment. This is not a generic
   consequence of a shielded ledger.
4. **Private-change P1 returns after remainder exit:** public requested/remainder
   amounts plus the experimental rule that all four exits partition the two
   original target role notes.
5. **Original funder becomes unique at full drainage:** fixed public deposits,
   complete exits, conservation and the experimental inventory of exactly four
   credits/two chains/no other activity.
6. **Commitment, output-grouping and transaction-position ambiguity remains:**
   declared cryptographic opacity and absence of a public nullifier-to-commitment
   link. It does not negate the payment facts above.

## Consequence for the new model

The candidate model removes the prior two-chain/one-to-one/target-role workload
facts and substitutes a public ordinary-contact graph with three genuine
payments. This is a changed experimental assumption, not a protocol privacy fix.

The earlier strong observer is retained as `strongExternalWorkload`: when the
observer knows that S's payment came from M, the candidate collapses from two
gross histories to one. The isolated known-owner failure control also remains
unique. No legitimate payout identity or adverse evidence is discarded to claim
the bounded possibility result.
