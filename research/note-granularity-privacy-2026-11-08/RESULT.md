# One-note exits reveal four of seven amounts in the retained wallet history

**Decision:** correct the earlier balance-only headline. With the current
one-input/two-output wallet rule and the actual public note-exit amounts,
**four of seven private payment amounts are forced exactly** for an observer who
also knows the payout owners and seven directed contacts. The 47-useful-KAS run
is offline with synthetic funding, so this is a structural attack on genuine
wallet-proof/native-Full records, not a fresh accepted-chain observation or a
population anonymity measurement. No consensus change was needed or made.

## What the stronger observer learns

The [frozen selection](SELECTION.md) fixed the evidence, extra owner/contact
knowledge and stop rules. The [public audit](PUBLIC-AUDIT.json) decoded the
actual native payloads: one credit, seven transfer operations, three 10-KAS
group exits and five final one-note exits. Transfer statements do not publish
their payment value directly; their encrypted deliveries have the same byte
length. The public EXIT statements and native outputs do publish each whole
note's value. Native fees, funding change and final fee refund are also visible.
The three later payment arrivals have a fixed controller schedule, but no
independent network-to-person timing channel was measured.

| Payment | Amounts consistent with note rules and known owners/contacts | Actual |
| --- | --- | ---: |
| A→B | **20 KAS exactly** | 20 |
| B→C | **10 KAS exactly** | 10 |
| A→D | 10, 18 or 19 KAS | 10 |
| D→A before group exit | 1, 2 or 10 KAS | 2 |
| D→B after group exit | **1 KAS exactly** | 1 |
| D→C after group exit | **3 KAS exactly** | 3 |
| D→A after group exit | 1 or 2 KAS | 1 |

Why: B and C each have exactly one note before each exits 10 KAS, so B→C must
be 10 and A→B must be 20. After that exit, B and C have no notes; their final
1- and 3-KAS notes are exactly D's later payments. A can exit either its old
10-KAS change note or a 10-KAS note received from D. A's two final notes are
publicly 2 and 1 KAS. Those choices leave only the [four structural amount
histories](BASELINE-CANDIDATES.json), including the executed one. Positive
integer-sompi and whole-KAS searches give the same four because the terminal
note sizes force the remaining values. This is a **necessary public-shape
constraint**; it does not prove the three non-exact amounts are cryptographically
indistinguishable using the exact commitment/proof bytes or assign equal odds.

The prior [balance-only screen](../matched-payment-privacy-2026-11-08/RESULT.md)
correctly found zero exact values *under its weaker necessary balance model*.
That was an upper bound on possible privacy, not a complete public-record score.
The new note-level attack resolves that gap. With A truthfully disclosing its
own four sent/received values, the single remaining structural history gives
all seven amounts. That is an explicit participant-disclosure control, not an
assumption that the isolated registration service has A's wallet instructions.

## Private merge test

The [offline counterfactual](attack.py) lets A combine its two final notes into
one 3-KAS note, while keeping every payment, owner and balance fixed. It models
one additional public two-nullifier operation. The current circuit, wallet and
ledger **do not implement this operation**, and no merged native transaction was
made. The experiment compares its resulting public payout layout only.

| Model | Distinct whole-KAS amount histories | Exactly exposed payments |
| --- | ---: | ---: |
| Actual one-note exits | 4 | 4 of 7 |
| Hypothetical A merge | 4 | 4 of 7 |

The merge widens a *0.1-KAS grid* from four to 58 structural histories; at
positive integer-sompi resolution its two branches admit 599,999,998
arithmetic possibilities. Those counts are **not** anonymity sets or a price
posterior. Under the predeclared whole-KAS sensitivity, which includes all
seven executed payment amounts, it protects no previously exact amount and
adds no relationship ambiguity. Its visible two-nullifier operation may also
add metadata. **Do not implement the merge for this workload on this result.**
The older [merge proposal](../full-drainage-history-ambiguity-2026-11-01/MERGE-PROPOSAL.md)
remains a scoped idea for reducing terminal note granularity, not an accepted
privacy architecture.

## Cost gate and checks

The merge did not clear the privacy gate, so no new proof, Testnet or complete
cost campaign was run. The actual 47-useful-KAS baseline already quotes
**0.992104 KAS native fees (2.11%)** and an illustrative **8.2123% native-fee
plus measured outer-proof-work subtotal**, before wallet CPU, issuer/network,
availability, storage, margin and other unpriced costs. The merge has no
measured fee or proof cost; it would add a public operation and require a new
security-reviewed proof relation. [Retained cost source](../cached-approval-verification-2026-11-07/RESULT.md)
is not a complete service price.

`PYTHONDONTWRITEBYTECODE=1 python3 research/note-granularity-privacy-2026-11-08/check.py`
passes pinned source hashes, full packet-field audit, an independent exhaustive
whole-KAS note-flow search, executed-truth retention and malformed-packet/wrong-
truth controls. [PREDICTION.json](PREDICTION.json) was sealed before the score
read private values; SHA-256
`d392ea489638af35c0440784e0df8ecb2e277e185a62a15d296571e45d474fc0`.
[RESULT.json](RESULT.json) records the stop decisions. No wallet secrets,
private instructions, real funds, mainnet transactions, new testnet broadcast,
or protected-host access were used.

**Next research implication:** this particular branch's working payment system
has meaningful *internal* confidentiality, but its note-by-note terminal exits
and ordinary participant knowledge expose too much for a strong full-lifecycle
privacy claim. Any next current-L1 candidate needs a specific, measured
improvement against this stronger observer before implementation or cost work.
