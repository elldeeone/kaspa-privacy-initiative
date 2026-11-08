# The larger real-wallet history does not make the bundle a payment-privacy gain

**Later stronger correction:** the [note-granularity attack](../note-granularity-privacy-2026-11-08/RESULT.md)
uses the actual wallet's one-note EXIT rule and public final note sizes. Under
the same supplied owners/contacts it forces **4 of 7 amounts exactly**. The
zero-exact figure below is this study's deliberately weaker balance-only
necessary bound, not a complete public-record privacy score. The board still
changes none of the amount constraints.

**Decision:** keep the public blind-reply bundle only as the separately tested,
optional service-timing repair. Do not spend another independent-machine or cost
campaign trying to make this bundle the full payment-privacy architecture. In
this matched four-wallet workload it changes **zero public payment amount
equations** and no supplied contact facts. This is a current-L1 research decision;
no consensus change or new network transaction was made.

## Plain result

We reused a retained 47-useful-KAS history: four wallet processes made seven
genuine private payments, three people withdrew 10 KAS each, five more payouts
drained all 40 KAS principal, and all eight payout keys made valid offline
restored-key spends. The existing six native Full transactions used a synthetic
funding output and were **not accepted on chain**. The ordinary arm is its real
three issue/redeem pairs. For the bundle arm we repackaged the **same real three
blinded requests and signatures** into one compact 9,259-byte board; the existing
public RSA checker accepted it. Wallets did **not** redeem this repackaged board
in the 47-KAS run. The earlier separate small TN10 bundle trial establishes an
accepted current-L1 transaction, not acceptance of this particular board.

The balance-only observer knows the contact edges and order, the initial 40 KAS,
and who ultimately received each payout. Those owner/contact facts are declared
extra knowledge from the research controller. They are not automatic facts for
an arbitrary chain watcher. Under positive integer-sompi payments and no other
deposits, all seven actual amounts remain possible:

| Payment | Balance-only possible amount, KAS |
| --- | ---: |
| A→B | 20 to 23.99999998 |
| B→C | 10 to 12.99999999 |
| A→D | 3.00000004 to 20 |
| D→A before group exit | 0.00000001 to 12.99999999 |
| D→B after group exit | 0.00000001 to 1 |
| D→C after group exit | 0.00000001 to 3 |
| D→A after group exit | 0.00000001 to 3 |

The ranges are **necessary balance constraints**, not a claim that every
alternative history would match the entire public proof transcript, network
timing, plausible prices or wallet behavior. The equations still expose useful
net-flow facts: B's first post-exit balance plus its later receipt is 1 KAS;
C's first post-exit balance plus its later receipt is 3 KAS; A's pre-exit net
outflow determines its later D receipt. The public board changes none of these
equations. The same three equal group payout scripts still have six possible
owner assignments to the isolated service, two if one participant reveals their
own key, and one with all payout owners supplied. The ordinary service-only
transcript already had six compatible assignments; this fixture does not retest
a malicious issuer's per-client timing attack.

As an **extra assumption**, requiring every transfer to be a whole KAS leaves
99 balance-feasible tuples and makes D→B exactly 1 KAS. That is a price-policy
sensitivity, not a public protocol rule or anonymity-set estimate. It shows how
a small, plausible amount prior can narrow the apparent uncertainty. The prior
four-payment accepted-chain control already forced two amounts exactly under
its own fixed known-owner contact pattern; this larger history does not erase
that negative result.

## Evidence and limits

The [selection](SELECTION.md) froze the source hashes, observer views, scoring
rule and stop condition before prediction. The [predictor](compare.py) checked
those hashes, the real payout records, owner-control outpoints and service
messages, then wrote [PREDICTION.json](PREDICTION.json) before reading
[TRUTH.json](TRUTH.json). Prediction SHA-256:
`147192c8496989ca50e10a796b9c8cd519f3a8c854d8fbff9de47a205ba3455e`.
The [score](RESULT.json) retained all seven actual amounts, found zero exactly
forced under the primary balance model, and triggered the predeclared stop rule
because the ordinary and board arms have the same payment facts.

`python3 research/matched-payment-privacy-2026-11-08/check.py` passed: pinned
source hashes, sealed prediction, actual-history replay, genuine public board
verification, and rejection of a broken signature, partial board and altered
payment truth. The fee refund uses the same script as the funding change; fee
origin is still linkable. No independent people, live network timing, 47-KAS
bundle fee, or production privacy were measured. This is not a matched code-level
comparison with Olaf's different two-user Testnet workload.

**Next research gate:** a proposed current-L1 mechanism must name a particular
payment fact it changes under known owners and full withdrawal, then beat this
ordinary-reply baseline on the *same* actual workload before more cost or
Testnet work. The bundle's separately proven timing benefit remains available
as an optional component.
