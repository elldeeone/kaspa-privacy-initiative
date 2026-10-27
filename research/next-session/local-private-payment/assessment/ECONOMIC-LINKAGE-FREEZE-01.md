# Public economic linkage observer: frozen design

Frozen at **2026-10-26 03:04:28 UTC**, before reading the actual final payouts.
The [machine policy](ECONOMIC-LINKAGE-POLICY-01.json) fixes the observer, algorithm,
metrics and negative controls. No threshold, posterior or privacy PASS is defined.

The observer knows only public genesis CM positions and three equal20-KAS note
values; six payment NFs, fees, output CM positions and chronology; nine terminal
exit NFs, payouts and fees; and zero terminal reserve. It receives no target
payment amounts, owner mapping, original wallet, private plan/log/truth or old
six-output metric. Public transactions already group two output CMs; that direct
grouping is not a newly inferred linkage. Address, endpoint and timing-correlation
models beyond the strict event order are separate channels.

Source inspection confirmed the amount rules: `integration/native_fees.py` sets
each exit payout to the entire note value minus its exact exit fee;
`relation/src/statements.rs` and `circuit.rs` enforce payout+fee=note value and
the60,000,000-sompi positive note floor. A payment has zero native payout and
its exact public fee leaves both the reserve and private value. External deposit
funding fees do not reduce the three admitted20-KAS note values. The selected
wallet `payment.py` creates both outputs with the same tuple/receipt adapter and
randomly reverses their order; the analysis assumes neither public slot is a
PAYMENT/CHANGE label. It does not claim that source inspection proves encryption
or proof security. Note identities are `(CM, public_position)`; historical CM
repeats do not merge positions.

For exit subset E and payment subset P, a candidate note subtree has value
`sum(exit payout+exit fee in E)+sum(payment fee in P)` and `|E|=|P|+1`.
There are6,435 shape-valid mask states. Its earliest consumer in the strict public
event order must be its root: an exit only for a one-leaf subtree, otherwise a
payment. Split the remaining events into two valid later child subtrees. Use
the least exit index to canonicalize child order; retain distinct public event
identities even when amounts or fees are equal. A canonical exact cover selects
three disjoint components, each worth20KAS, covering every event exactly once.
Big integer counts and possible/must feature sets avoid enumerating full forests.

Report canonical forest counts, joint payment/exit root-cover counts and distinct
exit-only partitions separately. Also report possible/must co-root exit pairs,
payment ancestry and direct input-parent payment groups. A possible parent payment
exposes both of its CM slots as candidates; a genesis parent exposes all three
equal-value root positions. The canonical forest count quotients child swaps and
root-label permutations; labeled-slot counts multiply by2^6, and labeled-root-CM
counts also multiply by3!. These are combinatorial counts, not probabilities.

The fixed counterfactual masks exit payouts while retaining exact public fees,
root amounts and chronology. An exit's minimum gross is
`max(NOTE_FLOOR,PAYOUT_FLOOR+exit_fee)`. The exact candidate set must be contained
in this masked set. Reductions measure incremental economic constraints; the
counterfactual is not an alternate observed ledger or a privacy pass.

Negative controls include an independent small forward consumer-to-live-note
enumerator; an exactly counted symmetric9-exit fixture; a unique economic
partition toy; a one-sompi accounting tamper; impossible chronology; CM-label
permutations; extra owner/private field rejection; and exact-versus-masked set
containment. In the symmetric fixture all six payment fees are1,000 sompi and
all nine exit grosses are666,666,000: expect280 exit-only partitions,25,200 joint
root covers,680,400 canonical forests,43,545,600 labeled-slot forests and
261,273,600 fully labeled forests.

Run the actual analysis only against an explicitly selected terminal public
ledger. Zero models or invalid conservation is retained as an input/model failure;
do not tune the observer or infer a unique linkage from it. Asset ancestry does
not imply common ownership: payments can transfer spend authority. Three equal
founding values retain three-way root-owner symmetry. This bounded observer does
not establish general financial privacy, network anonymity or a cryptographic
break. Old passive128-world statistics remain withheld until their own aggregate.
