# Fee decision: price the two-recipient core before a larger circuit

**The smallest promising route uses the selected core unchanged:** one payer
owns the 60M genesis note and one public-admission note, consumes both real
inputs in one 2in/2out proof, and pays two distinct 1B-sompi recipients with no
change. Both recipients can reveal independently and the last leaves zero
reserve. This avoids a new aggregate circuit, multi-party witness sharing and
an unpriced genesis tail. It is a favorable workload, not a general
recipient-plus-change or independent-owner batching result.

At the root/native agent's **compiled 22,388-byte three-branch union**, the
source-exact integer model puts the complete approved route at a maximum
**18,517,700 sompi per actual 10-KAS payment**, including ordinary preparation,
founding, native public admission, private authorization and each recipient's
own reveal. It leaves 1,482,300 per payment for unpriced proving/service/retry
costs. Ordinary private fee allocation is 9,375,700, leaving 624,300 under 1%.
These are prospective exact-body targets. Actual selected VK/proof/native
MassCalculator/Full/meter results take precedence; no new native or proof was
run by this fee workstream. The emitted length used placeholder values only
for sizing; budgets 1600(private),200(admit/reveal),10(funding) need qualification.

## Exact approved prefix at reference 100

Start with one externally supplied 4B source UTXO. Its ordinary signed
preparation creates 120M founding coin,1,963,601,800 admission coin and
1,915,486,800 returned native change. Preparation costs 911,400:370 estimated
bytes,2450 compute,1480 transient, **9114 KIP9 storage/mining mass**. This is
one explicit source oracle, not a demonstrated accepted-chain deposit.

| Operation | Modeled fee, sompi | Result |
|---|---:|---|
| Ordinary preparation |911,400|Both actual funding coins and all source change|
| Coherent founding from 120M |2,574,600|60M genesis liability;57,425,400 native change|
| Native ADMIT, no change |4,850,400|Note 1,958,751,400; reserve 2,018,751,400|
| Private 2-real-input proof |18,751,400|Two distinct 1B recipient notes; reserve 2B|
| First recipient reveal |4,973,800|Payout 995,026,200; reserve 1B|
| Final recipient reveal |4,963,200|Payout 995,036,800; reserve 0|

Shared prefix costs 27,087,800, allocated **13,543,900 each** with integer
quotient/remainder shares. Add each actual recipient's own reveal:18,517,700
and 18,507,100. Swapping exit order swaps those burdens; nobody must wait for
someone else to exit. Total fees are 37,024,800 and all returned native outputs
sum to 3,962,975,200: `4B−returned=fees` exactly. The 4B source, change,60M genesis
and recycled amounts never enlarge either recipient's 1B denominator.

The earlier 120M/C0 target packet remains an explicit alternative with a
different optional funding preparation. The abandoned two-provided 4B-coins
proposal is not this route. No historical 40M/80M authorization is repriced.
[Exact approved prefix](complete-prefix-4B-source.json) and
[sizing/fee targets](actual-size-22388.json) retain those evidence boundaries.

## Independent smallest claims and all tails

At 22,388 bytes, the 60M claim's continuing branch has mass 49,738; at 500 its
fee 24,869,000 leaves 35,131,000, above 10M without an external fee input. Terminal
mass is 49,632. Minimum remaining positive liability 60M is the hardest continuous
storage endpoint. The [rational all-values bound](STORAGE-BOUND.md) includes
integer-floor slack and covers every supported V>=60M and remaining reserve
either 0 or>=60M for the 16/24/32KiB conditional profiles. It does not erase the
historical 10M/20M remainder failures.49KiB fails 500 from full transient mass.

All genesis liability is consumed in the chosen private proof. Every returned
native change output is retained; nothing is swept, called an unrelated user's
fee or silently dropped below a new minimum. The generic recipient-plus-change
route instead has TWO final claims per useful payment and costs both. It
cannot borrow this no-change pilot's favorable accounting.

## Why admission and ordinary batching remain separate

An individually verified recipient-plus-change payment executes a direct
Groth16 tariff of at least 147,500 mass, costing 14.75M at 100 before body bytes.
That route necessarily fails the 10M ordinary cap. Removing the ADMIT verifier
does not fix it. The historical genuine B2 costs actual 80M/40M per payment;
its lower 9.8242M reference quote is not an authorized price for a new format.

Native public ingress is source-feasible as the separately reviewed 1344-byte
extension: disclose public Note168/cipher264, authenticate the current empty CM
append, preserve NF, require a real ALL-signed funding input and
`Rnew=Rold+V; E=V+fee+change`. Old liabilities pay none of this ingress fee.
It still requires its real emitter/control/initialization/privacy review and
must not be generalized to a hidden private top-up/merge.

For a later generic batch, the [1536-row model](arithmetic-04.json) keeps real
per-payment integer allocations and whole-cohort conservation, including
ordinary founding and all private/native change. Its hypothetical shared-header
wire is 356+4000B, retaining 3344 native state-witness bytes per logical payment;
even that sharing and budget are unselected. Arity rows above 1 are optimistic
structural screens, not existing accepted authorizations. Minimum cohort is
LCM(admission arity,payment arity), with actual startup costs charged over only
those actual useful payments; no future imaginary participants subsidize it.

Direct monolithic aggregation requires one witness owner; it cannot gather
other users' private witnesses. Separate local proofs plus a new RISC0 verifier
guest are an established independent-owner seam, but historical B2 proving is
about 303 seconds and already fails 60 seconds. A cheap fee row does not repair
that latency or qualify CPU-only laptop operation. More payments are not useful
unless the whole new authorization, public updates, fee allocation and healthy
fill/prove/recognize latency are actually measured. Partial singleton batches
retain their ordinary-price failure; independent reveals never wait to fill.

## Stop/go and what remains

The real 22,388-byte code passes the size screen; keep the selected full-route
fees as targets for the smallest genuine private/native integration. Measure
the actual bodies, proof, all input units and every mass dimension, including
both independent exit orders. If actual script/wire/budget makes either fee
cap fail, record that economic failure; a security-integration proof may still
be valuable, but a long larger-batch proving campaign needs a new decision.

For the high-L two-recipient shape, complete founding+admit+private+reveal cost
before preparation is `350L+10,226,200` per payment at private budget 1600.
Thus 27,925 bytes is the bare lifecycle cap, before preparation/service/retries;
32KiB already fails. Budget 1700 tightens that bare cap to 26,496. At actual
22,388,1700 adds 500,000 per payment and still needs genuine unit/fee qualification.
Operational budget is not cryptographic work saved, and cannot reprice a proof.

Ordinary funding preparation is now priced. Proving/service/retry costs remain
unpriced headroom, not zero. A rejected unaccepted body normally pays no chain
fee but can waste local/service proof work; accepted extra operations must be
charged. Reorg/fee replacement semantics, healthy latency, parameter loading,
CPU-only 4-core/16GB/4GiB wallet limits, accepted lineage, authentic public data,
recipient backup recovery and actual privacy remain open. This arithmetic
does not close R1–R8 or make the new format compatible with old notes.

## Reproduction and retained corrections

All executed work here is bounded Python arithmetic, affinity at most 2CPUs and
address-space limit 2GiB. The model reproduces three measured native cost anchors,
exact fee-share sums, fixed-point minimality toy cases, current common-stack
sizes, cashout conservation and whole-cohort source/returned-value equality.
The all-values storage bound uses exact rational arithmetic, not floating point.

Run `PYTHONDONTWRITEBYTECODE=1 python3 model.py --output NEW.json` from this
directory with the repository and pinned local native checkout present. The
source-04 snapshot/manifest records the executed code; helper SHA is checked
before import. `python3 actual_size.py --redeem-bytes 22388 --output NEW.json` prices the
reported emitted length; `prefix_prep.py` records the chosen one-source plan.
Those latter scripts refuse overwriting their retained output filenames.

[Arithmetic erratum](ARITHMETIC-ERRATUM.md) preserves 01's historical stack
offsets;02 corrects to common 199/public witnesses;03 adds the full isolated
pilot;04 adds founding/G0 consumption to generic cohorts. Original sources,
outputs and logs remain. An import-generated bytecode file outside this owned
directory was removed; the [cleanup record](generated-bytecode-cleanup.json)
retains its identity. Frozen source/evidence contents were unchanged. No Git
index, commit, push, native runtime, proof, funding or broadcast occurred here.
