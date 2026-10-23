# Complete-route fee screen

Source baseline: pushed `0c2f4c788a4274b381c4838e05cce5e9c32e8536`.
This is a new arithmetic workstream. Historical fee authorizations, native
packets, targets and cost models remain unchanged. No setup, proof, native VM,
funding, broadcast, old S7 owner/replay/DRAIN or wallet implementation is run.

## Gates before an expensive proof campaign

For the same actual 10-KAS payment principal, counted once:

- The ordinary payment costs at most 10,000,000 sompi at reference rate100.
- Admission, payment, ordinary funding, recipient cashout, payer change,
  final tails, service/proving and retries together cost at most 20,000,000.
- Every supported 60,000,000-sompi note can independently reveal, without a
  sponsor or another party exiting, at100/200/500 and retain at least10,000,000.

A direct two-public-limb Groth16 verification alone needs147,500 mass. One
recipient plus change is ONE useful payment, so this necessarily fails the
ordinary cap. Native public admission cannot fix that separate payment failure.
The existing genuine B2 has two useful payments, mass196,484 and actual80M fee;
its9.8242M/payment reference quote is not a new authorized price.

At32KiB the candidate-C terminal byte floor is70,132 mass. Adding one
unamortized G16 ADMIT floor147,500 already exceeds200,000 lifecycle mass before
payment. A general payment leaving a payer-change note has TWO final cashouts;
the one-cashout exact/no-change case must not replace that route.

## Compared routes

1. Existing actual authorizations:40M admission and40M/useful B2 payment fail
   unchanged. These are incompatible historical price anchors, not a composed
   candidate-C lifecycle.
2. Genuine proof-bearing admission and payment batching: retain a necessary
   verifier-floor frontier, then an explicitly conditional emitted-shape model.
   One batch must actually aggregate authorization; executing B separate native
   Groth16 checks does not divide their tariff.
3. Tentative native public ingress: disclose a168-byte note opening plus its
  264-byte receipt, authenticate a512-byte CM append path, consume a real
   ALL-signed funding input, append one CM, leave NF unchanged, and preserve
   `Rnew=Rold+sum(Vj)`. Funding inputs cover their own fee shares/change; old
   liabilities pay none of the admission fee. Architecture has not selected its
   complete wire or emitter. Public descriptor linkage and initialization
   authenticity need their own review. This applies to public ingress only,
   never to a private top-up/merge.

## Arithmetic model and evidence levels

Use native01b532e exact size, budget, transient and KIP9 storage rules through
the existing source-checked calculator. First reproduce actual ordinary1600,
ADMIT and B2 measurements and all relevant candidate-C exit bodies.

New shapes reserve redeem16/24/32/48KiB, budget200 for hash admission/reveal,
and1600/1700 for a single aggregate proof. These are design parameters, not
qualified code or a fee promise. The new common pool witness is redeem+199
bytes: push65(signature65), push128(proof128), PUSHDATA2(redeem). Actual core
PRIVATE payload is4356 bytes. REVEAL retains2029 bytes. Tentative single-note
ingress is1344 bytes including a public genesis-coherence opening; larger
ingress reserves400 fixed plus944/note (168 opening+264 receipt+512 path), and
remains unselected. Shared-header aggregate payload reserves356+4000*Bp,
retaining3344 public state-witness bytes per logical payment and the NF/CM/
ciphertext fields. It reproduces4356 atBp1, but sharing the356-byte header
requires a new binding design. No current proof authorizes that larger wire.
Every unselected byte, budget, signature and output remains an implementation
gap. Arithmetic01 used prior branch-specific stack offsets and an optimistic
all-state-in-proof projection. Its source/output are preserved and superseded
by arithmetic02; it cannot price the new common union.

Fee allocation uses quotient/remainder over real users/payments and sums EXACTLY
to the batch fee. Report the maximum individual share, not only an average.
Current signed bodies are never repriced. A prospective least-fee fixed point
requires a fresh exact authorization; it is not a proof or an executed body.

The ordinary route includes one1B recipient note and a separate60M payer-change
note. The latter is extra returned working capital and NEVER enlarges the1B
denominator. Both notes cash out separately; the payer must not wait for the
recipient or anyone else. Cost both terminal/continuing contexts and the worse
cashout order, with minimum60M other liability and maximum permitted reserve.
Also report exact/no-change as a separate favorable case.

A particularly small legitimate pilot is ONE payer's one-real-plus-dummy input,
ONE core2in/2out proof, and TWO distinct1B recipient outputs with no change.
Fund exactly `2B+private_fee+admission_fee`, not a larger denominator. Allocate
the real shared fees exactly across those two real payments, and charge each
recipient's own independent cashout. This uses no multi-party witness export
and no new aggregate circuit. It is a specialized no-change route, not generic
payment-with-change qualification. Include optional ordinary funding
preparation and leave initialization/service/retries as explicit headroom.

For a genuinely complete isolated prefix, improve that pilot by consuming BOTH
real inputs owned by the same payer: genesis G0=60M and the admitted note
`2B+private_fee−60M`. They become exactly two distinct1B recipient notes. The
native founding transaction, admission, private proof and both orders of
independent recipient cashout are all priced; the last leaves zero reserve.
Genesis is consumed, not an unpriced third tail or someone else's subsidy.
The architecture contract permits those two independently derived input
descriptors to have the same payer. This is the smallest selected-core route
worth pricing before inventing a new aggregate circuit. Each recipient remains
a separate1B denominator and every shared sompi is allocated exactly.
The model includes ordinary founding120M input→60M reserve+same-owner change,
and optional preparation of the main funding input. Source and returned native
amounts reconcile exactly to route fees, including that returned founder change.
An existing-pool one-real-plus-dummy estimate is retained as a separate favorable
case and never reported as complete isolated initialization.

For general multi-owner batching, direct monolithic G16 cannot simply collect
their private witnesses. Without a new MPC protocol it applies only to one
witness owner. Existing separate local child proofs plus a new RISC0 verifier
guest are a source-feasible independent-owner approach, with the155,000 native
verifier floor and an unmeasured new guest. Historical B2 proving already takes
about303 seconds and fails60 seconds. A fee-row pass cannot qualify that route's
latency or private wallet boundary. Lowering1600/1700 budget or dropping native
witnesses requires an actual new source bound/relation, not fee algebra.

Compare whole existing funding-UTXO ingress (all value less fee becomes the new
note) against funding/change and an optional ordinary preparation transaction.
Small native change has real KIP9 cost. All returned native/private change is
retained, never swept into an unrelated user's principal or called a fee.
Initialization, funding acquisition and service/retry costs are explicit extra
charges/headroom; zero modeled extras earn no all-in success claim.

Bounded pure arithmetic/property checks may use at most2CPU/2GiB. Check source
pins, measured anchors, exact per-user allocation, fixed-point minimality,
cashout conservation, storage domination and monotonic envelope failures. No
heavy resource job is justified by an optimistic arithmetic pass alone.

## Batch availability and next decision

Healthy payment batching must fit the60-second authorization-to-spendable target
including fill wait, proving, submission and recognition. Report an explicit
arrival/service assumption and partial-batch price failures. A singleton exit
always uses its own hash/signature branch and never waits to fill a batch.
Rejected unaccepted transactions normally pay no chain fee, but local proving,
service and replacement work still costs time/money. Count actual accepted
extra operations and lost work; do not invent a second chain fee for an orphan
or silently treat retries/service as free.

Select the smallest source-feasible shape with positive per-user residual for
all those costs, then measure its actual wire/units/native dimensions and
authorize genuine fees before setup/proving. An arithmetic failure stops that
economic route. A pass earns the next bounded construction, not a complete
private lifecycle, useful privacy, accepted backing or production claim.
