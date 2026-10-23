# Fee feasibility after the private-exit rehearsal

**The current two-output route cannot meet 2% at 10 KAS, even with much cheaper
entry. Extending its existing unrolled native CM-update code to wider payments
also fails a generous lower bound. This does not exclude a compact redesigned
direct-Groth16 architecture.** The next useful experiment is a source-only
wider-payment wire/program cost screen, before another circuit or setup.

This memo uses the pinned rusty-kaspa v2.1.0 source at
`01b532e8b553523216471682649693af92f0fd16`, selected private-native source02 and
the eight actual body rows in
[`ACTUAL-FEE-PROFILE-01.json`](../native/ACTUAL-FEE-PROFILE-01.json). The latter's
SHA256 is `8274ae92e814bfedf700ddfc8bf70956cc7b2a5f1c874460a1feb57c88b1afee`.
It describes fixed rate100 authorizations, with hypothetical higher-rate quotes.
The retained founding-payload and compute/relay reporting
[errata](../native/FEE-SHAPES-01-ERRATA.md) still apply.

All comparisons count a useful 1,000,000,000-sompi payment once. Its complete
fee cap is 20,000,000 sompi, or 200,000 normalized mass at rate100. N below means
N distinct receivers, each receiving one10-KAS private claim and exercising its
own complete exit. It does not mean splitting a larger payment to one receiver
into multiple counted payments, or replacing an owner's cashout with a
sender-issued transparent payout. Each receiver exits without another receiver's
secrets, participation, future arrival, re-entry or mandatory delay. Batches are
a single payer's already demanded simultaneous useful payments, never
manufactured users. Other demand/recipient-count models need their own screen.

## Which costs are fixed, and which are choices?

The native [Groth16 tag](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs#L29-L35)
charges 140,000 grams. [VK metering](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L16-L46)
adds 250,000 script units per gamma-ABC element. The present two-public-input
statement has three elements: 14,750,000 units, or 147,500 mass, before public
checks and transaction bytes. These are native charges, independent of prover
speed. The two-field digest representation is a profile choice; fewer public
inputs require a separately reviewed binding/circuit design and do not remove
the 140,000 base tag. No alternative cryptographic encoding is selected here.

The [mass calculator](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L335-L373)
charges v1 compute mass as estimated bytes + 10 times output SPK bytes
(including versions) + 100 times committed input budgets. Under these parameters,
normalized mining mass is `max(compute, 2*estimated_bytes, contextual KIP9 storage)`.
Storage depends on actual integer amounts and can dominate a small-output entry.
A compute reduction is not automatically a relay or mining reduction.

The current selected private budget is **1600**, not 1601. The
[budget units](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L4-L19)
give allowance `10000*B + 9999`. Four actual positive private paths used
14,846,698–14,961,272 units. Budget1500 would allow 15,009,999 units and reduce
compute by 10,000 mass, or 1,000,000 sompi per action while compute dominates.
That is a conditional saving, **not a safe selected budget**. All valid Merkle
index bits, predecessor sentinel/non-sentinel intervals, numeric operand sizes,
dispatch and stack charges need a conservative source upper bound. The observed
maximum alone would fit1496; four samples do not establish a worst-case bound.
The current1600 budget remains unchanged.

Other present choices are a 24,417-byte common redeem carried by every spend,
Auth528, cipher528, public updates3344, a fixed two-output proof shape, two dummy
CM appends on continuing full-claim cashouts, and the selected entry sequence.
They are not all unavoidable costs of native KAS or all direct Groth16 designs.

## Entry is substantially cheaper in a different existing shape

The selected rehearsal pays 8,742,200 sompi for prep + founding + admission.
That is its actual cost, not an unavoidable entry floor. Existing
`native.rs::founding_body` accepts any note value from60M throughMAX and builds
the coherent singleton root. A payer can instead found its whole required
sender balance directly from an existing ordinary coin, then consume that note
in the payment. There is no extra payer, receipt, hidden re-entry or surviving
founder claim in this proposed sequence.

For one input with its existing66-byte signature, one35-byte raw pool SPK,
GN536 and budget10, estimated bytes are
`94+54+66+53+536 =803`; compute is `803+370+1000 =2173`, versus normalized
transient1606. A source-only fee of217,300 sompi is a plausible exact fixed point
for a large note and one output if contextual storage is no larger. This is
**not an emitted quote, native acceptance or guaranteed storage bound**. A source
coin with change and any small tail must be modeled explicitly. The existing
60M founding's measured25,746 mining mass was storage-dominated; its compute
mass was only2585. The old GN-omission row must not be used.

An exactly sized coin is not required to remove prep/admission. For the existing
4B source value, a2,018,958,700-sompi whole sender note and1,980,782,800 ordinary
change leave258,500 sompi fees. The two-output founding shape has compute2585,
normalized transient1710 and source-formula storage749, so258,500 is a
source-arithmetic fixed point with all change visible. This example is not a
new constructed/native-validated transaction. The2173 entry used in lower bounds
below remains deliberately more generous.

## Two outputs cannot be rescued by a larger sequence

One useful recipient requires a sender payment proof and its own exit proof.
Even the two native base tags cost280,000 mass (2.8%) before entry. With two
useful recipients, one payment and two independent cashouts cost three base tags:
210,000 mass per recipient (2.1%), or221,250 (2.2125%) with the current two public
inputs. Merely changing public-input arity, code or entry cannot save this route.

More generally, a single payer delivering N final recipient claims through the
current two-output action needs at least N−1 payment proofs: each extra action
adds at most one final claim while retaining sender change until the last.
N independent exits then require at least2N−1 proofs. For N>=2 the base-tag-only
mean `140000*(2−1/N)` exceeds200,000; the current-PI bound is
`147500*(2−1/N)`. Natural larger sequential batches do not amortize this away.

For scale, the measured shape atoms for one two-recipient payment, one continuing
full cashout and one terminal cashout total56,916,200 sompi before entry. With the
optimistic217,300 entry they total57,133,500, or2.856675% per10-KAS payment.
Hypothetically selecting1500 for all three reduces this to2.706675%. This is
source arithmetic on shape atoms, not a newly executed complete sequence.
The rehearsal's extra partial exit is charged separately to Bob in its result.

## Wider one-payer payments: necessary bounds, not a qualified design

A genuinely N-output sender proof could use one payment verification plus N
independent exit verifications. Its current-arity verifier-only mean
`147500*(1+1/N)` falls below200,000 at N=3. This is why the two-output failure
does **not** prove that every direct-Groth16 architecture fails. At N=3 only
3,333.33 mass per recipient remains for all bytes, native checks and entry.

Consider an intentionally generous hypothetical shape: the current exit wire
stays two slots, every independent full cashout uses one continuing exit except
the last terminal exit, and the sender's public output material scales as
`Auth=(464+32N), cipher=264N, updates=(2320+512N)`.
Thus payment payload is `2784+808N`. There is no extra metadata/VK/framing,
no storage domination and a2173-mass direct entry. If B is a common valid budget
and ΔL is the net common-redeem growth, its necessary mean compute floor is

`A(N,B,ΔL) = 100B +30807 +(100B+29721)/N +ΔL*(1+1/N)`.

The423/N reduction accounts for the cheaper last terminal shape. This floor
retains the current wire constant and ignores any further runtime growth.

| Hypothetical common budget | First integer N fitting the floor if ΔL=0 |
|---|---:|
|1475: Groth16-only allowance; real public checks omitted|9|
|1500: observed examples fit; worst-case validity unproved|10|
|1600: current selection|21|

These are necessary arithmetic thresholds, not demonstrated sufficient batch
sizes. For example N32/B1600 allows only3,165 net additional common-redeem bytes;
N16/B1500 allows7,492. Extra native work and storage consume those margins too.

### A direct extension of the present unroller is excluded

Current `policy.rs::append_cm` emits two16-level native Merkle walks. For each
added slot>=2, a source lower bound is at least48 encoded bytes per level:
state-index13 + power-push>=1 + arithmetic/IF4 + two payload slices14 +
Swap/Else/EndIf3 + concatenation/tag/SHA13. Two walks plus their fixed43 bytes
therefore add at least **1579 redeem bytes per output**. Even a compact exit
that skips that work still carries the complete immutable common redeem.

If the original24,417 bytes are retained without unrelated code shrinkage,
`ΔL >=1579*(N−2)`. With the unrealistically favorable B1475, the previous floor is

`A >=176728 +1579N +174063/N`.

Its integer minimum for N>=2 is N11:
**209,920.909 mass, or2.099209%** before any extra execution/storage costs.
This excludes that precise common-redeem/unrolled-update candidate for every N.
If every exit also carries the wide N-slot padding, add `808*(N−2)` per receiver;
the lower minimum becomes215,935.333 mass at N9 (2.159353%). Larger offsets,
framing, verification keys and genuine resource budgets only raise these bounds.
The byte count and compact-exit formula were independently source-reviewed.

This is not a lower bound on refactored, interpreted or otherwise compact state
transition policies. Reducing common code or changing which transitions the
existing proof relation authenticates changes the assumptions and needs a new
cost/security review. Removing a native root check without constraining its
replacement in the proof would weaken the protocol, not optimize it.

## Smallest decisive next experiment

Freeze source-only candidate shapes for a payer's already demanded N=4,8,16,32
simultaneous10-KAS payments. Keep each receiver's own complete exit and charge all
entry/ordinary change, terminal tails and fees exactly once. Compare fixed-wide
exit padding with a compact exit shape; neither may require receiver cooperation,
mandatory waiting or a future payer. Define the unchanged privacy observations
before choosing a shape that exposes full-versus-partial spend information.

Before any circuit/setup, obtain the actual candidate common-redeem lengths,
payload lengths and conservative valid-path budgets from its source, then check
`entry + payment + (N−1)*continuing_exit + terminal_exit <= N*200000`
using normalized mass and actual integer amount/storage fixed points. The current
unroller can be rejected already. A compact candidate must beat the exact net-code
growth margins above; zero-proof wire construction/quotes are preparation only.
If its lower bound fails, stop before cryptographic implementation. If a source
upper bound fits, that only warrants a new reviewed circuit/actual proof and
native lifecycle experiment plus the privacy/recovery gates. If bounds straddle
the target, tighten the source model first.

No implementation, budget change, proof, setup, VM, rental, funding or broadcast
was performed for this memo. The pinned source and rational arithmetic are in
[`BOUNDS-01.json`](BOUNDS-01.json). No architecture decision or universal fee
qualification is asserted.
