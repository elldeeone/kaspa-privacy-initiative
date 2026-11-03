# Native terminal-claim cost envelope

A proof-free claim is not subject to the Groth16 tariff. The pinned vProgs
permission script is a concrete compact example: its selected final-claim shape
has a conservative source-derived mass envelope of **4,987 grams at depth1**,
or **2,493,500 sompi at rate500**, including a separate signed1-KAS fee input and its change.
This is source accounting, not a measured native result or an independent-exit
qualification. Its unchanged fee contract requires **external fee funding**;
it cannot subtract that fee from the60M authorized liability.

Three separate conclusions matter:

1. Hash/Merkle/native-signature work does not inherently make a60M claim
   uneconomic. The complete transaction and storage context decide that.
2. Tiny reserve/change outputs can exceed the budget even with no proof. A
   separate ticket and a shared-reserve claim have different storage costs.
3. A cheap terminal claim alone does not fix the known10-KAS lifecycle. One
   unamortized ADMIT verifier leaves only52,500 grams at reference100, whereas
   the actual B2 ordinary quote is98,242 grams per payment before any exit.

No candidate or new fee contract is adopted here. No script, transaction,
witness, signature, circuit or proof was generated. The pure integer
[calculator](cost_envelope.py) produced [the final source-verified arithmetic](cost-envelope-05.json);
[the initial arithmetic](cost-envelope.json), [first frontier extension](cost-envelope-02.json) and [reviewed03 output](cost-envelope-03.json) and [corrected04 output](cost-envelope-04.json) are retained. The [erratum](ARITHMETIC-ERRATUM.md) records the corrected fee-cap row reporting defect; economic outcomes and positive results were unchanged. The current calculator verifies both checkout revisions and each native/vProgs source blob before calculating; the result pins its own calculator SHA. It independently
reproduces the already measured paired196,484 and prospective ordinary190,511 /
ADMIT191,631 compute masses from their sizes and commitments.

## Pins and exact native accounting

Native source is `kaspanet/rusty-kaspa`
`01b532e8b553523216471682649693af92f0fd16`; the vProgs source is
`f9b84a863a7c7c20586a9cf947550475e894f72e`. vProgs' lockfile uses native
`9fdbaf1b1886fb5742783d2da73c36239bd6f272`, so a host01b532e probe is an explicit
source adaptation, not the original upstream test configuration. The JSON
records21 exact source/artifact paths, sizes andSHA256 values. Current S7
historical policy/fees are unchanged.

For version1, no native covenant output binding unless separately counted:

```text
E =94 +54*input_count +sum(signature_script_bytes)
    +sum(18+raw_output_SPK_bytes) +payload_bytes
    +34*number_of_covenant_bound_outputs
C =E +10*sum(2+raw_output_SPK_bytes) +100*sum(ComputeBudget)
T =4*E
M =max(C, ceil(T/2), S) =max(C,2*E,S)
```

The94-byte transaction overhead is an estimated mass serialization, not a
network wire-size promise. Standard P2PK rawSPK34 contributes52 estimated bytes
and360 compute grams; standard P2SH rawSPK35 contributes53 bytes and370 grams.
A covenant output adds34 estimated bytes, and its identifier affects storage
plurality. Native dimension limits are C<=500k, S<=500k and T<=1M.
[Estimator/masses](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L21-L99),
[compute/transient](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L335-L367),
[parameters](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/config/params.rs#L615-L629).

One budget unit allows10,000 script units, with9,999 free units per input. The
minimum covering commitment is floor(U/10,000), and each committed budget unit
costs100 compute grams. A successful ordinary Schnorr costs100,000 verification
units plus its one-byte true result:100,001; its covering budget is10. Script
units and mass are not interchangeable. SHA256 charges input_bytes+32 pushed
result bytes; Blake2b charges2*input_bytes+32. CAT, substring, duplication and
introspection charge newly created bytes; literal pushes and stack moves do not
add those runtime byte charges. A P2SH wrapper adds2*redeem_length+33 units.
[Units](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L4-L23),
[covering budget](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L77-L85),
[opcode charging](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L61-L71),
[execution/moves](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L577-L598).

For storage, p=ceil((63+rawSPKbytes+32*has_covenant_id)/100). Thus normal P2PK
and P2SH have p1, while covenant-bound P2SH has p2. Set K=10^12. Output terms
are **floors**, sum floor(K*p²/value), with checked output arithmetic. The
relaxed input credit is sum floor(K*p²/value) when output plurality is1, or
when at most2 inputs have total plurality1, or both total pluralities are2.
Otherwise credit is `input_plurality_sum * floor(K/max(1,
input_value_sum//input_plurality_sum))`. Subtract with saturation at zero.
Do not replace the general three-input case with harmonic subtraction.
[Exact storage implementation](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L439-L512).

Default relay uses100 sompi/gram on max(C,2E), excluding S. The100/200/500
scenarios here instead price complete mining mass M, including storage. There
is no claim of live fee conditions. Standard script classes and <=15 classic
P2SH sigops are separate requirements; one Schnorr fee input is well below
that sigop ceiling. A wallet's separate generator size/dust heuristic must not
be substituted for consensus or mempool limits.
[Actual relay and standardness rules](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/mining/src/mempool/check_transaction_standard.rs#L11-L104).

## The60M claim envelope

A60,000,000-sompi liability retaining at least10,000,000 payout permits at most
50,000,000 attributable sompi of fees:

| Scenario rate | Maximum affordable full mining mass |
|---:|---:|
|100|500,000|
|200|250,000|
|500|100,000|

For a separate ordinary p1 ticket of value V60M paying a=V-fee to one P2PK:
`S=max(0,floor(K/a)-floor(K/V))`. The calculator solves the integer fee/storage
fixed point rather than quoting storage before fee subtraction. Conditional
illustrations, each requiring a separately emitted and metered script:

| Complete signature script | Assumed budget | Mining mass | Fee100 | Fee200 | Fee500 |
|---:|---:|---:|---:|---:|---:|
|1,024B, no payload|11|2,684|268,400|536,800|1,342,000|
|4,096B, no payload|50|9,656|965,600|1,931,200|4,828,000|
|24,709B +5,231B payload|100|60,280|6,028,000|12,056,000|30,140,000|

All three arithmetic shapes leave at least10M at500. These are parameterized
shapes, not existing permission-script measurements or a claim that the
specified budgets cover unspecified guards. If60M is the required net payout,
the ticket must instead prefund60M+fee. A signing key supplied separately from
a note is not proof of that note's existing ownership/nullifier relation.

Shared-reserve splitting can fail before hash work. A p1 reserve70M, a60M
liability and10M surviving reserve change have storage at least
`floor(K/60M)+floor(K/10M)-floor(K/70M)=102381`, even at zero fee. This exceeds
the affordable100k at500. Deducting fees from the payout only increases that
storage term. A one-sompi change output is far worse. Do not infer affordable
claim support for every reserve/payout ratio from a terminal1→1 example.

Separate ticket issuance also has a storage cost. From one standard p1 reserve,
N standard p1 tickets at60M each contribute N*16,666, minus the input credit.
Even the zero-fee/nochange31-ticket lower bound is516,109, above500k. Thirty
can fit storage at499,425 before other dimensions and change are considered.
Covenant-bound p2 tickets contribute66,666 each; eight exceed500k, while seven
can fit storage. These are native storage restrictions, not proof tariffs.

## Established vProgs permission claim: compact, public, externally fee-funded

The upstream permission script commits accepted `(destinationSPK,amount)` leaves
and checks old-root membership, the bound public destination, amount deduction,
new root/count, continuation and delegated backing. It is anyone-can-submit:
the permission branch has **no Schnorr and no SNARK**. A fee payer's signature
is separate. No new primitive or privacy-preserving note-opening relation is
being inferred from this public entitlement mechanism.
[Emitter contract](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L1-L17),
[public witness builder](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/test-suite/tests/permission_spend.rs#L155-L179).

The actual emitter has L=445+22d bytes for depth1..32. Its witness pushes each
path twice, with sibling32+push1+direction1 per level. For a34-byte destination
and60M amount/deduct, the complete permission signature script is
`S=L+68d+52=497+90d`. The delegate redeem is53B plus one push byte. With one
permission input, one exact60M delegate input, one signed nondelegate fee input,
no change, no payload and one terminal P2PK output, `E=925+90d`.
[Exact emitter lengths](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L117-L162),
[builder](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L657-L710),
[delegate bytes](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/abi/src/delegate_script.rs).

A deliberately broad source bound, independently checked against the emitter
and native stack/charging rules, is:

```text
permission units U <= L² +4L +139 +65*(2d+3)
```

There are at most L executed opcodes and at most one newly created stack item
per emitted opcode, each of length<=L for the selected standard-SPK profile.
Thus L² overcounts all runtime pushes, including skipped phases. There are
2d+3 SHA calls with at most65-byte inputs. The two possible L-byte Blake2b
calls (wrapper and successor),53-byte delegate hash, wrapper hash result and
comparison add4L+106+33. This bound excludes arbitrary nonstandard SPKs. It
bounds charging, not state-update soundness or accepted authorization.
The delegate input bound is32*53+2*53+33=1,835 units, within budget0's free9,999;
the external P2PK fee input uses100,001, budget10.

| Depth | Redeem / permission sig bytes | Permission unit bound / budget | Full-shape mass upper | Fee100 | Fee200 | Fee500 |
|---:|---:|---:|---:|---:|---:|---:|
|1|467 /587|220,421 /22|4,575|457,500|915,000|2,287,500|
|16|797 /1,937|640,811 /64|10,125|1,012,500|2,025,000|5,062,500|
|32|1,149 /3,377|1,329,291 /132|18,365|1,836,500|3,673,000|9,182,500|

These are source-upper-bound budget selections, not minimum measured budgets.
In this exact terminal context the permission UTXO has p2/value50M, delegate
has p1/value60M, fee input has p1/valuefee, and the sole payout has p1/value110M.
The relaxed storage result is zero. The rent is returned in the110M payout;
**60M remains the claimant-liability denominator**, not110M.

The unchanged script requires payout>=deduct; a final claim additionally
requires payout>=deduct+permission-input rent. Delegate change is exactly
sum(delegate inputs)-deduct, while nonfinal continuation rent equals the
permission input amount. Therefore the permission/delegate principal has no
surplus for a positive miner fee. A zero-fee upstream engine test does not
establish a claim-funded, relayable Full transaction. The fee must come from
an additional nondelegate input, or a separately reviewed prior fee-allocation
construction. A missing fee coin remains a liveness/economic gap. Default50M
permission rent is operator/settler value, not a free claimant subsidy or an
amount to silently deduct for fees.
[Payout/rent guards](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L407-L509),
[exact delegate change](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs#L577-L604),
[default rent](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/script.rs#L187-L189).

The no-change table assumes an already available exact-size fee input. Creating
that small UTXO is not free: splitting a large p1 coin to a457,500-sompi fee
output alone contributes floor(10^12/457500)=2,185,792 storage grams before
input credit, beyond500k in a usual large-input split. Such an input must not
be conjured as a cost-free preparation step.

A more practical source profile uses an existing1-KAS nondelegate fee coin and
returns its change to P2PK. This adds52 estimated bytes+360 SPK grams=412 compute
grams. The exact final inputs are50M permission rent (p2),60M delegate (p1),
100M fee coin (p1); outputs are110M payout and100M-fee change. General KIP9
storage is zero throughout the fee<=50M range, rather than assuming the
single-output relaxed branch. The full source-upper envelopes are:

| Depth | Estimated bytes | Full-shape mass upper | Fee100 | Fee200 | Fee500 |
|---:|---:|---:|---:|---:|---:|
|1|1,067|4,987|498,700|997,400|2,493,500|
|16|2,417|10,537|1,053,700|2,107,400|5,268,500|
|32|3,857|18,777|1,877,700|3,755,400|9,388,500|

The1-KAS funding principal is returned as change minus its actual fee; it does
not enlarge the60M liability or10-KAS lifecycle denominator. Funding it earlier,
locking permission rent and proving accepted authorization still have separate
attributable costs. This profile is a useful bounded native probe; it is not
claim-funded independence from an empty transparent wallet.

Continuing claims are not the selected probe and are not security-qualified by
this note. Their *arithmetic* can be much less favorable: a covenant-bound50M
continuation contributes80,000 storage grams. A tiny delegate-change output
can exceed the native500k limit. General three-input storage and the separate
fee input must be calculated exactly. The JSON preserves these adverse shapes;
no favorable final-claim result may be promoted into support for all continuing
permission claims or shared reserve ratios.

## Proof-bearing authorization and full10-KAS lifecycle frontiers

The two-field v6 Groth16 check costs at least14,750,001 script units, requiring
147,500 compute grams before other work. The current five-public-input outer
check requires155,000 proof-only grams. These floors apply when that proof
check is actually executed, not to the permission claim above.
[Base tag charge](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs#L25-L39),
[VK-element charging](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L16-L49).

At10KAS=1,000,000,000 sompi, the reference1% payment cap is10M and complete
per-user2% cap is20M, or200,000 priced grams at rate100. The denominator is
this same user's actual10-KAS principal once. A large reserve, operator rent,
other users' deposits, change outputs and recycled payments do not enlarge it.
The200/500 percentage comparisons are diagnostics; supported independent exits
remain required at all three scenarios.
[Unchanged requirements](../../../docs/rfc/0012-useful-privacy-requirements.md).

Unamortized ADMIT's147,500-gram **verification-only floor** leaves52,500 grams
for every payment, terminal claim, fee-funding creation and other attributable
cost. Actual B2 ordinary mass196,484 divided by its two useful payments is
98,242 grams/payment. Thus even a free terminal claim leaves24,574,200 sompi,
over20M. The selected no-change final-claim shape's optimistic lower bound is another
2,375 grams (1,015 bytes+360 outputSPK+1,000 signature commitment), giving
24,811,700. This rejects the named B2 route before service/proving/retry costs.
It is not a universal impossibility result for different entry/payment routes.

The unchanged factory1700 ADMIT is201,631 grams:20,163,100 sompi at100, already above20M before payment or exit. The genuine prospective1600 ADMIT comparison is191,631 grams, leaving only8,369 grams.
Its actual authorized fee remains40M, already above20M by itself. The genuine
B2 authorizations also remain80M total/40M per payment, rather than their lower
mass quote. No existing proof can be repriced. The four/five-KAS public fixture
is not an actual10-KAS lifecycle result; changing values can change storage.
[Measured ordinary and paired evidence](../ordinary-budget/REPORT.md).

For separately amortized admission Ba and private payments Bp, an explicit
per-user necessary reference-fee test is:

```text
ceil(100*A(Ba)/Ba) +ceil(100*P(Bp)/Bp)
  +100*T_claim +F_funding +F_proving/service/retry <=20,000,000
```

Ba/Bp count real attributable users/useful payments, not2Bp recipient/change
records or duplicated proofs. A single accepted authorization that also creates
tickets is counted once; a separate ticket-export proof must be added once.
Uniform shares need an actual allocation, and sponsor payments remain costs.
Returning change from the1-KAS fee coin adds412 grams to this optimistic terminal lower shape (2,787 rather than2,375). Ticket/root issuance and funding preparation are additional. No batching assumption may make an independently arriving claimant wait for
another user's authorization. Receiver-only histories do not inherit an ADMIT
cost they did not incur; they still need a complete stated route.

The existing conditional24KiB/1700 batch shape is
`P(Bp)=195488+498*Bp`; onlyBp2 is measured. Ticket output creation additionally
costs423 compute grams per ordinary P2SH ticket, plus contextual storage and any
new authorization metadata/guard cost. The JSON includes a zero-extra-metadata
optimistic ticket shape, not proof that old P/J or1700 authorize it.
[Existing aggregate shape assumptions](../AGGREGATE-COST-DESIGN.md).

| Ba | Bp | ADMIT verifier-floor allocation +conditional payment +2,375-gram claim | Optimistically divided prospective1600 ADMIT atom instead |
|---:|---:|---:|---:|
|1|2|24,811,700|29,224,800|
|1|4|19,924,500|24,337,600|
|1|8|17,480,900|21,894,000|
|1|12|16,666,367|21,079,467|
|2|2|17,436,700|19,643,250|
|2|4|12,549,500|14,756,050|

The right column is an optimistic arithmetic model dividing the measured prospective1600 191,631 mass
atom; it is **not an implemented multi-user ADMIT or a proven lower bound on a
new admission design**. Likewise larger Bp needs new emitted code, metering,
authorizations and storage validation. Passing an arithmetic row leaves all
omitted expenses and independent-exit/privacy/latency obligations unresolved.

For Ba1, even the verifier-floor ADMIT needs Bp>=4 under the conditional curve
and free/minimal terminal assumptions. Using the conservative4,575-gram claim
source upper requires Bp>=5 for that shape's cost estimate, not as a necessary
lower bound. With the measured191,631 ADMIT atom, the algebraic thresholds are
Bp25 for a free exit, Bp36 for the2,375 minimum, and Bp60 for the conservative
claim estimate. These last arities lie outside even the proposed2/4/8/12 source
study; the same padded emitter/budget must not be extrapolated to them as a
working route. Separately amortized admission can change the frontier, but
cannot be silently obtained by charging the fee to unrelated principal.

## Smallest useful next native observation

The separate probe plan should use the official accumulator's normal minimum
depth1/count1→0 final claim, exact emitter bytes, one supplied permission UTXO,
one delegate UTXO and one real signed nondelegate fee input. It should measure
all input meters, official isolation→Full, native dimensions and100/200/500
costs, and retain exact destination/underpayment/Merkle/covenant failures with
any fee signature refreshed so the intended guard is reached. A claim-funded
attempt without the fee input must reject rather than quietly spend rent or
underpay deduct. Existing source-only and actual results must stay distinct.

Full validation over re-injected supplied entries does not establish spentness.
A tiny source-adapted missing-outpoint lookup or official duplicate-input
control must be named accurately, not presented as an accepted-chain replay
result. Accepted authorization/backing, fee-coin availability and public witness
survival remain separate obligations. No old S7 owner/replay/DRAIN workflow,
new proof, PK restore, funding or broadcast is proposed by this note.
