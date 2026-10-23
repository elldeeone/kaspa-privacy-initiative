# Native terminal claim: Full validation result

**The unchanged upstream terminal claim is cheap and passes complete native
validation with a separate fee payer. It cannot pay a positive fee from the60M
claim principal.** This does not qualify independent exits from an unaccepted
private note or an empty transparent wallet.

The one normal depth1/count1→0 claim was built with the exact vProgs
`f9b84a863a7c7c20586a9cf947550475e894f72e` public permission/delegate emitters.
The source-linked scripts ran through pinned native
`01b532e8b553523216471682649693af92f0fd16` isolation, `Full`, and separate
metered execution of every input. The byte bridge from upstream's native9fdb
is explicit in [source-bridge.json](source-bridge.json). No emitter was rewritten,
and no SDK prover, GPU, new proof, funding or broadcast was used.

## Actual complete transaction

Inputs are50M permission rent,60M recognized delegate backing, and an existing
100M public P2PK fee coin. Outputs are110M to the committed recipient and the
external fee coin's P2PK change. The110M payout contains60M entitlement plus
50M returned rent; **60M is the claim-principal denominator**. The external coin
and returned rent are not claim-funded fee capacity. Recipient and fee-payer
keys are publicly declared synthetic test keys and must never be funded.

|Scenario rate (sompi/gram)|Actual Full fee (sompi)|Fee-payer change (sompi)|Full|
|---:|---:|---:|:---|
|100|498,700|99,501,300|Accept|
|200|997,400|99,002,600|Accept|
|500|2,493,500|97,506,500|Accept|

Each positive is1,067 estimated mass bytes (not a network serialization-size
promise),4,987 compute/mining mass grams,4,268 transient mass and zero storage
mass. Budgets are22(permission),0(delegate),10(fee payer), selected prospectively
from conservative source bounds. Measured successful input costs are2,553,
181 and100,001 script units. The observed permission units fit the free9,999
allowance: the source formula implies a0/0/10 budget would remove2,200 compute
grams, yielding2,787 grams if the same shape passed at that commitment. **That
lower-budget transaction was not constructed, signed or Full-qualified here.**
These100/200/500 rates are hypothetical scenarios, not a live fee quote.

The no-fee-input transactions with the same full60M deduction attempted to
withhold345,500 /691,000 /1,727,500 sompi at their shape's rate. All three
failed input0 with exact `VerifyError`, and Full returned exact
`SignatureInvalid(VerifyError)`. Each still left more than10M principal payout;
the blocker was the unchanged contract's final payout≥deduct+rent requirement,
not insufficient face-value fee capacity. A zero-fee transaction passed Full
as expected, while failing the separately reported positive default relay floor.
Consensus Full acceptance alone is not relay or inclusion.

## Controls and evidence

All22 prospective cases matched their exact expectations: three sponsored
positives, one zero-fee consensus positive, and18 negative cases. The negative
set covers claim-funded fees; substituted payout; one-sompi underpayment and
10M rent diversion; wrong current root, old sibling, amount, count and leaf
hash tag; mismatched delegate/covenant ID; an unwanted50M continuation;
bad/wrong-key/post-sign-mutated payer signatures; and a duplicate input.

Semantic controls retain a valid fee-payer signature and require exact input0
`VerifyError`. Signature controls require permission/delegate acceptance and
exact payer `EvalFalse`; Full must return `SignatureInvalid(EvalFalse)`.
Duplicate input requires exact native isolation `TxDuplicateInputs`. Resources,
malformed setup or arbitrary errors cannot count as the selected rejection.
A separate supplied `UtxoView` missing-entry lookup passes, explicitly without
claiming official Full validates global spentness. Reinjecting old populated
entries is not a replay test.

The run took0.01 seconds in `/usr/bin/time -v`, with13,304KiB process peak RSS,
under6CPU/10GiB/swap0, network isolation and read-only source/input/binary.
This single tiny offline run is not a wallet latency or percentile benchmark.
The owned unit is inactive/dead, MainPID0, with no matching checker process.

The immutable [preparation manifest](preparation-01/public/manifest.json) has
SHA256 `2dc7a4fc92ceb96072adc1c630584f2724be55f7cba5ad26744c0519d31b8f6f`.
The [actual report](execution-01/report.json) has SHA256
`d26f552d1889b21c17ac3dac2ce6b667235560effad555015ae9f7f156ff9d64`.
The selected compiled checker is retained locally with SHA256
`6549a955731710d330cc2b138050a888f2d068852ee5b09eb930ecb7ee5fbd69`;
source, lock, historical build snapshots, exact signed public bodies/contexts,
logs, command and cleanup are published, compiled software/cache is not.
The README's post-build command-format correction has an explicit old/new hash
record; original source freezes and snapshots were not rewritten.

## What remains unqualified

Supplied UTXOs assume a legitimately accepted permission root, balanced backing,
and available public witness; this probe does not authenticate that ancestry.
The public permission branch requires payout to the committed SPK, not a
permission-holder Schnorr signature. The signature measured here belongs to
the separate fee payer. It reveals recipient SPK/amount and supplies no privacy
qualification.

Continuing claims remain correctness-blocked by the separate old/new Merkle
walks lacking script-enforced binding. The selected legitimate terminal branch
discards the new-root result and leaves no remaining liabilities. No hostile
continuation was generated or safety claim made. Wrong leaf tags and delegate
IDs are specific controls, not generic application-domain replay protection.
Global spentness, root origin, reorg behavior, witness/service-loss liveness,
accepted private-note authorization and total user-lifecycle fees remain open.
