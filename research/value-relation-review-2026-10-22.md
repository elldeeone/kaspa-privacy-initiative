# v6 value relation review — 2026-10-22

**Result:** no new inflation, padding-value or unauthorized-release bypass was
established. A concrete qualification failure remains outside the 16 relation
controls: valid minimum notes cannot fund independent exits throughout the
adopted fee scenarios. At 5×, the original 3,000-budget two-input construction
cannot even begin combining a balance made entirely of minimum notes without
additional capital, lower fees or a changed operating envelope. A later bounded
1,600-budget qualification is recorded in the addendum below; it does not change
these original-budget inequalities.

This is a bounded source/arithmetic result, not a new exploit, generated proof,
native execution, privacy inference or funded trial. It sharpens the already
documented fee/repricing gap; it does not reopen rejected experiments.

## Source and prior coverage

Repository baseline: `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`.
Native dependency: `01b532e8b553523216471682649693af92f0fd16`, verified in the
existing local Cargo checkout. No source was changed.

The prior 16 controls at `2251864a7f89065a526641c3782506f27b39c59f` cover
mixed ownership/order, stable positioned nullifiers, aggregate MAX/MAX+1,
fee minimum/nonempty result, positive DRAIN output, payout floor, padding value
and secret, and exact bounds-helper behavior. Their successful outcomes remain
constraint evidence with their original provenance. They do not check whether
a valid note can pay the fee required by the chosen research rate.

Relevant contracts:

| Contract | Exact source |
| --- | --- |
| Minimum positive note 60m sompi, minimum payout 10m, default fee 40m | [two_input/mod.rs](../poc/shared-pool/src/two_input/mod.rs), constants |
| At most two private inputs; zero padding contributes no value; every active operation has a real input | [circuit.rs](../poc/shared-pool/src/two_input/circuit.rs), lines 132–218 |
| Bounded amounts; positive DRAIN payout; DRAIN outputs zero; no fee-only operation; exact conservation | [circuit.rs](../poc/shared-pool/src/two_input/circuit.rs), lines 223–270 |
| Non-admission native spend has exactly one input | [covenant.rs](../poc/shared-pool/src/two_input/covenant.rs), lines 230–236 |
| Default reserve compute budget is 3,000 | [covenant.rs](../poc/shared-pool/src/two_input/covenant.rs), constant `BUDGET`; [settle](../poc/shared-pool/src/two_input/mod.rs) uses it |
| Current wallet fee is fixed; EXIT consumes selected value less that fee | [wallet.rs](../poc/shared-pool/src/two_input/wallet.rs), lines 499–525; [harness.rs](../poc/shared-pool/src/two_input/harness.rs), authorization construction |
| Each compute-budget unit charges 100 grams; execution receives only 9,999 free script units per input | [pinned mass units](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs) |
| Native compute mass includes the full committed budget plus bytes and output-script mass | [pinned mass calculation](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs), lines 335–366 |

## 1. Necessary exit-feasibility bound

For selected private value `V`, fee `F`, payout `W` and the 10m-sompi payout
floor, an independent DRAIN requires

```text
V = W + F; W >= 10,000,000.
Therefore F <= V - 10,000,000.
```

At research rate `r`, the adopted costing requires `F >= r * mining_mass`.
Mining mass is at least compute mass. The unchanged committed budget alone
costs `3,000 * 100 = 300,000` compute grams before bytes and scripts. Thus

```text
Necessary: V >= 10,000,000 + r * 300,000.
```

| Research rate (sompi/gram) | Fee lower bound from budget alone | One minimum note: maximum remaining payout | Two minimum notes: maximum remaining payout |
| ---: | ---: | ---: | ---: |
| 100 | 30m | 30m | 90m |
| 200 | 60m | 0 | 60m |
| 500 | 150m | -90m | -30m |

These are necessary bounds, not fee quotations or successful exits. Real bytes,
output scripts and storage can only make them less favorable. At rate 200 the
singleton cannot leave the required payout; at rate 500 even two minimum notes
cannot pay the budget component of the fee. Merely exposing a variable-fee
wallet option cannot repair those cases.

The limitation is sharper than a low total wallet balance: a wallet could own
many valid 60m notes and have a substantial aggregate claim. Under the unchanged
budget, no first SPEND/DRAIN consuming one or two such notes can fund the rate-500
fee. SPEND additionally needs a positive output or payout; setting all results
to zero is prohibited. Repeated merges cannot begin. ADMIT would require new
external native value and would change the user's cost and funding assumptions;
it is not an exit funded by the existing claims.

The existing [mass table](../poc/shared-pool/TWO-INPUT.md#measured-cost-and-fee-envelope)
reports 330,497 grams for a terminal exit and 330,920 for a continuing exit.
Those measured layouts require respectively 66,099,400/66,184,000 sompi at rate
200 and 165,248,500/165,460,000 at rate 500. The stronger conclusion above needs
only the source budget lower bound, not an assumption that every changed-amount
transaction has a valid proof. The historical 36-case amount sweep remains
mass-only evidence.

## 2. Budget optimization has a remaining singleton floor

The 3,000 budget is a wallet construction policy, not a proved immutable minimum
of the v6 relation. Lowering it would need its own meaningful native execution
qualification. This review does not claim that all pairs of small notes remain
unusable under every correctly qualified lower budget.

There is nevertheless a tighter unavoidable singleton bound for the pinned
one-proof v6 exit:

1. The Groth16 tag charges 140,000 grams, or 14,000,000 script units, in
   [the pinned tag table](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs).
   [OpZkPrecompile](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs)
   consumes that charge before invoking verification.
2. The v6 verifier has two public field inputs, so its VK has three
   `gamma_abc_g1` elements. The pinned
   [Groth16 verifier](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs)
   also charges 250,000 script units per such element. Total verification
   charges are therefore at least 14,750,000 script units.
3. With 10,000 script units per budget unit and 9,999 free units, at least
   `ceil((14,750,000 - 9,999)/10,000) = 1,475` budget units are necessary.
   They charge 147,500 compute grams before transaction bytes and other work.

At rate 500 this lower bound alone costs 73,750,000 sompi, above the entire
60m minimum note and its maximum 50m exit-fee allowance. A single minimum note
therefore cannot meet this fee scenario merely by reducing an overgenerous
budget. This says nothing universal about different proof constructions,
settlement layouts, upstream prices or arbitrary future fee markets.

## 3. What the inspected value and delivery constraints do establish

Static review supports the existing conservation argument: amounts and slacks
are bounded byte/UInt64 values; the relevant sums stay below `2^66`, far below
the scalar modulus. Saturating subtraction supplies a candidate slack, not an
acceptance rule. Canonical padding contributes zero. Real inputs bind owner,
commitment, historical position and positioned nullifier; current spentness is
enforced separately by native settlement. No additional bypass was identified.

Ciphertext hashing still proves binding, not correct delivery. The existing
malformed-delivery lifecycle fixture already exercises that distinction with a
genuine proof. Current receipt scanning checks decryption, domain, owner, incoming
key, value/floor, commitment and positioned membership, then tracks spentness;
bad delivery is not credited and does not block other notes. Repeating that
known fixture would not add a new finding. Offline replay explicitly leaves
accepted-chain authentication/freshness external; this review does not relabel
its successful reconstruction as current chain acceptance.

## 4. Two-proof composition is not yet a qualified fee unit

The local two-v6 composition experiment has a separate low-end cost constraint.
For two 10-KAS payments, RFC-0012 permits at most 10m sompi per payment, or 20m
in total, for the ordinary 1% target. At the frozen reference rate of 100
sompi/gram, the pinned `R0Succinct` tag's base 250,000 grams already cost 25m
sompi. Two users cannot both remain below their 10m limits under any allocation
of that 25m cost. Equal division would be 12.5m each (0.125 KAS), before every
other transaction, service, merge or retry cost.

This bound does not invalidate a NONSETTLING verification experiment. It means
successful receipt generation alone cannot qualify a two-payment Succinct native
settlement at the lower endpoint of the adopted amount range.

The prepared five-public-input Groth16 receipt route has a different necessary
lower bound. The existing
[native wrapper](../poc/takeover/vendor/covenant/src/script.rs), lines 956–965,
uses five public field inputs. At the same pinned verifier pricing this needs
six IC elements: `140,000 + 6*2,500 = 155,000` verification grams. Its reference
cost floor is 15.5m sompi per pair, or 7.75m (0.0775 KAS) per payment under equal
division. That leaves at most 4.5m sompi total for everything else if both 10-KAS
payments are to meet their caps; it is not evidence that the complete path fits.

Both inequalities were checked with integer/rational arithmetic only. No actual
compression, receipt verification or settling transaction is established by
them. They compare necessary costs for existing pinned constructions, select
no runtime or reserve design, and make no privacy-benefit claim.

## Focused check and disposition

A standard-library integer calculation read the current floor, payout and budget
constants and the pinned native conversion constants directly. It asserted all
three necessary failures: singleton at rate 200 with the current budget, pairs
at rate 500 with the current budget, and singleton at rate 500 even at the
Groth16-only budget lower bound. All assertions passed. No build, proof,
native script execution, private data, funding or network was used.

Keep R1/I-1/I-2 backing and conservation unchanged. Keep the 16 controls as their
original bounded regression evidence. Record this limitation under RFC-0012
R7/R8: the current note floor and exit construction do not satisfy every adopted
fee scenario. The existing note already says repricing and small-change
qualification are open; this review supplies exact necessary inequalities and
the fragmented-balance case.

Any future cost improvement should demonstrate its independent-exit envelope
separately from ordinary payment amortization. Do not silently redefine supported
claims, add privileged rescue, erase liabilities, count external rescue funding
as free, or treat another relation pass as resolving economic exitability.

## Addendum: separately qualified public native budget

The native lane subsequently published
[budget attempt-03](../../native/poc/shared-pool/evidence/2026-10-22-public-native-budget/attempt-03/validation.json).
Its 13 original-context full-native cases accept a reduced reserve budget of
1,600 while preserving genuine proofs, authorizations, ciphertexts, outputs,
signatures and the original 40m fee. It records 35 total native cases (31
acceptances and four expected budget rejections), four classifier controls and
105 independent fee quotes. A subsequent
[independent source/byte review](../../review/research/intensive-2026-10-22/review/NATIVE-BUDGET-INDEPENDENT-REVIEW.md)
reproduces all full hashes, SIG_HASH_ALL invariance, masses and quotes. It is
independent serialization/arithmetic evidence, not a second native VM execution.
This reviewer verified all four manifest artifact hashes/sizes and independently
recomputed all 105 quote multiplications and payout-floor additions from the
exported public metrics; no VM execution was repeated.

Maximum measured mining mass is 191,628, so the existing 40m fee covers the
38,325,600-sompi worst rate-200 quote for these cases. This narrows the original
budget limitation without changing the relation, default wallet, old observation
artifacts or minimum-note evidence. At rate 500 the worst measured quote is
95,814,000; adding the 10m payout floor gives a conservative workload envelope
of 105,814,000 sompi. That is not a tight universal minimum claim, a freshly
repriced valid proof, or a genuine minimum-note native exit. The stronger
Groth16-only singleton impossibility at rate 500 remains unaffected.

The pinned v1 implementation preserves transaction IDs and SIG_HASH_ALL under
this budget-only change; full transaction hashes change. The lane checked those
properties explicitly. A lower charged execution budget does not itself reduce
the proof-authorized 40m fee or establish chain acceptance.

A later [source upper bound](v6-native-budget-upper-bound-2026-10-22.md),
independently checked in the
[second-pass review](../../review/research/intensive-2026-10-22/review/RFC0018-AND-GAS-SECOND-PASS.md),
covers every successful fixed-v6 standard-P2SH reserve-input-0 execution at the
pinned layout/runtime: 15,857,502 units versus budget-1,600's 16,009,999 allowance.
This manual source argument plus pinned arithmetic checker is separate from
the 13 observed cases. It covers neither malformed inputs, funding-input meters,
the new state-aware script, compiler correctness nor whole-transaction mass/fees.
That source-bound packet retains its historical 3,000-default identity, and the
high-fee singleton inequality remains intact.

[ADR-0036](../docs/adr/0036-v6-native-budget-1600.md) subsequently adopts the
1,600 v6 factory budget. Its new 13-case actual-factory regression preserves
emitted scripts/proofs/auth/ciphers/outputs/signatures/storage mass/IDs and
SIG_HASH_ALL, with changed full hashes; historical3,000 and factory1,600 replay
agree on state/accounting. The reader preserves the supplied typed operational
budget before exact reconstruction, native validation and mass/fee checks.
Earlier statements about the current 3,000 budget refer to the pinned original
source and remain historical findings. This adoption narrows those construction
limits but does not change the 40m authorized fee or the rate-500 singleton
impossibility.
