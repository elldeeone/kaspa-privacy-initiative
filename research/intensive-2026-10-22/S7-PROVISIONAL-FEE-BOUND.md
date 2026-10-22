# Conditional fee failure for the provisional S7 profile

**The proposed 24,576-byte redeem, 1,700 ordinary budget and 5,231-byte
ordinary payload cannot fit the unchanged 40,000,000-sompi fee at rate 200.**
Even its smallest ordinary one-input/one-output P2PK layout has compute mass
200,500 and requires at least 40,100,000 sompi. This is a source-only conditional
negative, before a new emitter or native run; no owner/replay implementation
or proof job was performed. Existing fees, targets and prior results stay fixed.

[ADR-0037](../../docs/adr/0037-offline-continuing-s7-owner-lifecycle.md) and its
reviewed design retain these resource values as provisional, not qualification.
The native source is pinned at
`01b532e8b553523216471682649693af92f0fd16`:

- [Estimated-size and compute equations](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L21-L77)
  count the signature script and complete payload; compute adds size,
  output-SPK mass and declared input budgets at lines 335–369.
- [Budget units](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L4-L7)
  charge 100 grams per budget unit. Pinned testnet parameters use one gram per
  estimated byte and ten per output-SPK byte, including its two version bytes.
- [Standard scripts](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/standard.rs#L18-L36)
  give 34-byte P2PK and 35-byte P2SH scripts. The smaller P2PK output gives the
  conservative bound; additional ordinary inputs/outputs cannot lower it.

For version 1, no native covenant-output field and exactly one required output:

| Estimated-size component | Bytes |
| --- | ---: |
| Fixed transaction fields, including payload hash/length | 94 |
| One input's outpoint/length/sequence/budget fields | 54 |
| Proof plus push prefixes and 24,576-byte redeem | 24,709 |
| One P2PK output, including amount/version/length | 52 |
| Complete ordinary payload | 5,231 |
| **Estimated size** | **30,140** |

```text
compute = 30,140 + 10*(2+34) + 100*1,700 = 200,500
mining mass >= compute
necessary rate-200 fee >= 200*200,500 = 40,100,000 sompi
shortfall from fixed 40,000,000 = 100,000 sompi
```

Storage can increase mining mass; it cannot repair this lower bound. The
unchanged 80,000,000-sompi paired fee is a different authorization/layout and
is not reduced or combined with this ordinary fee. This calculation is neither
a native acceptance result nor a universal bound for another script length,
payload, budget or output format. It strengthens the proposal's conditional
“may fail at 200” observation for these exact provisional choices.

The [retained arithmetic/source pins](s7-provisional-1700-fee-bound.json) have
SHA-256 `d91e4356003576be76ea8ad62ec9959fe2533077f970c04bcaaa30b8c8375bc3`.
Future per-branch budgets are an **unselected** design seam, requiring a new
emitted-source charge bound and actual native checks. Do not adopt them or
reprice frozen authorizations to remove this result. The parked S7 public
replay/owner CLI job remains outside this calculation and is not recreated.
