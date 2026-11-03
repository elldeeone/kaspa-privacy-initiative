# Post-hoc scoring correction: withdrawal-conditioned facts

**Date:** 2026-11-01  
**Status:** Post-run reassessment, not a new frozen or blind experiment  
**Original evidence:** preserved unchanged

## Correction

The previous statement that the target-cashout checkpoint passed all four privacy
views was wrong.

The v1 scorer projected compatible histories onto hidden internal chain slots 0
and 1. It then counted uncertainty about which slot was the withdrawing chain as
uncertainty about the withdrawing payment. Renaming a hidden label cannot provide
payment privacy.

The v2 correction uses observable roles instead:

- the chain whose two notes exit at the target checkpoint; and
- the unrelated chain whose notes remain private at that checkpoint.

It reports each privacy property separately. It does not replace or overwrite the
original frozen selection, public operations, v1 predictions, score, or manifest.

## Public exit inference

The target exits are public:

| Exit ordinal | Amount | Known payout owner |
|---:|---:|---|
| 8 | 156,392,455 sompi | H |
| 9 | 151,826,556 sompi | F |

Under the frozen workload policy, these are the target chain's second payment
`P2` and first-recipient change `P1-P2`. Therefore:

```text
P1 = 156,392,455 + 151,826,556 = 308,219,011 sompi
```

This reveals the earlier amount received by the first recipient regardless of
which exit is `P2`.

- With payout-owner knowledge, H is the second recipient and F is the first
  recipient. The withdrawing onward payment is therefore exactly
  `F -> H`, `P2 = 156,392,455`, with earlier received amount
  `P1 = 308,219,011`.
- Without payout-owner mappings, `P1` is still exact. `P2` has two candidates:
  151,826,556 or 156,392,455 sompi. The withdrawing onward relationship has four
  candidates and the recipient/amount tuple has eight.

## Corrected checkpoint results

### Before cashout

The existing conclusion remains supported under the admitted observer model.
Across all four views, an arbitrary payment chain has:

- 4 original funders, 8 first relationships and 4 onward relationships;
- 320,000,001 possible P1 values and 360,000,001 possible P2 values;
- 4 historical funding notes, 6 possible onward historical inputs;
- 2 output groupings per transfer and 6 possible transfer-position pairs.

This is generated local ambiguity, not adoption or production privacy evidence.

### Target cashout while six notes remain

The blanket checkpoint **fails** as a full payment-privacy result.

Known payout identities:

- withdrawing chain: onward relationship, P1 and P2 are each unique;
- withdrawing chain: original funder and historical funding note retain 4
  candidates; the first funding relationship retains 4;
- unrelated chain: the one-to-one recipient rule identifies the remaining onward
  relationship as `E -> G`, even though its funder and amounts remain ambiguous;
- both chains retain 2 output groupings, 6 historical onward-input candidates and
  6 transfer-position pairs.

Unmapped payouts:

- withdrawing chain: P1 is unique; P2 retains 2 candidates, the onward
  relationship 4, the original funder 4, and the withdrawal-linked tuple 8;
- unrelated chain: funder, amounts and relationships remain non-unique;
- grouping and transaction position remain ambiguous as above.

Thus unrelated activity preserved meaningful uncertainty about funding origin,
commitment linkage, grouping and transaction position. It did **not** preserve
the withdrawing payment's earlier amount, and known payout identities exposed
the withdrawing onward relationship and both amounts.

### Full cashout

The earlier negative conclusion remains, now stated by property.

Known payout identities recover both chains completely at the identity/amount
level:

```text
B -> F -> H, P1 308,219,011, P2 156,392,455
D -> E -> G, P1 248,674,526, P2 71,946,378
```

Unmapped payouts still reveal:

- target original funder B and P1 308,219,011 uniquely;
- unrelated original funder D and P1 248,674,526 uniquely;
- 2 P2 candidates, 2 first relationships and 4 onward relationships for each
  chain.

Both full-cashout views retain 2 output groupings, 6 possible historical onward
inputs and 6 possible transfer-position pairs. Knowing payment facts is not the
same as knowing which opaque commitment or transfer event carried them.

## Implications

1. Transparent exits plus the frozen two-exit policy reveal prior private amounts
   through conservation before full drainage.
2. Payout-owner knowledge can reveal the withdrawing relationship immediately.
3. Unrelated activity still protects some origin, commitment, grouping and timing
   facts at partial cashout, but it does not satisfy the full payment-privacy goal.
4. MPC is not indicated. It would not hide public exit values, conservation
   equations, payout identities or the disclosed workload policy.

## Reproducible correction

- corrected public-only observer: `observer_correction_v2.py`
- corrected truth-retention scorer: `score_correction_v2.py`
- regression checks: `correction_regression_v2.py`
- public controls: `correction_controls_v2.py`
- public-safe audit: `audit_correction_v2.py`
- correction artifacts: `run/correction-v2/`

Checks:

- 17 focused regression assertions passed;
- 20 public controls passed, including hidden-label renaming invariance;
- every true role-conditioned fact remained in the candidate sets;
- no private truth values, new proof, wallet, network or funding artifact was
  published or created.

Correction prediction seal:
`226627bdebf990f7a1e536f64cf3780e55a3eaa462ea05e22f768ef7b202b2b5`

Correction manifest SHA-256:
`f11471b8fc290194dd461445c9a83dec511c78e5fd81bd8acd1a1acf4ca6700f`

Preserved original manifest SHA-256:
`1a9463269ef5647a1ce22b0af6b8e2121f236950fe2333873107c204f49677d9`
