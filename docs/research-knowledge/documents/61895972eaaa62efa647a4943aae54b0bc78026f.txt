# User-chosen withdrawals with private change — measured result

**Date:** 2026-11-01  
**Experiment:** `wallet-local-private-change-v1`  
**Decision:** **user-chosen withdrawals materially reduce prior-payment amount
identification while private change remains. Withdrawing that change later
recreates the original amount equation. Relationship and payout identity leakage
remain separate failures. No observed result requires MPC.**

## What executed

Two independently sampled, distribution-matched counterfactual ledgers used one
fresh depth-four Groth16 setup:

- direct-exit baseline: 16 genuine operations, 8 full-note exits;
- private-change candidate: 20 genuine operations, including 2 owner-to-self
  TRANSFER splits, 2 requested exits, 2 later change exits and 6 final exits.

The candidate is a two-operation composition:

```text
ordinary private self-transfer(requested note, private change)
then unchanged whole-note EXIT(requested note)
```

EXIT itself was not changed and does not atomically create private change. The two
self-transfers took the ledger from 12 to exactly 16 leaves. Restored owner
backups discovered both outputs exactly once. Every note later exited from its
owner backup; both ledgers ended at zero reserve and private liability.

The run produced 36 accepted proofs in 169.511 seconds. All execution controls,
21 observer controls, the coupled-truth check, public-safety audit and unchanged
default wallet suite (9/9) passed.

## Requested-withdrawal checkpoint

The candidate strongly improved amount unlinkability versus direct exit:

| View | Baseline P1 / P2 candidates | Candidate P1 / P2 candidates |
|---|---:|---:|
| known payout identities | 1 / 1 | 320,000,001 / 357,546,121 |
| unmapped payouts | 1 / 2 | 320,000,001 / 360,000,001 |

Known payout identities still reveal the withdrawing relationship `F -> G`.
They do not identify the original funder: A/B/C/D and four historical credit
commitments remain compatible. Both original transfer groupings, both split
groupings, six original transfer positions and two split positions remain
ambiguous.

Without payout mappings, the withdrawing onward relationship has four candidates
and the original funder four. Thus the candidate protects amounts at this
checkpoint, but it is not a full sender/recipient privacy pass.

The known-identity view also infers the unrelated onward relationship `E -> H`
from the public one-to-one recipient policy. Its amounts and original funder
remain broad. Shared activity does not hide a relationship already fixed by
legitimate identity knowledge and the disclosed workload structure.

## Later private-change withdrawal

The candidate requested exits were:

```text
F:  13,421,743 sompi
G:  52,453,880 sompi
```

The later change exits were:

```text
F: 111,036,857 sompi
G:  96,461,617 sompi
```

With known payout identities, the observer reconstructs:

```text
P1-P2 = 13,421,743 + 111,036,857 = 124,458,600
P2    = 52,453,880 +  96,461,617 = 148,915,497
P1    = 273,374,097 sompi
```

P1, P2 and `F -> G` therefore become unique again. Original funding origin still
has four candidates until final drainage.

Without payout identities, P1 is still uniquely the sum of all four exits:
273,374,097 sompi. P2 retains four role-assignment candidates and the relationship
retains four. Later change withdrawal therefore undoes the P1 protection even in
the less-informed view, and fully undoes target amount protection when payout
owners are known.

Temporary retention is not a durable fix if the remainder later exits under the
same observable policy.

## Full drainage

Known payout identities recover both chains' funders, relationships and amounts:

```text
A -> F -> G, P1 273,374,097, P2 148,915,497
D -> E -> H, P1 362,194,335, P2 154,336,366
```

Without payout mappings:

- target funder A and P1 remain unique; P2 has 4 candidates and the onward
  relationship 4;
- unrelated funder D is unique; P1 has 2 candidates, P2 has 3 and the onward
  relationship 4.

Output grouping, exact historical input commitment and original transaction
position remain ambiguous. Those opaque-record uncertainties are not a full
payment-privacy pass.

## Operation, proof and fee implications

- Reaching requested withdrawal required 2 extra self-transfer operations/proofs
  versus direct exit. Their measured proof time was 9.013 seconds total.
- Later withdrawing both private changes required 2 more exit proofs, 9.036
  seconds total.
- Candidate total: 20 operations and 90.148 proof-seconds; baseline: 16 operations
  and 72.312 proof-seconds. Setup was shared and took 5.880 seconds.
- Local application fee fields were zero. No native network fee was measured
  because no network transaction occurred; no native fee claim is made.

## Security and evidence limits

- Below-minimum requested amount, below-minimum change and sum mismatch rejected
  before proof construction. Wrong domain/root, replay, unauthorized discovery
  and diverted payout attempts rejected atomically.
- Passing proofs establish only the executed implementation relation, not
  cryptographic correctness or production safety.
- Same-host wallets are not independent physical custody or user adoption.
- Deposits and payouts are authenticated offline fixtures, not native consensus.
- Public and neutral-service results were identical. Network/IP origin was not
  observed.
- No MPC, network, funding, real funds, mainnet, Testnet, paid compute, commit or
  push occurred.

## Reproducible evidence

- frozen design: `SELECTION.md`
- pre-wallet workload commitment: `WORKLOAD-COMMITMENT.json`
- genuine runner: `runner/`
- role-conditioned observer/scorer: `observer.py`, `score.py`
- coupled truth check and controls: `joint_truth_check.py`, `controls.py`
- adversarial review: `ADVERSARIAL-REVIEW.md`
- public artifacts: `run/public/`

Prediction seal:
`0849703e8acf65f38bd6a6be8d04e74bfab5fd115499d5e791a5294676300c0e`

Public manifest SHA-256:
`807d5022e40f443d8c0d8d96b9046f20a7fc1ee75aa5d780afcf83e83c5baff4`

Private workload, truth and 16 wallet backups remain outside Git under
`/var/tmp` with `0600` files and `0700` directories.
