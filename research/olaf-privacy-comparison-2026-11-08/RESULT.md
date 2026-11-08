# Olaf's published trial: payment privacy after withdrawal

**Decision:** Olaf's current published two-user TN10 trial does not hide its
single payment amount through complete withdrawal from an observer who knows
the payout owners and the one contact. The 4-KAS payment is forced exactly.
Our current public-exit design has the same arithmetic result for that exact
10/4/6-KAS workload. This is **not** a matched execution of both programs or
a ranking of full architectures. No consensus change or new transaction.

## Plain explanation

Alice deposits 10 KAS. She privately pays Bob once. Bob later takes out 4 KAS;
Alice takes out the other 6 KAS. If you know those are Bob's and Alice's
withdrawals, you can work out that Alice paid Bob 4 KAS. The extra 0.5 KAS in
each native payout is a separate rent refund, not part of the private payment.
Hiding the transfer inside a proof does not erase this later subtraction.

| Observer | Olaf trial result | Our current system |
| --- | --- | --- |
| Reads the published trial source and reports | The code names Bob and hardcodes the 4-KAS payment; 1/1 amount and the Alice→Bob relationship are disclosed by publication. | No matched published 10/4/6 trial. |
| Knows the deposit owner, each payout owner, the one contact and complete drainage | 1/1 payment amount exact: 4 KAS. The contact is supplied, so this row does **not** score relationship discovery. | Same 1/1 exact in an **unexecuted field-level control** using our current public-exit rules. |
| Has bare payout amounts without owner labels | 4 or 6 KAS are arithmetically possible recipient amounts under the deliberately minimal one-transfer model. This is no anonymity or proof-indistinguishability score. | Same public amount boundary; no matched chain-only trace. |
| Our previously tested larger wallet history | No matching Olaf trace exists. | 4/7 payment amounts exact under known owners/contacts and actual one-note exit rules; 47-KAS **offline** workload. |

The 1/1 and 4/7 fractions come from **different workloads**. They do not show
that Olaf's architecture is worse or better than ours. Both current designs
publish exit values/destinations on the existing L1. Olaf's transfer statement
does not directly publish its payment value, but his published `Statement`
includes `exit_value` and `exit_destination`; the wallet sets them from the
note being exited. Our public exit statement has the same fields. The upstream
recovery result publishes both native payouts and separates principal from
rent. Its final accounting reports zero reserve principal and zero private
liability. The trial had two logical users controlled by one owner, and its
full public operation bodies are not published; no independent-user or precise
chain-only ownership measurement follows.

Pinned upstream sources: [trial report](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/recovery-tn10/live-2026-10-20/README.md),
[result data](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/recovery-tn10/live-2026-10-20/evidence/result.json),
[wallet fixture](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/recovery-tn10/src/wallet.rs),
[public statement](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/private-note-wallet/src/protocol.rs).

## Reproduction and limits

[SELECTION.md](SELECTION.md) fixed the source hashes, observer knowledge,
hypothesis and stop rule before scoring. `compare.py predict` reads pinned
public evidence and field definitions, strips the 0.5-KAS rent refunds and
solves the one-transfer full-drain equations. Its sealed
[PREDICTION.json](PREDICTION.json) SHA-256 is
`65ef1d933ab6f25879f8147dffaee361df1c40469d2992b69c1a5b3ad98a9f8d`.
`compare.py score` then reads Olaf's source fixture truth and the already scored
branch history. It verifies truth membership and rejects rent-as-principal,
broken reserve reconciliation and wrong-truth controls. The
[machine result](RESULT.json) retains the distinction between actual upstream
execution, our actual but different offline workload and the unexecuted matched
field control.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/olaf-privacy-comparison-2026-11-08/compare.py predict
PYTHONDONTWRITEBYTECODE=1 python3 research/olaf-privacy-comparison-2026-11-08/compare.py score
```

This analysis uses Olaf's committed report of accepted TN10 settlements; it
does not freshly query the canonical chain or verify the privately retained
operation bodies. It is an amount-leakage **lower bound** for the stated strong
observer: additional timing, network, participant or public-proof facts can
reveal more, not less. The bare-chain structural candidates are only arithmetic
possibilities. Neither their relative likelihood nor cryptographic
indistinguishability was measured. No live reorg, independent users, production
security or broad-population anonymity was tested.

**What to do with this result:** keep working with the shared direction, but
do not call its present trial a privacy demonstration. Preserve our optional
service-timing improvement as a narrower contribution. A future comparative
privacy trial must run the *same* multi-user payment and exit schedule under
both implementations, with owner/contact knowledge and complete public
transcripts fixed in advance. The first gate is whether a proposed current-L1
exit policy leaves any payment amount ambiguous after realistic withdrawals;
if it fails this arithmetic gate, more proving or cost work will not fix it.
