# Frozen selection: reusable wallet consent, fresh current-state settlement

Selected before new prototype execution, 6 November 2026. Starting checkpoint
`44d28516` is pushed to the owner's origin branch. Follow ADR-0111; keep the
optional common-set privacy mechanism and every earlier failure.

**Hypothesis:** two wallets can approve a fixed equal-value payout set once;
their exact original proof bytes remain usable after unrelated accepted payments
and withdrawals, while the final native receipt is necessarily fresh. No
consensus, circuit, setup, invariant or privileged withdrawal changes.

Use the actual depth-four private-payment wallet, fixed checked parameters,
encrypted discovery, Ledger and current native guard. Start from Alice's genuine
30-KAS credit/payment-to-Bob/re-spend-to-Carol fixture (10 KAS each). Bob/Carol
approve a full fixed intent before Alice's subsequent activity.

1. Admit and settle the initial payment batch in a fresh synthetic bank.
2. Alice privately self-splits 10 KAS into two positive 5-KAS notes; settle the
   real proof/native update. Bob/Carol's notes remain unspent. The old exact-effect
   branch must reject its earlier approvals, while the intent branch retains
   literal proof bytes with no additional wallet proving.
3. Demonstrate a continuing common-set withdrawal at this prefix as a separate
   counterfactual, with a genuine fresh native receipt.
4. In the main world Alice restores and independently exits both 5-KAS notes.
   This changes roots/outpoints/fee allowance and makes Bob/Carol's payout terminal.
   Their same proofs must authorize the now-terminal payout, ending at zero
   reserve/liability, with correct allowance refund.

Stop on acceptance of a wrong payout/cohort/pool, missing current spentness,
principal-funded fee, wrong native state/outpoint/effect, invalid receipt, lost
principal or unexplained nonzero final liability. Retain all failures; do not
relax bindings to make the experiment pass.

Negative gates: changed payout script/value, nonce, pool/domain/verifier/refund
key, changed/missing/duplicate claims, partial group, fee cap/range and reserve
boundaries, wrong/unaccepted reference anchor, a genuinely spent cohort note,
replay after payment, malformed proof/packet, changed successor program/root and
reuse of an actual final receipt at a different current input/state. Require the
intended failure layer, including representative actual guest/native cases.

Public observer: complete actual native transactions, state/prover inputs,
canonical intent and approvals. Under the same cryptographic assumptions, the
new independently sorted sets must not introduce a per-owner payout mapping.
Retain known-owner/timing/collusion controls and do not claim stronger financial
privacy, independent clients or anonymous approval transport.

Measure new approval-proof count after creation (target zero), literal proof
hashes before/after updates, native fees, complete proving time, sampled resources
and all principal/refunds. The two counterfactual withdrawals do not both spend
one outpoint in one history. This is not a funded chain or a sustained-traffic
liveness qualification. Protect owner consent; fresh backend proof work remains.
