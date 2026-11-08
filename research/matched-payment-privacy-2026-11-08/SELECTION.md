# Matched four-wallet privacy screen: frozen before scoring

**Date:** 8 November 2026 (Australia/Sydney). **Source commit:** `b151fe72`.
This is an offline comparison of two reply-publication policies applied to the
same retained, genuinely proved four-wallet payment history. It is not a new
wallet run, accepted bundle transaction or independent-human experiment.

## Fixed source and workload

Use only the 47-useful-KAS, 40-KAS-principal complete history in
`research/cached-approval-verification-2026-11-07/run/`. The main history has
real wallet proofs, six native Full settlement transactions, three equal
10-KAS group payouts, five later native payouts, eight restored-key spend
controls and zero final reserve/liability. The source bank is a synthetic
UTXO, so these 47-KAS native transactions were **not** broadcast. The separate
small Testnet bundle trial is evidence of current-L1 acceptance, not this
matched workload's chain acceptance.

Pinned inputs (SHA-256):

| File | Hash |
| --- | --- |
| `run/combined/MAIN.json` | `07c0e4fedf81d3776d66f2042c986ca1baf471b3fb6e0fbafb2bba798be45f69` |
| `run/registration/operator.jsonl` | `aae893908071bd6e5b9ce30976bdd6ddb691bf598f31245419e30fcf0f508255` |
| `run/registration/config.json` | `af6f63274e01eb995e5b01c3d5c05a45d8902e6b1f1f7a61538f71f267f8e5cb` |
| `run/registration/PUBLIC-REPLAY.json` | `eac5b0fc001fd07d388e117923f79772528496e6b249bcb7ba26aef68e5feed3` |
| `run/registration/PRIVACY-VIEWS.json` | `a1ffa0ab0bcec5b0124085c92a994584df8550a47f43146cce7cd33558362914` |
| `run/combined/APPROVALS.json` | `1f221b5be0ea2b0f83f9115bd0dd6c1bcdb0f12dc9b4e32f219f9926c4e69ebd` |

The seven actual private payments, in order, are A→B 20, B→C 10, A→D 10,
D→A 2, then after the group payout D→B 1, D→C 3, D→A 1 KAS. These values
are **scoring truth**, not inputs to the amount predictor. The observer's
declared contact graph contains these seven directed contacts in this order,
but not their values. That means this screen measures amounts under known
contacts; it cannot claim the observer discovered sender/recipient identities.

## Matched arms and observer views

- **Ordinary reply arm:** the actual first three successful issue and redeem
  events from the retained registration-service log. The service returned each
  valid blinded signature privately. Actual wallet unblinding, approvals and
  payouts completed in the retained run.
- **Bundle arm:** assemble one complete public board from those **same three
  genuine issue requests and signatures**, then run the existing public
  blinded-RSA relation checker. This is a counterfactual *repackaging* of real
  requests. Wallets did not redeem that repackaged board in this 47-KAS run;
  the separate small Testnet trial is the only accepted-bundle wallet run.

Score these views separately:

1. **Published native/economic fields:** input and payout amounts, output
   scripts, transaction order and fee source. The research controller's
   owner labels are excluded from the chain-only view.
2. **Service-only:** actual issue/redeem messages, including order and private
   reply contents. No controller wallet instructions or owner truth. A
   one-client-at-a-time malicious release is a separate mechanism control,
   previously executed on another workload; do not fabricate it as this run.
3. **Known participants/owners:** the published `ownerDisclosureControl` values
   and true contact edges/order as explicit auxiliary facts. Group A/B/C each
   withdraws 10 KAS. Final five outputs total A 3, B 1, C 3, D 3 KAS. All 40
   KAS principal exits. Fee allowance/refund is separate from private value.
4. **Network/fee funding:** record the source/fee linkage and absence of an
   independent-user/network-timing qualification. A hypothetical 47-KAS bundle
   publication adds a fee transaction that this offline arm did not produce.

For the known-contact amount view, allow positive integer sompi transfers,
nonnegative balances at every operation, no outside deposits and no retained
principal. First score exact amounts from these **necessary balance
constraints**. Then separately test a declared whole-KAS transfer grid as an
auxiliary price-policy sensitivity. Neither candidate count is an anonymity
set or proof that alternative histories match all public proof shapes.

## Measures and stop rule

Require the actual seven-value truth to remain feasible. Report each payment's
min/max possible amount and exact-amount flags, group payout-key mapping counts
under isolated service and known-owner views, and whether the bundle changes
any public balance equation. Compare arms only on fields genuinely shared by
this fixed history. Do not transfer the small Testnet fee or malicious timing
score into a new 47-KAS measured result.

**Stop bundle escalation if it changes no actual payment amount or relationship
fact in this matched workload.** Preserve a separately demonstrated timing
benefit as optional. A source-only field comparison against Olaf's different
two-user Testnet run is allowed; a matched code-level win is not. No new token,
consensus rule, mainnet transaction, test-KAS spend or protected-host access.
