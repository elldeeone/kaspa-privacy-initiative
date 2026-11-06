# Reusable withdrawal approvals (offline)

Wallets approve one fixed group withdrawal. Unrelated payments/withdrawals may
change the bank, but do not change their approval. A fresh complete transition
proof still binds the actual current native transaction. Read
[ADR-0111](../../docs/adr/0111-reusable-withdrawal-intents.md), the
[frozen selection](../../research/reusable-withdrawal-approvals-2026-11-06/SELECTION.md)
and [sources](../../research/reusable-withdrawal-approvals-2026-11-06/SOURCES.md).

The new canonical intent binds protocol/profile, pool, fixed verifier/refund key,
accepted historical anchor, round nonce, full sorted distinct claim set, full
independently sorted equal-value payout set and an aggregate native-fee cap.
Wallets check their own complete payout before authorizing the existing opaque
32-byte context field. The full circuit/setup/proof decoder is unchanged.

The new kernel requires exact claim/payout equality and current unspentness. It
computes current backing, continuation/terminal shape and fee refund; the native
guard still authenticates exact roots, current outpoint/value, all effects and
payload, immutable image and successor. It contains no admin lock or spending
key. Legacy exact-effect, solo/named/refund branches remain. `generate.py` records
the small kernel hooks and a wire-only adaptation of old benchmark helpers.

The experiment starts a new unfunded bank/image. Bob and Carol authorize once;
Alice makes a genuine private payment and two independent exits. Their original
approval bytes must still authorize the now-terminal payout. Separate continuing
and spent-note counterfactuals test a repriced fee and real revocation. An actual
old outer receipt must fail at a different current input/state, even when the
same wallet approvals remain usable. No live chain or network trial is involved.

```sh
python3 poc/reusable-withdrawal-approvals/generate.py --check
python3 poc/reusable-withdrawal-approvals/run.py OLD_CORE_RUNTIME
# Resume only exact completed proof inputs from a retained failed attempt:
python3 poc/reusable-withdrawal-approvals/run.py OLD_CORE_RUNTIME PREVIOUS_RUN
```

The runner uses existing checked RISC Zero 3.0.3 CUDA tools/assets and a fresh
ignored UUID runtime. It preserves source freezes, measurements and failed
attempts. No development-mode receipts, paid allocation, broadcast, altered
consensus, wallet/circuit change or secret proving input is accepted.

Explicit `preflight PROGRAM CORE OUT` checks the host wallet/kernel path without
creating receipts or claiming native settlement. It cannot pass public replay.
Generation requires the previous private synthetic fixture and parameters;
public replay requires only public evidence and compatible dependencies.

Unchanged approved notes, accepted historical anchors, available fee allowance
and fixed intent are necessary. Changing the payout/cohort/cap requires consent.
Accepted spending of a note cancels its old use; deleting a local request does
not revoke it. State-transition proving and serial bank contention remain.
Same-host wallets do not establish independent users, network anonymity or
strong known-owner financial privacy. The optional payout-ownership mechanism
keeps its earlier limits; there is no new Tor service or production deployment.

Releasing approvals also releases control of their execution timing: any holder
of the complete proof set may execute the fixed payout while conditions remain
valid. There is no wall-clock expiry or second owner confirmation. Spending the
note on accepted state revokes its old use. This explicit opt-in tradeoff does
not qualify timing privacy.
