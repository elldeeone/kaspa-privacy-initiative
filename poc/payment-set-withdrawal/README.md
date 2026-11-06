# Actual-wallet common-set withdrawal test

Unfunded offline integration with the existing depth-four private-note wallet.
Read [selection](../../research/payment-set-withdrawal-2026-11-05/SELECTION.md)
and [ADR-0108](../../docs/adr/0108-real-wallet-common-set-integration.md).

Alice credits 30 KAS, privately pays Bob 20 and keeps 10. Bob decrypts his
received note and privately pays Carol 10, keeping 10. All three restore their
wallets, discover their final notes and authorize joint or independent native
withdrawals. Actual original and digest-packed wallet proofs verify; the actual
Ledger kernel checks current economic nullifiers and conservation in both worlds.

The isolated circuit copies the complete original constraint relation and only
changes how its public statement is packed. `check_reuse.py` checks source
identities and unchanged constraint code. All old wallet sources/proofs remain
untouched. The common-set digest changes application withdrawal semantics;
old native permissions cannot execute it.

```sh
python3 poc/payment-set-withdrawal/run.py
bash poc/payment-set-withdrawal/check.sh
```

The first command builds with the locked Rust 1.97.1 package and creates a fresh
ignored runtime, setup, real proofs, native executions and sealed observer views.
The second checks the retained public run without generating setup/proofs.
Experimental one-party setup, same-host synthetic wallets, supplied native state
and a logical anonymous redemption interface are explicit assumptions. No
accepted native funding/history, full node validation, network anonymity,
complete-route fee measurement or production security follows.

Costs distinguish an exact finite withdrawal quote from a verification-only
lower bound for the selected direct-verification route. Fee-price/amount
sensitivity is arithmetic, not paid or confirmed transactions. No real funds,
RPCs, broadcasts, providers, consensus changes or paused MPC are used.
