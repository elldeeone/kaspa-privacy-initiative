# Replaceable exit-fee sponsor — mempool result

Date: 2026-11-08

## Outcome

Pass for the bounded construction and node-local mempool questions. The
proof-authorized Bob partial exit and Alice terminal exit can each be rebuilt
with a different unprivileged sponsor at a higher declared fee rate. Kaspa's
actual mining manager rejects an equal-fee conflicting candidate, then replaces
the original with the higher-fee candidate. No private proof, exit authorization,
principal, recipient, permission or selected reserve is changed.

The implementation removes a host-only restriction that pinned every builder
operation to the sponsor created during trial initialization. An unpinned key is
now accepted only for `payout`, matching the existing native permission's unbound
sponsor input. All earlier transaction kinds stay pinned.

## Executed cases

For each retained genuine exit fixture:

1. Build candidate A with the trial sponsor at 100 sompi per priority gram.
2. Build candidate C with an independent key/UTXO at the same 100 rate.
3. Build candidate B from the same registered exit state with another UTXO at
   1,000 sompi per priority gram.
4. Execute every signed input script and the existing size, compute-budget,
   storage-mass and fee checks.
5. Confirm candidate B pays a higher fee while both protocol inputs, all
   non-sponsor outputs, lane and payout payload are byte-identical.
6. Apply each candidate independently and confirm equal reserve principal and
   zero unpaid exit liability.
7. Insert A into the locked Kaspa mining manager, require mandatory replacement
   by C and ordinary submission of B to fail without changing the pool, then
   require mandatory replacement by B to remove A and occupy the pool.

Both the 400,000,000-sompi partial payout and the final reserve-draining payout
pass. Thirteen signed script mutations reject across the two shapes: underpay,
fee-from-principal, recipient substitution, input reorder, output reorder and
wrong lane for both, plus reserve diversion where a reserve-change output exists.
Twelve sequential second-candidate applications reject at the state layer. Six
non-payout builder kinds remain explicitly denied an unpinned sponsor. The
transaction-specific mempool control passes for both payout shapes.

The repository remains locked to `rusty-kaspa`
`01b532e8b553523216471682649693af92f0fd16`. The official generic
`test_replace_by_fee_in_mempool` also passes independently at current upstream
`4863866fce8439d0305b410fc4d802e7261d54d0` using Rust 1.95.0.

## Checks

```text
cargo +1.91.0 fmt --manifest-path poc/recovery-tn10/Cargo.toml --check
cargo +1.91.0 test --locked --release \
  --manifest-path poc/recovery-tn10/Cargo.toml -- --test-threads=1

# In a clean official rusty-kaspa checkout at 4863866f:
cargo +1.95.0 test --release -p kaspa-mining \
  test_replace_by_fee_in_mempool -- --test-threads=1
```

The complete fast suite has nine passing tests; the separate parameter-dependent
wallet lifecycle test remains ignored by default, as before this change.

## Adversarial review

- **Mint or principal haircut:** protocol outputs are unchanged and the higher
  fee is the reduction in sponsor change only.
- **Double discharge:** all three candidates are valid alternatives from the
  same pre-payout state; after any one is applied, the others reject.
- **Unauthorized exit/redirect:** the different sponsor supplies no protocol
  authority. Recipient, permission and reserve bindings remain enforced by the
  existing scripts.
- **Reorder/replay:** actual input/output reorder mutations reject; application
  replay rejects after the liability is settled.
- **Privacy leakage:** a sponsor and fee remain public and may correlate the
  payout. This change avoids requiring the user's own transparent fee input but
  does not prove sponsor unlinkability.
- **Dependency failure:** any available sponsor with a suitable UTXO/key can
  construct the payout; sponsor availability and transaction relay are still
  liveness dependencies.
- **Replacement boundary:** equality fails, and ordinary submission forbids the
  conflict. The higher-fee candidate must use the dedicated replacement path
  while the original remains unconfirmed in the same node's mempool.
- **Hidden trust:** no admin or new cryptographic primitive is introduced. The
  retained proof fixtures and existing native policy are assumed as before.

## Limit

This result proves construction, offline native validation and node-local
pre-confirmation replacement in Kaspa's mining manager. It does not show that a
public Testnet endpoint exposes the replacement RPC, that peers propagate the
replacement, that miners include it, or that sponsor acquisition preserves
network anonymity. No Testnet/mainnet funds, live RPC, broadcast or upstream
write was used.
