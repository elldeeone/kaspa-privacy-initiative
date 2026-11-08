# Replaceable exit-fee sponsor — local result

Date: 2026-11-08

## Outcome

Pass for the bounded offline question. The proof-authorized Bob partial exit and
Alice terminal exit can each be rebuilt with a different unprivileged sponsor at
a higher declared fee rate. No private proof, exit authorization, principal,
recipient, permission or selected reserve is changed.

The implementation removes a host-only restriction that pinned every builder
operation to the sponsor created during trial initialization. An unpinned key is
now accepted only for `payout`, matching the existing native permission's unbound
sponsor input. All earlier transaction kinds stay pinned.

## Executed cases

For each retained genuine exit fixture:

1. Build candidate A with the trial sponsor at 100 sompi per priority gram.
2. Build candidate B from the same registered exit state with an independent
   key/UTXO at 1,000 sompi per priority gram.
3. Execute every signed input script and the existing size, compute-budget,
   storage-mass and fee checks.
4. Confirm candidate B pays a higher fee while both protocol inputs, all
   non-sponsor outputs, lane and payout payload are byte-identical.
5. Apply each candidate independently and confirm equal reserve principal and
   zero unpaid exit liability.
6. Apply one candidate after the other and require rejection.

Both the 400,000,000-sompi partial payout and the final reserve-draining payout
pass. Thirteen signed script mutations reject across the two shapes: underpay,
fee-from-principal, recipient substitution, input reorder, output reorder and
wrong lane for both, plus reserve diversion where a reserve-change output exists.
Four sequential second-candidate applications reject at the state layer. Six
non-payout builder kinds remain explicitly denied an unpinned sponsor.

## Checks

```text
cargo +1.91.0 fmt --manifest-path poc/recovery-tn10/Cargo.toml --check
cargo +1.91.0 test --locked --release \
  --manifest-path poc/recovery-tn10/Cargo.toml -- --test-threads=1
```

The complete fast suite has nine passing tests; the separate parameter-dependent
wallet lifecycle test remains ignored by default, as before this change.

## Adversarial review

- **Mint or principal haircut:** protocol outputs are unchanged and the higher
  fee is the reduction in sponsor change only.
- **Double discharge:** both candidates are valid alternatives from the same
  pre-payout state; after either is applied, the other rejects.
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
- **Hidden trust:** no admin or new cryptographic primitive is introduced. The
  retained proof fixtures and existing native policy are assumed as before.

## Limit

This result proves construction and offline native validation at two supplied fee
rates. It does not show that a higher-fee conflict replaces a lower-fee candidate
in a Kaspa mempool, that miners include it, or that sponsor acquisition preserves
network anonymity. No Testnet/mainnet funds, RPC, broadcast or upstream write was
used.
