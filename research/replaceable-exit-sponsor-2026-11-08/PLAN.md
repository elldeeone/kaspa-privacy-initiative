# Replaceable exit-fee sponsor — frozen local experiment

Date: 2026-11-08

## Decision

The live upstream review found no open pull requests and ranked three unclaimed
tasks:

1. replaceable fee sponsor for an already authorized exit (#23/#8);
2. wallet-independent full-log scanning (#12/#13);
3. property-based lifecycle accounting (#6).

Task 1 is selected. It closes a narrower current-L1 withdrawal blocker than the
scanner work: the native permission already leaves the sponsor input unbound,
but the host builder pins one trial sponsor and the tests never demonstrate that
a fee-stale payout can be rebuilt by a different sponsor without changing the
user's authorized payout.

## Frozen question

After the private exit proof, exit ID, permission, reserve and recipient are
fixed, can a different unprivileged sponsor rebuild the payout at a materially
higher fee rate without reducing principal, redirecting value, regenerating the
private proof or discharging the liability twice?

## Fixed fixture and hidden truth

- Reuse each retained genuine Bob and Alice exit receipt already covered by the
  recovery test fixture. Do not generate or replace proof artifacts.
- Build candidate A with the trial sponsor at 100 sompi per priority gram.
- Build candidate B from the same registered exit state with an independently
  generated sponsor key/UTXO at 1,000 sompi per priority gram.
- The test knows the authorized exit ID, recipient, principal, permission UTXO,
  selected reserve and pre-payout state. Sponsor keys are never protocol
  authority.

## Pass conditions

1. Both fully signed native transactions pass the existing script, mass,
   compute-budget, storage-mass and supplied-fee checks.
2. Candidate B pays a higher fee while preserving the permission/reserve inputs,
   authorized recipient output, principal/rent refund, reserve change, lane and
   payout payload.
3. Sponsor input, sponsor change, sponsor signature and transaction ID may
   differ. No private proof or exit authorization is regenerated.
4. Applying either candidate to the same pre-payout application state produces
   the same economic result and discharges the exit exactly once.
5. Applying the other candidate after one succeeds is rejected.
6. Input reordering, output reordering, reserve diversion, recipient
   substitution, underpayment, fee-from-principal and wrong-lane mutations fail
   at the actual script/state layer.
7. Non-payout builders remain restricted to the trial sponsor.

## Stop rules

- Stop and retain the binding failure if Kaspa signature or covenant rules make
  sponsor replacement require a new private exit proof or changed user payout.
- Stop if higher fees can be taken from reserve principal or permission rent.
- Do not add a privileged rescue/admin path, weaken scripts, use Testnet/mainnet
  funds, broadcast, or contact upstream.

## Evidence boundary

A pass demonstrates offline signed-transaction replacement under two declared
fee rates using retained local fixtures. It does not prove mempool replacement,
miner inclusion, censorship resistance, production security, fee privacy or
mainnet readiness.

## Follow-on mempool gate

The source audit adds one bounded question without changing the original pass
criteria: does Kaspa's actual mining manager replace candidate A with candidate
B under `RbfPolicy::Mandatory`?

Fixed controls:

1. Build candidate C with an independent sponsor UTXO at the same 100-sompi
   rate as A.
2. Insert A normally into an empty Testnet-parameterized mining manager.
3. Submit C under mandatory replacement and require rejection with A retained.
4. Submit B under ordinary forbidden-RBF policy and require conflict rejection
   with A retained.
5. Submit B under mandatory replacement and require A returned as removed, A
   absent and B present.
6. Use the repository's locked Kaspa revision for the transaction-specific test;
   run the official generic RBF test separately at current upstream `master`.

This gate can establish node-local, pre-confirmation mempool behavior. It cannot
establish public RPC exposure, peer propagation, miner inclusion or replacement
after A confirms.
