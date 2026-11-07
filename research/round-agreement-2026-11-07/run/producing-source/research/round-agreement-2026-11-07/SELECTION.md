# Wallet agreement and service timing test

Selected before new observations, starting at `4703f7aa` on 7 November 2026.
The owner authorizes three ordered steps: enforce one common round before payout
keys leave the wallet; attack the fix and retest timing with genuinely separate
machines when feasible; measure first-payment costs only if privacy survives.
No consensus changes, mainnet, real funds, new token, new primitive or admin exit.

## Fixed question and observer

Use the existing 40-KAS supplied-deposit, four-wallet private-payment history:
A->B 20, B->C 10, A->D 10; A/B/C then own equal 10-KAS notes. Each issues one
genuine blind eligibility request and, only after a wallet-local cohort check,
may send its random payout key. Keep the existing whole-set approvals and current
Ledger/kernel. The service knows all public claims and its own request delivery
schedule and raw messages. It does not receive owner wallet backups or the
observer's private scoring truth. Later participant disclosures and transparent
amounts are separate, adverse controls.

The wallet checks exactly three distinct, genuine eligibility operations against
the same public state, issuer, denomination and round configuration that its own
issued proof uses. The service may supply the transcript, but cannot forge the
other owners' wallet proofs under a substituted round. One mismatched round,
wrong issuer, forged proof, omitted owner, duplicated claim, wrong root or altered
blind request must reject before any payout-key redemption. Do not add a host
boolean that skips proof validation or modify the wallet relation/native guest.

## Preselected arms and gate

1. Honest one-configuration service: all three clients should register and the
   existing whole-set kernel should accept the fully authorized payout. Repeat
   the same prior source/order observer without tuning its guesses.
2. Per-wallet round IDs with one issuer key: all three genuine issues may pass,
   but wallets must refuse redemption before any payout key reaches the service.
   The previous three-owner reconstruction remains the adverse baseline.
3. Same valid common configuration, active delivery scheduling: the service
   releases the public cohort proof transcript to one known claimant, waits for
   its key, and only then releases it to the next claimant. Use the actual
   service-visible release/response sequence to attempt exact links. This tests
   whether the round fix alone protects against the service's timing control.
4. Run a bounded two-host check if the existing remote host can support a real
   wallet without weakening the protocol or exposing real funds. A root on one
   host is never claimed independent of the wallets on that same host. Keep any
   partial machine coverage explicit; do not silently call it three independent
   human users.

Prediction and observer facts must be sealed before reading owner-local truth.
Keep failures and transport errors distinct. Public protocol replay checks real
proofs and accounting; it cannot turn supplied native ancestry into Testnet
acceptance. No cost work follows if any tested active service identifies all
owners, or if the timing attack remains open. Do not retune this rule after seeing
results. If the privacy gate survives, measure complete first-payment costs
against the earlier 47-useful-KAS workload, including wallet/service/idle costs
and the old native-plus-outer subtotal, before deciding on use.
