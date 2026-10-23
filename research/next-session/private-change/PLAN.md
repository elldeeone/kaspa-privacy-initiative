# Recoverable private change and repeated spending

Baseline: `a8392f1127e656da59709e0b6f93ece7cf5eb9c2`, 2026-10-23 UTC.
Status: implementation and local validation in progress. A successful complete
testnet rehearsal is required before any readiness claim.

## Concrete path

1. Fresh identity/domain/seeds/setup, whole native funding and initial private
   10-KAS payment to Bob.
2. Bob independently restores, requests a 400,000,000-sompi native partial
   payout and creates positive private change.
3. Bob restores from the same original backup and spends that recovered change
   in a 300,000,000-sompi private payment to Charlie with new private self-change.
4. Restore both resulting private claims from their original backups. Bob
   performs a continuing full private exit; Charlie performs the terminal exit.
5. Fresh public reconstruction and final backup-only restores authenticate all
   payouts, spent private receipts and zero reserve.

The main local route has six native bodies/five genuine proofs. One additional
independent public-synthetic exact-zero-change private payment tests the sizing/
actual candidate barrier under the same VK, with no main-note/NF overlap. Four
new independently owned cold proofs follow the live
prefix. If local funding is synthetic, its outpoint-bound prefix proof cannot
be reused for actual funding: a newly bound actual prefix proof is required.
No used stage is rebroadcast.

The [publication addendum](EVIDENCE-PUBLICATION-01.md) keeps unbroadcast main
alternatives private, preventing a debug-artifact NF intersection channel.

## Selected design and evidence

[ADR-0055](../../../docs/adr/0055-recoverable-private-change-and-repeated-spending.md)
and [CONTRACT.md](CONTRACT.md) select exact integer sompi, unchanged floors,
fresh probabilistic u64 change indices, private input/output permutations,
seed-only encrypted-index recovery and exact quote/body/context binding.
Sizing diagnostics have no witness and cannot authorize release. Existing
Auth528/native/circuit/network implementations remain unchanged where reused.
New wallet/controller packages preserve all completed earlier packets.

The fresh identity was created in one command in 0.878 seconds. Its public
identity and reuse authority are [PUBLIC-IDENTITY.json](PUBLIC-IDENTITY.json)
and [TRIAL-REUSE-SELECTION.json](TRIAL-REUSE-SELECTION.json). Setup uses a fresh
compiled domain, never an old key chosen by matching dimensions.

The larger live route needs about 11 test KAS. Official faucet homepages returned
403; a finite check of known published funding scripts found no sufficient coin.
Local source, synthetic-context proof/native and recovery work continues while
actual testnet funding is unavailable. Synthetic acceptance is never chain
acceptance or trial readiness.

## Parallel work

- New wallet action/restore logic and boundary/replay/alias controls.
- Six-stage once-only transport and exact source-to-final-payout accounting.
- One new setup, six local proofs, then owner-local live proofs when funded.
- Public native subtree-append fee screen, with whole-policy code, budget,
  storage, capacity and independent-exit costs retained.
- Exact global integer-conservation observer controls; no hidden ownership map,
  held-out qualification or rerun of the old 72-case privacy scores.

Builds use up to eight CPU workers; full setup/proving uses fourteen, with heavy
jobs coordinated to fit this host. Passing tests/proofs/native validation remains
bounded implementation evidence. The single-owner intermediate reserve still
exposes its remaining total. Privacy, complete-fee, setup honesty, durable public
data/parameter availability and independent consensus remain separate gates.
