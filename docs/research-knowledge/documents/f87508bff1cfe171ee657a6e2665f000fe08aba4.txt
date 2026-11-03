# ADR-0055: Recoverable private change and repeated owner spending

**Status:** Accepted for a fresh research/testnet rehearsal; production architecture remains unselected.
**Date:** 2026-10-23 UTC. Baseline `a8392f11`.

## Problem and reuse

The owner-local private cashout path restores and pays complete claims. Under
its known one-real-input/no-positive-change policy, public payout plus fee
reveals that consumed claim's value. Auth528 already supports a requested payout
with private change and P0 payment with two positive private outputs. The prior
synthetic partial fixture proves capability, but does not demonstrate backup-only
owner operation or repeated spending of change.

Reuse the unchanged ADR-0050 relation/native program, ADR-0042 V2 receive fields,
ADR-0053 public replay/authenticated local proving and ADR-0054 trusted executable
release boundary. Reuse the established public-value-balance/private-change
pattern studied in Orchard and RAILGUN and local decrypt/rederive recovery.
Do not inherit Orchard reusable-address safety, add a cryptographic primitive,
new token, administrator exit or based-app requirement.

## Decision

Create new wallet/trial/controller source packages and fresh private TN10 domain,
seeds, setup/VK and selected public parameter manifest. Preserve every prior
closed byte. Keep `AUTH528_PRIVATE_CASHOUT/v1`, fixed wire formats and circuit
relation unchanged. Compiled D changes require fresh parameters; old AA/CAF/S7
keys are not compatible merely because counts match.

Expose recover, requested partial cashout, private payment and full cashout.
Initially consume one owner-recognized real note plus a dummy; no aggregation is
needed. Enforce exact integer conservation, unchanged floors and actual fee/body
fixed points. Never silently alter requested payout/payment or donate change.
Partial cashout leaves positive change. Payment permits positive or exact zero
change: a zero-proof public dummy-output sizing quote discovers a candidate fee
without a private witness, then actual legal private material is built and
re-quoted. Only its exact selected quoteID/body/witness may reach proving and
native Full; sizing bytes never authorize reserve release. Full exit remains
explicit without a timer or mandatory working balance.

Root selected uniform OS-random u64 self-change invoice indices under unchanged
V2 derivation. Reject all known historical own indices and repeated receive
tuples, spent included. Hold invoice/rho and privately random input/output roles
for one preparation; rebuild fee-dependent outputs with fresh encryption, then
preserve the exact final proof candidate. New attempts sample anew. The embedded
encrypted index allows original-backup restore without counters/maps/lookahead.
Freshness remains probabilistic; lost pending/orphan disclosures cannot be
exhaustively excluded. Duplicates remain backed and owner-actionable while
marked privacy-contaminated.

Use the exact [common contract](../../research/next-session/private-change/CONTRACT.md). Before funding, rehearse
founding, a 10-KAS Bob payment, Bob partial 400M cashout, Bob 300M private payment
from recovered change, Bob full continuing exit and Charlie terminal exit:
five genuine proofs/six complete bodies, CM9/NF11/R0. Add one genuine local-only
zero-change payment fork/Full control under the same VK (six local proofs total).
It does not extend the live route or claim simultaneous accepted consumption.
After the operator publishes
only founding/P0, each remaining owner action starts cold from the original
backup and a fresh network view, generates its own new proof and confirms its
exact native/public effects. No rehearsal exit, private operator map or other
owner secret enters the cold client.

## Safety, recovery and evidence boundaries

Preserve I-1 through I-16, including exact backing/conservation, original
positioned NF, current state/outpoint/destination binding and recipient checks.
Changed head, occupied NF, wrong domain/root or unavailable data safely halts;
there is no automatic revealing fallback or weaker-check retry. Reorg rebuilding
does not erase earlier disclosures or recover missing orphan-only ciphertext.
Retain failed attempts and canonical once-only submission markers.

This extension tests repeated owner mechanics, not financial privacy. The chosen
single-owner intermediate reserve still determines its remaining total. Public
payout/fee/timing/drainage, invoice-directory linkage and the prior failed
amount-prior/fee targets remain. All five action fees and ordinary funding/
founding/change are counted without cover-user or artificial-principal discounts.
The next privacy test remains a separately frozen blinded policy comparison with
global conservation/ownership inference; do not retune prior observer results.

## Alternatives rejected for this milestone

- Whole-claim-only wallet: retains the policy-dependent exact-input-value leak.
- `max(index)+1`/fixed indices or saved issuance counter: collision/reuse after
  old-backup restore, unpaid invoices or reorgs; map becomes recovery authority.
- New child-seed/key scheme or address format: unnecessary for this bounded
  demonstration; established V2 already transports the recovery index.
- Fixed change-first roles: creates an avoidable deterministic public convention.
- Mandatory working balance, privacy timer or cooperative exit: conflicts with
  independent optional owner exit; does not establish privacy.

The accepted common contract fixes the strict API, largest actionable one-input
selection, existing fresh-identity schema/domain tag and six finite transport
stages. Architecture, RFC-0022/open questions and threat model track this new
work separately from completed trials. Primary references are in the
[source refresh](../../research/next-session/private-change/SOURCES.md).
