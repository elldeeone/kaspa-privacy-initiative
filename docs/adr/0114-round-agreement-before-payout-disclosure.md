# ADR-0114: Verify common round details before disclosing payout keys

**Status:** Accepted research decision; repair remains unimplemented.
**Date:** 7 November 2026.

The owner authorized wallet/service separation and a payout-owner attack, with
cost work conditional on privacy holding and no consensus changes.

The [separated-role experiment](../../research/separated-withdrawal-2026-11-07/RESULT.md)
removed direct links in the honest service view but its fixed timing/order guess
still matched all three owners once. A dishonest issuer using one key and three
different round IDs derived three exact owner/key links. Genuine wallet approvals
and the unchanged economic kernel accepted the full payout set. This is an
offline enforcement failure, not a new native/chain acceptance result or RSA break.

## Decision

1. The privacy gate has not passed. Do not begin the conditional cost campaign.
2. Treat common round/configuration agreement as a client-enforced requirement,
   verified before payout-key disclosure. An intent check after redemption cannot
   undo prior disclosure. Design the smallest shared-transcript/configuration
   check and rerun this active attack before extending the component.
3. Preserve the successful honest-arm timing guess and require a fresh selected
   timing comparison. Common-configuration agreement alone does not qualify it.
4. Keep cached verification and optional batching; retain the shared upstream
   contribution direction. No competing architecture is selected.

This enforces an existing RFC-0005 assumption rather than relaxing an invariant.
It adopts no new primitive, token, admin authority, circuit, native image or
consensus change. The test's same-host separation and private-truth scoring
limits remain explicit. A future shared-transcript mechanism must identify its
availability and consistency assumptions; no authenticated bulletin is silently
assumed to exist today.
