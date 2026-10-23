# RFC-0023: Compact native private-payment fee feasibility

**Status:** Native-only feasibility experiment; financial/circuit profile open.
**Date:** 2026-10-23 UTC.

ADR-0056 selects an actual whole-program screen after the authenticated subtree
component passes. The target remains complete fees at or below 20,000,000 sompi
per genuine 1,000,000,000-sompi useful payment at reference rate100. A two-output
sequential route remains above target; the candidate uses a single payer's
already demanded batch with independent recipient exits.

Required evidence is actual complete common code/wire lengths, every retained
branch/VK/guard, conservative metering, integer fees/storage and all cashout tails.
Public zero-proof cases must reach the final G16 seam and malformed cases fail
earlier. Conditional scalar allowances are not emitted code or financial proof.

Open questions before any funded profile:

- Matched circuits for the emitted mode/arity/range/CM-array digest encoding;
  exact obligations are recorded in the [circuit memo](../../research/next-session/private-change/fees/CIRCUIT-OBLIGATIONS-01.md).
- Independent private exits at CM/NF capacity and the privacy cost of a no-append
  full-exit mode, without privileged withdrawal or cooperative witnesses.
- Genuine wide-payer and compact-owner proofs under fresh selected parameters.
- Public recovery/recipient delivery for aligned gaps and the new wire format.
- Complete real cost/amount/privacy effects under legitimate demand and full
  drainage, including smaller/separate-time payments and fee spikes.

The current Auth528 private-change wallet and all old privacy/fee failures remain
unchanged. A cheap branch or faster prover cannot be presented as a complete
qualified native-KAS payment system.

The emitted screen now passes55/55 expected native outcomes with23575 common
bytes and a conservative15,008,331-unit all-valid-path bound. Complete32-payer
cost projection is1.949145625%, or1.967895625% under payer2200 stress. This
retains all independent exits/storage/terminal costs. Eight positives reach
only the intentional final invalid-G16 seam; no financial acceptance occurred.
Separate-time payments remain4.72573%. See the [native result and scope](../../research/next-session/private-change/RESULTS.md).
