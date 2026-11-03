# Hidden cohort dispatcher seam

Status: **UNQUALIFIED SOURCE ONLY**. The genuine common ingress is wired into
registered construction, but no configured driver/launch qualifies privacy.

## Audit result

The selected financial trace privately sorts three complete NF/CV rows and
uses 768 fresh private random bits to sort six whole Output520 tuples. The
dispatcher is not the permutation authority.

Registered intake now calls `receive_cohort`. It accepts and TLS-authenticates
all three roles in arbitrary local arrival order. Each authenticated owner gets
its already validated public specification immediately, avoiding the upstream
sequential-client deadlock. MPC agreement, preprocessing and private upload
remain blocked until the complete cohort exists.

After that barrier every computing party processes C0/C1/C2 canonically, so
different local socket schedules cannot reorder all-three MPC operations. All
three masked frames must have one equal fixed width. Arrival labels go only to
the private dispatcher observer; public phases reveal only listener readiness
and whole-cohort completion.

This is primarily a liveness and evidence defect. A corrupt server may know
which masked share came from each owner; the observer model includes that.
Privacy instead requires the authenticated relation to hide the
owner-to-public-NF/output permutation and forbids any later per-owner release.

## New source-only seam

`hidden_cohort_dispatcher.{hpp,cpp}` provides:

- exactly three roster-pinned roles on one common route;
- one immutable attempt/cohort and one fixed frame width;
- arbitrary arrival order, retained as observer metadata;
- refusal of retries, reconnects, partial cohorts and route fallbacks;
- full-cohort sealing before authenticated-MPC consumption;
- one unlabelled aggregate release and no owner-release/body-getter API; and
- exact pins for the selected private NF/output sorting trace.

Changing connection order does not change the aggregate release binding.

The standalone dispatcher is not used as an MPC body buffer. Real
`AuthScalar` values remain in `receive_cohort` and enter `execute_trace` in
canonical role order.

## Remaining integration

1. Finish the typed registered-driver authority handoff into construction.
2. Wire the genuine public handoff after aggregate release, never
   to the private permutation or owner-to-public association.
3. Add a configured registered build and complete transitive closure,
   then run the real proof and frozen observer experiment.

`source_status()` remains `UNQUALIFIED_SOURCE_ONLY`; registered integration,
launch authorization and privacy qualification are false.

`test_owner_cohort_ingress.py` covers all six arrival permutations, equal
fixed-frame enforcement, duplicate/incomplete refusal, and a real localhost
3-server/3-client run with different forced arrival orders per server under a
deadlock timeout.
