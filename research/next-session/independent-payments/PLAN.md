# Independent native-KAS payments: execution plan

Date: 2026-10-23 UTC. Starting commit:
`5aaf99532d8714e510d421102df719f60f54d073` on
`research/shielded-kas-feasibility` in the continuation worktree.

The owner authorizes execution of the four next workstreams. Native test KAS
remains the sole asset. No mainnet, real funds, new primitive, privileged exit
or claim of production security is authorized by this experiment.

## Completion gates

1. **Settlement and complete fees.** Execute a public two-action semantic
   contract with actual verification of the existing owner proofs. Bind the
   externally selected starting outpoint/state, ordered transitions, current
   nullifier absence/updates, commitment placement, reserve, recipient effects
   and fees. Reject coherent competing, stale and tampered transcripts. Use
   those results to choose or falsify the smallest shared-settlement design;
   an ordinary verifier wrapper is not a new settlement. Any fee improvement
   requires an actual matched proof/native route and complete costs, including
   low-demand private unilateral exits. The existing 2.95% verification-only
   floor at reference rate100 remains applicable to its stated two-call route.
2. **Financial privacy.** Change the modeled payment behavior to address
   demonstrated invoice/co-output payer-role labeling and staggered funding
   ancestry. Review the candidate against established protocols and executable
   implementation dependencies. Freeze a new observer, source, workloads,
   independent sample size, truth boundary and original success thresholds
   before heldout generation. Retain negative controls and unknowns. A model
   improvement alone does not qualify an unimplemented cryptographic design.
3. **Independent recovery.** Prepare exact public parameter/history/software
   release and offline objects; verify actual retrieval and a clean software
   restore/build with original producer/cache paths absent. Separately evidence
   provider/administrative failure domains and retention. Own backup plus
   independently authenticated public data must suffice; a mirror cannot select
   financial authority, software, setup or current chain state. Stale/reorged
   history must not authorize spending. Provider independence remains open
   until a real separately controlled destination is identified and exercised.
4. **Private exits under stress.** Reproduce the existing append-capacity
   failure with actual native execution. Review a new-instance resolution and
   establish genuine proof/native exit evidence at the commitment boundary,
   with continuation and terminal payout. Preserve original positioned real
   nullifiers, membership, conservation and exact native outputs. Account for
   nullifier capacity over every admitted action. Never reinterpret old funded
   instances, reuse their setup for a changed relation or substitute REVEAL for
   a private exit. Test missing/corrupt material and stale/reorged state.

## Work division and ordering

Independent agents own settlement semantics, verifier/fees, privacy measurement,
primary-source comparison, public transport, cold software recovery, capacity
exits and adversarial review. Root owns cross-track decisions, documentation,
resource scheduling, final review/publication and integration.

Each new subsystem states its problem, assumptions, alternatives and selected
bounded experiment before implementation. Important changes are recorded in
RFC-0024 and an ADR before cryptographic implementation. Independent adversarial
review precedes new heldout draws and fresh parameter generation.

CPU-heavy setup/proving is serialized on this 14-logical-CPU/24-GiB host;
measured independent work may run alongside it when memory permits. No paid
compute/storage is selected. Resource limits are operational controls, not
privacy, economic or safety thresholds; retain failures and fix the cause.

## Evidence preservation and final integration

All old studies, genuine proofs, funded instances and negative results remain
historical evidence. New source/evidence lives in new paths. Evolving top-level
architecture documents are identified by their source commits; old manifests
are not rewritten to hide source evolution.

Backups, witnesses, owner/issuance maps, private study truth and discarded
unbroadcast alternatives remain outside Git. Public deterministic canaries are
explicitly unfunded and must never become a funding profile. Release exact
finite public inventories only after material review.

After the necessary design/proof gates, integrate independently funded,
varied-demand payments, private change/repeated spending, original-backup
recovery after service loss and exact terminal accounting. A fresh testnet
readiness claim requires actual broadcast and confirmed terminal native payouts;
local contexts, byte verification, synthetic observers or a prepared release
cannot substitute. If a gate cannot be closed, record the concrete dependency
and completed evidence rather than marking the four-track milestone complete.
