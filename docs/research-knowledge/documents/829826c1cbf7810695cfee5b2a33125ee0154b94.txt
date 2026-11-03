# ADR-0090: Owner-local hidden-candidate truth release

Date: 2026-10-29 UTC.

Status: Accepted source architecture. The authority and process boundaries have
real-process and production-link controls. The selected owner-lifecycle,
paired-arm parent and score-worker launch callsites remain absent;
`CONFIGURED0`, launch false and no privacy qualification remain unchanged.

## Problem

The transparent baseline can obtain owner-grouped truth from its explicit,
consented public-effects receiver. The hidden candidate cannot use that path:
opening its owner map would disclose the exact grouping the experiment is
supposed to measure. A parent-authored truth packet, a public digest of private
owner truth, or one owner's score permit unlocking all three owners would make
the privacy result caller-authored.

The three hidden-arm owner processes already possess the genuine local facts:
their actual public nullifier and the two created rows and commitments for each
round. Those facts must remain in the same long-lived owner process from R1 to
R2 and become available only after the genuine observer barrier has frozen.

## Decision

1. Each hidden-candidate owner child retains its own R1 and R2 truth in private
   memory. The parent control channel carries no nullifier, created-row digest,
   commitment, stable logical-owner identity, owner-body path, body or body
   hash. On abort or exit, the child scrubs the retained truth.
2. `RunMeasurement::issue_candidate_truth_barrier_release()` is the sole
   production mint for `CandidateTruthBarrierReleaseAuthority`. It is callable
   exactly once, only in `BarrierFrozen`, only for `HiddenCandidate`, and only
   after genuine capture and observer completion. Its identity binds the full
   run binding, capture completion, observation completion and frozen barrier.
   Candidate owner-score permits cannot issue until this global release has
   been issued. The transparent baseline cannot mint it.
3. R2 completion emits one private, move-only
   `CandidateOwnerTruthPendingAuthority` for the exact three-owner supervisor.
   It binds the supervisor session and continuation plus the admitted two-round
   financial runs, capture plans, projections and context identities. Context
   identities have no caller parameter in the global measurement release; the
   bridge can obtain them only from this private pending authority.
4. `CandidateOwnerTruthPostBarrierBridge::release` exchanges both live bits
   before validation. It recomputes the global release identity, requires the
   hidden classification and exact pending run/plan/projection lineage, then
   privately combines the prebound contexts and supervisor continuation. A
   mismatch, replay or exception consumes both inputs and poisons the owner
   supervisor. The supervisor kills remaining children and closes its control
   and truth sockets; a corrected receipt cannot revive that process tree.
5. The supervisor independently checks trial, per-round attempt/cohort,
   admitted runs/plans/projections/contexts, session and continuation before
   sending the release command. Success yields three independent move-only
   `CandidateOwnerTruthEndpointAuthority` values. Each endpoint owns one
   owner-local `SOCK_SEQPACKET` receiver; there is no public fd, read, body or
   packet getter in production.
6. Candidate and baseline use the same exact 813-byte `KPB BOT1` scorer packet
   layout. The canonical classification byte is 1 for `HiddenCandidate` and 2
   for `ExplicitOwnerPublicEffectsBaseline`. The frozen barrier is deliberately
   absent from the packet; it remains authority-bound. The packet omits the
   stable logical-owner identity and owner contract after the endpoint has
   validated them.
7. Global release is not score consent. The common
   `OwnerTruthScoreHandoffBridge` must separately consume one endpoint and that
   owner's one-shot `OwnerTruthReleasePermitAuthority`, recheck owner,
   classification, barrier, two capture plans and socket identity, and emit
   only an opaque measurement input endpoint. One owner's permit cannot unlock
   the three-owner batch.
8. The baseline and candidate owner trees remain disjoint under the separate
   private arm-isolation join. This decision does not permit owner, root, PID,
   TLS, contract or logical-roster reuse across arms and does not require role
   permutations to differ.

## Rejected alternatives

- **Parent constructs or parses candidate truth.** This exposes the hidden map
  and creates a second truth authority in the observer/controller.
- **Put the barrier digest in a candidate-only packet.** This creates an
  arm-specific scorer schema and leaks an avoidable classification-dependent
  shape. The typed release and score permit already bind the barrier.
- **Let one per-owner score permit release all owners.** One score child could
  unlock or consume truth belonging to the other two owners.
- **Accept a public receipt, digest, JSON object or raw fd.** These are
  reproducible data, not a one-shot post-freeze authority.
- **Reuse the transparent disclosure collector.** Its owner mapping is the
  positive-control disclosure and is forbidden auxiliary information for the
  hidden candidate.

## Security and privacy consequences

- Missing truth, child EOF/nonzero exit, wrong credentials, wrong
  run/trial/round lineage, cross-plan/context substitution and replay halt the
  candidate. Liveness loss cannot become a partial or re-cohorted score.
- The parent still sees public experiment lineage and opaque endpoint metadata.
  It does not see the private owner map, stable owner identity, truth bytes or
  a digest of those private values.
- The exact selected owner-child, bridge, measurement and handoff sources are
  trusted boundary components. A modified host, memory/swap disclosure, covert
  channel or unselected launcher remains outside this bounded source claim.
- Passing controls establish the implemented state and process ordering only.
  They do not prove cryptographic correctness, anonymity or production safety.

## Evidence and remaining gate

The boundary is implemented by:

- `poc/local-private-payment/private_batch_trial/privacy_measurement_authority.{hpp,cpp}`;
- `poc/local-private-payment/mpc-prover/financial/fresh_owner_process_adapter.{hpp,cpp}`;
- `poc/local-private-payment/mpc-prover/financial/candidate_owner_truth_post_barrier_bridge.{hpp,cpp}`;
- `poc/local-private-payment/mpc-prover/financial/fresh_owner_candidate_truth_schema.hpp`; and
- `poc/local-private-payment/mpc-prover/financial/owner_truth_score_handoff.{hpp,cpp}`.

The focused controls cover post-freeze issuance, pre-barrier/baseline refusal,
one-shot replay, cross-plan and context substitution, owner-local real-process
emission, unread endpoint destruction, common-schema equality, per-owner
handoff and production-mode compilation/link without fixture factories.

The selected private-lifecycle executable and root/history/replay minters, the
paired-arm outer trial callsite, registered selected parent and score-worker
launcher are still absent. Therefore this source closure cannot produce an
actual privacy result and must remain `CONFIGURED0`.

## Reconsideration

Revisit this decision if a selected scorer needs information not present in the
common 813-byte schema, if a genuine retry path is introduced, or if production
integration cannot preserve the one-shot typed joins without exposing owner
truth or stable cross-round identities. Such a change requires a new ADR and
new cross-arm, replay and parent-non-decoding controls.
