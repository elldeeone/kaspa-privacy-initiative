# Proposed research ADR: isolated hidden-key authorization composition gate

Status: PROPOSED RESEARCH EXPERIMENT ONLY. No production/current Native architecture acceptance. Source preparation is authorized; build/run remains held by Root.

Problem: direct sharing of the unchanged Native Spend witness shares the current owner-secret authority. Full prover collusion could then threaten funds. Current owner-local NIZK aggregation avoids that trust change but has an expensive recursive verifier path. We need one decisive authority/interface experiment before considering a different profile.

Options considered:
1. Retain current owner-local NIZKs and separately qualify actual native recursive verification. This remains the existing contract and is not displaced by this experiment.
2. Share unchanged legacy Spend authority. Rejected as the default alternative because all-server collusion would learn spending authority.
3. Use an established spend authorization signature whose verification key and signature stay hidden inside a new joint relation, while the signing seed/scalar/nonce stay owner-local. Study only this option in the isolated public synthetic seam. Public randomized authorization keys are unnecessary for the published proof interface if the key itself stays private; sender/co-server/network linkage still requires separate analysis.

Proposed bounded experiment: reuse exact Native SHA/HMAC/CV/depth16/ranges while explicitly replacing only Note.owner authority with a new canonical Babyjub verification-key commitment. Join that new NativeAuthSpend predicate to unmodified mature Circomlib EdDSAPoseidonVerifier plus established point/range gadgets and explicit admission wrappers. Bind the complete reconstructed exact-effects statement via constrained SHA256 and stock Poseidon(2). Evaluate every actual matrix row, including both digest and key links. Test a coherent coordinator redirection without consent, then the same redirection with deliberate owner consent. SPEC-02 and CONTROLS-01 provide all assumptions/offsets/controls.

Tradeoff: signatures may keep co-servers from acquiring spend authority even if all collude, subject to the mature scheme and the complete new profile/every-path checks. Confidentiality of amounts/openings/hidden identities would still depend on an honest participant and an actually qualified malicious MPC/prover. This is weaker than current owner-local isolation under full collusion and cannot be described as automatic privacy improvement.

Consequences: new note owner commitment, key/address/backup profile, complete exact-effects authorization, migration and independent Exit semantics would be necessary before any accepted profile. New CS requires new setup/keys. The prototype does not design those production subsystems, reuse current VKs, accept legacy notes, issue a new token, or change native KAS backing. No setup/proof/MPC/native job occurs in this gate. Source-policy wallet fingerprints and active cohort retry leakage remain separate unsolved privacy blockers.

Decision boundary: no architecture decision is made here. A passing source review permits only a separately released setup-free synthetic matrix qualification. A passing future gate would justify assessing the next minimal malicious-MPC witness boundary, not shipping this design. A first failure is preserved and stops the identity. The existing financial/data publication proceeds independently with this unfinished source package excluded.
