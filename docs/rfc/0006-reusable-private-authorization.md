# RFC-0006: Does authorization/state separation remove the reproving bottleneck?

Design: [ADR-0018](../adr/0018-reusable-private-authorization.md). H5 is supported
for the bounded offline and TN10 workload, 2026-10-19. A complete rehearsal and
fresh measured trial confirmed Bob's exact-proof reuse after Alice's payment,
with his prover stopped and about 21 ms of public rebuilding. Both pools drained.
See [measurements, controls, cost and limits](../../poc/shared-pool/ANCHORED.md).

Smallest workload: bootstrap Alice/Bob claims; Bob prepares a whole-note exit;
Alice pays Bob again from her different note; a public-only process discovers
and validates the updated reserve and reuses Bob's exact authorization/proof;
then both wallets drain all remaining claims. Bob's initial prover must stop
before Alice's payment and remain stopped until the target payout is confirmed.

Offline success requires actual native script/Full consensus validation, native
mass/policy checks, exact SDK round trips, and no second settlement proof. A
public-only rebuild target is under one second excluding RPC/confirmation; this
is a proposed usability threshold, not a measured result. Record proof/setup
time, exact proof hashes, all rebuild/validation work and fees separately.

Reject malformed proofs; false anchors; future anchor counts; wrong domain/VK;
spent nullifiers; dropped/reordered commitments or nullifiers; changed mode,
fee, payout, recipient or ciphertext; under-backed successor; incorrect terminal
shape; below-floor values; capacity overflow and integer-boundary cases. Check
both proof relation predicates and direct hostile native transaction mutations.
The current version-3 stale-proof rejection remains intact.

Only after offline success, run a fresh funded TN10 rehearsal and measured trial.
Confirm chain acceptance and native payout UTXOs, exact conservation and zero
remaining reserve. Export only public artifacts and sanitized measurements.
No wallet, plaintext note, secret or proving witness enters Git.

Stop this candidate if a missing native predicate requires a trusted assertion,
if current native resource/relay limits cannot accommodate it, if an equivalent
expensive settlement proof is still needed, or if any safety control accepts.
Do not weaken controls to reach a live demonstration.

Open beyond this test: trees and capacity, bounded anchor lifetimes and privacy
of anchor selection, continuous contention and admission fairness, fee repricing,
reorgs, public data availability, independent cryptographic review and practical
anonymity. A successful rebase does not settle these questions.
