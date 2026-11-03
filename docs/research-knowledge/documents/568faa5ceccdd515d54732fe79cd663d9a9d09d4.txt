# Capacity source delta review

Source ACK for finalized shape/direct-CS controls; **fresh setup and financial
acceptance remain gated on those results and actual native execution**.

Compared the complete new deltas against the original compact-batch relation
and emitter at base `5aaf99532d87`:

| New source | Reviewed SHA256 |
| --- | --- |
| `poc/private-exit-stress/prover/src/lib.rs` | `638c3f5b1d34be4df0543718bb40dae8ff27aeeba1a53e10434935e1f91a2724` |
| `poc/private-exit-stress/prover/src/circuit.rs` | `17c39f7d3064d66c0db8ee8d23a97c53fd14e8cfd07531781eab933ff242acef` |
| `poc/private-exit-stress/native/src/policy.rs` | `315655892e55a06c3e69e0c9a08b0c764697497a2e6938e8c4c78914f806420b` |

The new domain matches ADR0058. In the reviewed delta, `no_append` controls
zero output fields including rho, CM root/count carry, ordered digest/start
sentinels and zero-container CF hash. `terminal` and `has_reserve` independently
control positive remaining-reserve bounds. Terminal implies no-append, while
continuing no-append requires payout. Wide remains append-only/P0. No private
input ownership, membership, original positioned NF, dummy-slot NF, exact Auth
hash, amount/range, distinctness or balance gate was removed.

The native branch first handles CM mode, then independently chooses terminal
versus exact immutable-policy continuation from remaining reserve. It retains
both current NF absence/insertions, count limits, exact reserve decrease and
payout amount/destination. Its mode0 branch fixes the omitted metadata and
carries CM state. This addresses the old full-CM nonterminal-exit obstruction
without an administrator, reset or revealing fallback.

No additional source blocker was found in this delta. Review does not infer
same-matrix behavior from similar source, nor constraint satisfaction from host
validation. Require finalized compact fingerprints across append/continuing
no-append/terminal no-append, direct constrained adversarial controls, fresh
role parameters, full-key identity checks and genuine proof/native outcomes.
Constructed near-full roots remain supplied premises; no accepted-history,
future fee affordability, privacy or provider retention claim follows.
