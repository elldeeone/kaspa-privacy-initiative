# Offline wallet adversarial pass

Scope: full generic wallet relation, real local receipts and synthetic host
admission/restore. Native authority and a proved outer transition are excluded.
Actual runtime outcomes belong in the result report; source review is not a
cryptographic correctness proof. The separate reviewer shares model/platform/host.

| Attack question | Enforcing layer and evidence | Remaining assumption/limit |
| --- | --- | --- |
| Mint value | Guest reconstructs notes/keys, checks u64 values and u128 equations; CREDIT verifies the exact recovery signature. Host consumes exact pending principal once and reconciles liabilities against synthetic reserve. Native/VM mutations and real CREDIT receipt cover these paths. | Initial backing/deposit recognition is a trusted synthetic fixture, not native evidence. |
| Spend twice | Guest derives both nullifiers from the same owned notes and requires distinct slots. Host checks all current markers under fixed policy before effects; restore replays them before scan. Old anchors do not select old spentness. | Host admission is not proved; native ordering/shared-state integration is open. |
| Release reserve incorrectly | Credit moves pending into private value without R += p. Exits create exact unpaid claims and do not reduce reserve. This harness has no payout or admin-withdrawal operation. | Native exact payout, paid markers and terminal drain remain unimplemented qualification gates. |
| Leak keys/values/linkage | Guest commits only the reviewed intent/auth journal; complete V2 encryption is constrained. Backups/inputs stay local and are excluded from public evidence. Separate actor restores use network/filesystem isolation. | Plaintext backups/raw secret memory and timing are not hardened; public entry/exit amounts/shape and traffic correlation remain. No anonymity/security certification. |
| Dependency disappears | Missing/changed history or receipt errors before scanning; malformed receipt envelopes halt availability. A proof is checked against the actual permitted image and default verifier parameters. | The host classifier is narrower than total R13; missing data cannot be relabelled invalid or zero. |
| Reorg/stale state | Expected latest synthetic history pin, complete replay, allowed anchors, cursor and current markers bind the chosen fixture lineage. Wrong/orphaned roots and replay are rejected. | Pin origin/freshness is locally trusted. Caller-recomputed pins choose a different synthetic branch and authenticate no native lineage. |
| Hidden trust | Pinned Orchard/Ed25519/RISC Zero, compiler/source identities and private local machine are explicit. A clean target rebuild reproduced identical guest bytes. | Passing tests and a shared-model reviewer do not establish cryptographic soundness, independent operators or external audit. |

Review-discovered corrections: raw scanner preconditions are enforced by
receipt/pin replay before scanning; duplicate decoded backup keys reject;
replacement-pin tests distinguish invalid-operation no-ops from unavailable
history; isolated fixtures deduplicate repeated receipt names while rejecting
conflicting digests; shared receipt decoding requires exact bincode roundtrip
bytes. These changes add no authority or new primitive.

The typed `Intent::journal` helper still assumes validated ID widths. All wire,
guest and admission entry points shape-check first; a manually malformed local
typed caller can panic. The reviewer classified this as nonblocking API
hardening, not an acceptance bypass; it is retained explicitly with the frozen
proved core rather than changing its identity mid-run.
