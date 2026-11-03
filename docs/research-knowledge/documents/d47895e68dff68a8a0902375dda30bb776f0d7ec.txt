# Stage 2 adversarial second pass

2026-10-19. Self-review of the audit software and conclusions, not independent
cryptographic review. Protocol baseline `af9bae8`; no Rust, covenant, proving
parameters, live wallet or transaction builder changed.

| Challenge | Check and disposition |
| --- | --- |
| Mint value or release reserve incorrectly? | The new tools read retained transactions and write local JSON. They have no signer, builder or RPC submission code. Integer model enforces floors, exact public fees/payouts, conservation and remaining reserve. Corrupt balances/overlarge payouts fail controls. It is not a native validator. |
| Spend twice or count impossible candidates? | Every modeled operation spends one distinct eligible note position. Nested-prefix matching checked against brute-force enumeration for 340 systems/1,252 target queries; the value solver uses `Distinct`. Repeated commitment bytes do not merge funded positions. |
| Accept stale/wrong/replayed state? | Decoder follows reserve outpoints, rejects forks/missing lineage and duplicate IDs/nullifiers, checks old/new counts, historical count/root, P2SH continuity, ciphertext digest and amounts. It assumes accepted proofs and does not verify all Merkle paths, Groth16 or canonical history itself. Existing native evidence is the acceptance basis. |
| Confuse a nullifier index with a private note index? | Native predecessor index is an indexed-nullifier-tree location. Attack derives note eligibility from historical commitment count and joint spentness; it never reads predecessor index as the consumed note. |
| Leak private truth into the attacker? | A strict projection gives only transaction/header records. Sandbox mounts no home, wallet, manifest, descriptor, private backup or scorer input; network interface is loopback only. Two known H6 source facts are scored after observer execution, in a separate process context. The trace selection is exploratory and already known. |
| Inflate attack accuracy or anonymity? | Source transaction, position and person are separate. Publish all-exit coverage/abstentions, not just selected 2/2 source certificates. Large-trace amount analysis was not run; its candidate counts are upper bounds. No fitted probabilities, population confidence intervals, user counts or network privacy result. |
| Hide late information or failing cases? | Each target is queried at its own prefix and full drain. All four/102/three recorded exits remain in coverage. Inconsistent or unknown solver results fail instead of counting as privacy. No traffic experiment was generated, so no low-activity policy threshold is claimed. |
| Claim an invalid modified proof succeeded? | Fresh-anchor comparison changes abstract eligibility only; the old native proof would reject modified authorization. Reports explicitly require a genuinely new proof and describe the native fee as an estimate from unchanged shape/rate. |
| Expose the fallback off chain? | Same-note old/fresh authorizations share a nullifier. If both become visible, the old anchor's restriction remains available. H6 publishes a labeled bundle as research evidence; a proposed wallet must retain its unused fallback privately. Chain-only analysis excludes this separate public-artifact surface. |
| Dependency disappears or history reorgs? | Audit needs retained receipts, Python/Z3 and bubblewrap, and makes no new availability or reorg guarantee. H7 recovery assumptions remain. A real privacy policy must use independently authenticated accepted history and preserve safe exits. |

Twelve control tests passed. The runner pins the exact projected input, observer,
test/specification and output hashes. Result reproduction needs no wallet secret,
new proving setup, funding or network access. Remaining limitations are explicit
in [PRIVACY.md](PRIVACY.md); useful anonymity remains unestablished.
