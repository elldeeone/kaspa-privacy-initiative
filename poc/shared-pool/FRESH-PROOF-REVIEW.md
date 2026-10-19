# Fresh-proof adversarial second pass

2026-10-19. Review of the offline harness, observer separation and report by the
implementing agent; not an independent cryptographic audit. The compact relation,
covenant, parameters and invariants are unchanged.

| Challenge | Evidence and remaining boundary |
| --- | --- |
| Mint value or strand a claim? | Both exclusive histories validate and drain every created note. Payouts plus integer pool fees equal the original 1,000,000,000 sompi in each fixture. No added funding or privileged payout path. These are finite explicit-UTXO tests. |
| Spend once with each proof? | Same nullifier checked before either spend. Both winner orders reject the loser through the builder and native validation against the actual winner successor. Hostile duplicate paths/roots are recomputed; this is separate from old-outpoint rejection. Singleton also has a terminal-shape inconsistency, disclosed rather than counted as isolated nullifier evidence. Larger cases avoid it. |
| Change receiver/value/fee while refreshing? | Authorization bytes compare equal after masking only anchor count/root. Same destination is derived once, instead of using the usual history-step-dependent payout derivation. Native wrong-payout/script/fee and swapped proof-authorization controls reject. |
| Accept wrong pool, anchor or stale state? | Wrong domain/root, malformed paths/proof and actual first-transfer stale nullifier paths reject. Existing history witnesses authenticate each genuine old/fresh anchor. No claim about reorg selection or RPC freshness follows from synthetic contexts. |
| Old fallback depends on the new prover/operator? | Six separately isolated public rebuilds see only a chosen bundle, current public state/UTXO and VK. No wallet, PK or network; original proof/auth bytes are preserved. Parameters/history must still be available for other operations, and exact fees cannot be repriced without fresh authorization. |
| Wrong rejection reason? | Positive before-winner instances pass for both genuine proofs. Duplicate transactions use current inputs and recomputed successor data. No check is weakened. Native errors remain private; six duplicate checks return script verification failures. This is bounded rejection evidence, not proof that all double-spend encodings are impossible. |
| Feed truth or the alternate world to the attacker? | Each bwrap process mounts one serialized history, observer code and runtime only. Host home is absent; network is loopback only. Labels, seeds, openings, bundles and the other history stay outside. A separate parent scorer rejects any candidate set that excludes the actual source/position. |
| Overstate privacy from chosen old targets? | Report all exits at withdrawal and full drain, abstentions, source/note counts, recency and explicitly uniform priors. Bob is deliberately the earliest received note. Three selected cases do not support a population interval, optimal timing policy, independent-user count or real-world anonymity. Full-exit values and deposit ancestry remain visible. |
| Disclose the old restriction while publishing evidence? | Export is an allowlist. All old-arm transactions, pending requests/bundles, private errors/truth and wallets are omitted. It rejects exact secret/raw/hex/JSON-array encodings and private-field names. Actual-material injection controls pass; the singleton's identical public authorization is an explicit pre-run exception, not an exception for its unused proof. |
| Confuse offline execution with acceptance? | Constructed transactions and all 48 saved JSON instances pass native Full and policy checks using explicit synthetic UTXOs. Ledger checks current outpoint consumption separately. No RPC, broadcast, chain admission or simultaneous live race occurred. |
| Misreport resources? | Initial external GNU time captured wrapper RSS/CPU rather than prover peak memory. Prover peak memory is null, wrapper measurement labeled. Wall/proof/load timings remain available. Future launcher measures inside the namespace. |

Verification: release build passed; three complete proof fixtures, six isolated
public rebuilds, 48 serialized native replays, 34 hostile native controls,
12 existing observer tests and six new export/scoring tests passed. Export also
rejected six injections drawn from actual private material. Public projection
hashes, source/specification hashes and proof bytes were checked before commit.
The frozen Rust/specification bytes still match the original proving run.

The first analysis was retained privately, then rerun to add serialized funding
validation with the existing native CLI. No ledger, proof, target, observer rule,
amount or evaluation threshold changed. Raw proof generation was run once.
