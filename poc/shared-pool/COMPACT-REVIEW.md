# Compact-state adversarial second pass

Second pass completed with the offline gate, complete TN10 rehearsal and fresh
100-payment TN10 trial, 2026-10-19. This is the implementing agent's review,
not an independent audit or cryptographic correctness proof.

| Attack or missing dependency | Required enforcement and current evidence |
| --- | --- |
| Mint private value | R1CS owner/membership, bounded integer conservation; note position bound to path and nullifier; native exact initial reserve backing. Matching-commitment economic boundary tests are separate from public-input mutation tests. |
| Hide invented notes in genesis | The initial accepted count is one; private index must be below that count. Every later note position must be proved empty before incrementing the count. Hidden future leaves cannot become spendable by advancing past them. |
| Seed forged historical roots | First spend requires canonical one-entry history derived from the initial note root and the canonical nullifier sentinel tree. Later archive updates authenticate an empty append index and the exact newly constructed commitment root/count. |
| Reset current spentness | Native predecessor membership and two sequential tree updates authenticate current spentness and retain all other branches. Successor-root mutation controls also update the output script, avoiding a trivial mismatched-SPK rejection. |
| Double withdrawal using a valid proof | A native control reuses Bob's genuine proof after payment, constructs consistent fresh duplicate-insertion roots and paths, and must reject the equality at the predecessor gap. Consuming the current UTXO also prevents exact transaction replay. |
| Ambiguous integer comparison | Full 256-bit nullifiers, explicit unsigned limbs, native comparisons against an independent host ordering at limb/sign boundaries. No hash truncation or probabilistic small-key collision assumption. |
| Duplicate commitment griefing | Distinct funded positions derive distinct economic nullifiers. Private position membership and count bounds are constrained. Three identical commitment leaves at different positions pass valid private authorization checks. |
| Redirect payout, alter fees, steal reserve | Authorization binds recipient/payout/fee; native outputs and exact arithmetic must match. Terminal shape is available only when commitment and spend counts agree. No alternate signature branch or admin key. |
| Replace rules/VK/domain | Successor script uses the consumed script's immutable prefix/suffix around the exact checked new state. Wrong-domain proofs and forged successor state reject. |
| Prover or operator disappears | Bob retains an old proof. His isolated public rebuilder receives no wallet or proving key and discovers updates by reserve outpoint. Both original payment provers stopped before his confirmed exit in both the two-payment rehearsal and 100-payment trial; exact proof and authorization bytes were reused. Every remaining claim then drained. |
| Missing history or reorg | Public leaves/archive must remain available; current root proofs cannot be fabricated when data disappears. Full-node view and stable accepted history are explicit assumptions; no arbitrary-reorg recovery or permanent data availability claim. |
| Leak relationships | Private note index stays inside the proof, while nullifiers and their predecessor ordering are public. Anchor count reveals an old candidate horizon. Fees, exits and ancestry remain visible; no anonymity improvement is inferred from scaling. |

The original array variants and their evidence remain unchanged. The new protocol
has no later deposits, partial withdrawals, continuous contention fairness or
fee repricing without authorization. The capacity fixture is synthetic and must
not be described as a full 65,535-note execution. Public reconstruction performs
work proportional to retained history even though native verification/transaction
size have fixed-depth bounds. This distinction belongs in the final results.

Evidence checks matched all 204 measured native bodies/full hashes and exact
funding/payout/fee accounting. A separate Python implementation reconstructed the
three trees, path witnesses and successor scripts. Five Rust test groups and
117 native hostile cases passed. These checks support the bounded result; they
do not replace independent cryptographic or protocol review.
