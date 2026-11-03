# Independent read-only Full-validator result observation

Read the retained official isolation/UTXO-Full result without executing the
helper. Report SHA256 `b11964f81405c7191b3e8b6ec5224b13fd880f03bd75a8450591b155e1b8c8a3`:
one unchanged-body positive, ten exact typed-stage rejections, and four separately
labelled source-adapted policy outcomes all match the prior source review.

The consumed2910-byte body is byte-identical to the original native diagnostic,
SHA256 `8cb44d28e488eab9e59f540b47016394dd8cf440313332e0cac48e827ac18c97`.
Positive Full returns exactly80M sompi. Wrong storage mass reaches `WrongMass(29,30)`;
changed P reaches exact `SignatureInvalid(ZkIntegrity("Groth16 verification failed"))`.
Maturity and sequence cases stop at their intended Full checks; four malformed
cases stop in isolation. The source-adapted500-rate failure remains explicit.

This closes source/result observation only. The reviewer performed no build,
native validation run or proving. The original source review and independent
Borsh/full-hash/P2SH/mass recount remain unchanged. Synthetic UTXO/DAA context,
private-header and actual-mempool omissions, NONFUNDABLE noncontinuing policy,
missing accepted lineage/backing/exits/privacy remain explicit limitations.
