# Adversarial review of the note-granularity screen

The new code is read-only. It does not create proofs, alter a ledger, sign or
broadcast transactions, release reserve KAS, spend a nullifier or add a merge
operation. Source hashes and the predicted public-field digest are checked
before private-value scoring. The independent whole-KAS search reproduces the
four predicted baseline and four merge histories; altered payment truth and a
truncated public packet are rejected. The executed truth remains in both.

The exact-four finding uses *more* information than a normal chain watcher:
the research fixture's payout-owner controls and all seven directed contacts
in order. It is therefore a conditional strong-observer result. Additional
real information can make more values exact; it cannot make the four already
forced values uncertain. A's truthful own-payment disclosure collapses the
remaining histories. The service's ordinary issue/redeem log does not by itself
contain those private payment instructions, and the controller's timing
schedule is not an independent network-identity measurement.

The four structural histories hold public value, kind, output count and packet
shape fixed under a declared opacity assumption for randomized commitments,
ciphertexts, nullifiers and Groth16 proofs. Different hidden histories would
produce different actual cryptographic bytes; this one run does not prove
computational indistinguishability or a posterior probability. Whole-KAS and
0.1-KAS grids are sensitivities, not real-world payment-price distributions.
The hypothetical merge omits implementation, proof generation, native fee,
contention, reorg, recovery and transcript-timing cost; its fine-grained
candidate increase cannot qualify a privacy architecture.

No security invariant, spending authority, fee rule, output authorization,
stale-state check or dependency fallback was changed. A future merge would
need separate review for two-note ownership, atomic distinct nullifiers,
conservation, replay, stale roots, output binding, fee accounting and recovery
before any Testnet trial. Failure of the offline analyzer halts the analysis;
it cannot accept an invalid state or move value.
