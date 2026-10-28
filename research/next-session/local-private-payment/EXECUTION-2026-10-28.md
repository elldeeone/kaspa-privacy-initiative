# Resumed native KAS payment work — October 28

The owner authorized completing the three workstreams and continuing at full
speed. Work continues in `continuation` on `research/shielded-kas-feasibility`,
from `8cd88a6eb4e01ddfaeeaf3c902457dc70c7032e3`. The historical
[handoff](SESSION-HANDOFF-2026-10-27.md) is preserved unchanged.

## Executed component evidence

1. **Owner authorization:** all 21 planned controls passed, including actual
   recipient substitution, wrong-key, malformed assignment and field-alias
   refusals. The 16 matrix cases evaluated 24,281,808 rows in total. See
   [the results](../../../poc/local-private-payment/native-authority/RESULTS-2026-10-28.md).
2. **Authenticated proving:** three isolated MASCOT servers produced the same
   genuine Groth16 proof, independently verified with rejection of a changed
   statement. Invalid assignment and MAC corruption refused proof release.
   [Toy evidence](../../../poc/local-private-payment/mpc-prover/evidence/2026-10-28-functional-toy/QUALIFICATION.json)
   and [actual shared SHA evidence](../../../poc/local-private-payment/mpc-prover/trace/evidence/2026-10-28-active-sha3/QUALIFICATION.json)
   are separate from a financial batch. The actual SHA case covered 28,849 rows;
   the 28-case capability suite separately tested private assertions, changed
   bindings, poisoned contexts and one-use enforcement.
3. **Wallet and Exit components:** genuine new-domain Output and AuthExit proofs
   passed independent verification. Two native Exit cases passed Full and
   ScriptEngine checks; 21 negative cases refused. Their payment metadata was
   deliberately unselected, so this is unfunded Exit-component evidence. A fresh
   private Original bootstrap and isolated seed-restoration probes also ran.
   See [wallet results](../../../poc/local-private-payment/private_batch_trial/RESULTS-2026-10-28.md)
   and [the bootstrap boundary](../../../poc/local-private-payment/private_batch_trial/PRIVATE-BOOTSTRAP.md).

The full joined financial matrix has now been generated and checked against
the direct stock circuit: 13,093,029 rows, 12,949,821 variables and three public
slots. Its fingerprint is
`c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab`.
Stock parameter generation succeeded, but the first serialization hit a tmpfs
user quota. That attempt remains retained. Fresh disk-backed setup02 completed
in 97.5 seconds at 9.90 GiB peak, and independent PK/VK readback passed. Its
2,608,842,576-byte canonical proving key is retained as a 1,749,414,110-byte gzip;
the VK SHA256 is
`2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102`.
The complete 15,474,590-operation financial trace was subsequently exported
with actual model/key/layout/prefix bindings. These are source/setup results,
not a financial proof.

The first full financial attempt reached all three owner listeners, then the
workers exited before any owner clients or private inputs. The stock external
client queue has a 60-second timeout; the launcher had been paused for resource
scheduling. That source-consistent explanation is retained separately from the
observed exit codes, without reading raw diagnostics. The repair replaces only
the empty-queue timeout with an unbounded condition wait. All three real MPC
roles then survived a deliberate 65-second idle period and completed the small
TLS/DDNNT/full-proof control with independent verification. A fresh full
financial run uses immutable Source05 and the reviewed public-point decoder
optimization. It remains an unfunded qualification attempt until it finishes.

The original recovery audit completed 108 of 180 primary scanner cells before
disk exhaustion during D6 preparation, before D6 Original intake. Those results
are preserved as partial evidence. Complete preparation provenance had not been
serialized, so they cannot be imported into a complete aggregate. A fresh audit
now uses a separately reviewed controller that durably saves preparation records
before Original intake and checkpoints whole completed batches. The scanner,
guard, archive and Original selection remain unchanged.

## Work still required

1. Run the complete three-owner private construction and financial prover with
   the actual matrix, private state witnesses, hidden tuple routing and durable
   release history. Bind that proof to the six genuine Output proofs, selected
   R0 guest/image and native payment acceptance. Rehearse the complete terminal
   path before any new testnet funding.
2. Freeze the actual observer views, owner-truth separation and privacy criteria
   before the private experiment. Test original-seed received/change spending,
   independent Exits, complete reserve/fee accounting and confirmed TN10 payouts.
3. Complete the earlier final recovery-data audit, publication and fresh Tor
   readback. Its partial scanner preparation remains incomplete evidence.

[RFC-0030](../../../docs/rfc/0030-private-batch-construction.md) and
[ADRs 0074](../../../docs/adr/0074-private-batch-construction.md),
[0076](../../../docs/adr/0076-batched-private-assignment-validation.md) and
[0077](../../../docs/adr/0077-durable-private-attempt-history.md) define the
bounded research integration. The new history design uses one unresolved
attempt per service/pool epoch and permanent released-NF tombstones. Unknown
exposure can permanently stop private progress; independent Exit remains usable.
Actual whole-CASE accepted-chain verification is required to resolve an attempt.
The registered accepted-head and public continuation designs are recorded in
[ADR-0079](../../../docs/adr/0079-registered-head-program-selection.md) and
[ADR-0078](../../../docs/adr/0078-public-continuation-after-private-egress.md).
Their source controls do not yet establish a genuine financial or live result.

## Retained limitations

The October 27 result remains six testnet payments, nine confirmed payouts and
zero reserve. Its measured complete fees remain **12.5793%**, against the fixed
2% target and 21-KAS denominator. No cheaper completed lifecycle, improved
native grouping privacy or completed recovery publication has yet been shown.
Public known-seed fixtures are functional tests, not privacy evidence. No new
profile funding or broadcast has occurred in this resumed work. These are
research components, not cryptographic correctness or production-safety claims.
