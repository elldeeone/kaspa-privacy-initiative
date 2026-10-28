# Batched capability runtime controls

All 28 fresh, isolated three-party public-fixture controls passed. The selected
implementation is core build13 and tests-only build03. All selected source,
object, vendor, binary, model and verifier identities were checked before and
after each case. Exact source bytes are preserved under `source/`.

The three proof cases (valid, caller mutation and reuse) produced identical
Native128 proofs across their three roles, accepted independently at128 and
rejected at129. The other cases require specific failure types and no H-map or
proof events. Nonempty private assertion residuals are included in the valid
case, and a nonzero assertion is actually rejected. Coin fault controls use the
stock checked-coin exchange on the two honest roles, with a corrupt role0 in
this test translation unit only.

`QUALIFICATION.json` gives the bounded result. `SUITE-RESULT.json` retains all
fresh run identities, timings and observed cgroup peaks. Raw worker captures,
private TLS keys and preprocessing files remain local and were never read or
hashed. No failure occurred in the 28-case runtime suite.

This is a public synthetic capability/coin/proof test. It does not qualify
external owner intake, a financial secret-derived prefix, process crash and
checkpoint recovery, durable service history, native settlement, privacy or
cryptographic correctness.
