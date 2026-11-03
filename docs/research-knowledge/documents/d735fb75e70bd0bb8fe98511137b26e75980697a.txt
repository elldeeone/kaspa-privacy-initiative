# Raw dummy padding reveals a public format difference

Exactly one frozen ciphertext-only experiment completed. The byte31 high-bit
classifier flagged129/256 old uniform-random dummy ciphertexts,0/256 genuine
V2 Receipt216 sealed boxes and0/256 proposed sealed dummy ciphertexts. In this
declared fixture every flagged sample was a dummy; an unflagged sample remains
unresolved. This is a synthetic format result, not a population privacy result.

| Class | Flagged / total |
| --- | --- |
| Historical uniform-random264 dummy | 129 / 256 |
| Genuine crypto_box Receipt216 seal | 0 / 256 |
| Random216 sealed to fresh throwaway recipient | 0 / 256 |

For the fixed forced-choice diagnostic, guessing dummy when flagged and real
otherwise scored385/512 against historical padding and256/512 against corrected
padding. These comparisons share the real control. No confidence interval,
independent improvement estimate or protection against other classifiers follows.

The cause is source-grounded: crypto_box0.9.1 prefixes the generated ephemeral
public key in `src/public_key.rs:57`; `src/secret_key.rs:59` derives it with
Montgomery base multiplication. curve25519-dalek4.1.3's `edwards.rs:553` converts
to Montgomery form and `backend/serial/u64/field.rs:365` emits a canonical field
encoding modulo2^255−19. Bit255 is zero. Historical raw random bytes set that
bit with probability1/2. The pinned source map is in the
[final pre-run freeze](padding-01/PRE-RUN-FREEZE.json).

The runtime used the existing genuine crypto bridge, fresh unfunded recipient
material, real receipt serialization and generator-local decrypt/roundtrip
checks. Keys/plaintexts were never saved. Labels were separately shuffled and
hidden from the network-isolated attacker. Predictions were sealed before the
separate scorer received labels; the scorer independently checked each result
against the fixed bit rule. Public sample labels may now be inspected without
exposing a secret. No actual wallet, backup, profile, proof parameter or network
source was accessed.

Live cgroup limits were captured **before** generation: one CPU,2GiB memory,
zero swap. Controller wall time was14.1606s; systemd recorded14.210s service
runtime,14.190s CPU and22.5MiB peak memory. The service finished successfully,
inactive/dead with MainPID0. These are format-control resources, not wallet or
prover performance measurements. [Raw result](padding-01/run/result.json),
[live limits](padding-01/run/LIVE-CGROUP.json),
[execution](padding-01/run/EXECUTION.json) and
[prediction barrier](padding-01/run/PREDICTION-BARRIER.json) retain the evidence.

The first freeze was superseded **before any inputs/runs** because a concurrent
lifecycle fix reached the shared file before it was copied as historical source.
The actual historical raw-padding source is now pinned asab6de90f…; the initial
fixed source is preserved separately. The
[cancellation receipt](padding-01/FREEZE-01-CANCELLED.json) records the source
correction; no attack, workload or threshold changed and no result was discarded.

The wallet correction seals arbitrary216-byte plaintext to a fresh throwaway
recipient using the real sealed-box format. This removes the measured classifier
for its samples; it is not proof of padding indistinguishability. Any population
arithmetic model must represent the historical leak when claiming that baseline,
or explicitly freeze a corrected wallet policy. A model must never silently
treat historically distinguishable padding as cryptographically opaque. Terminal
Auth528 zero ciphertext is intentionally public and is outside this experiment.
The existing21103/100025>20% common-price amount-prior failure is unchanged.
