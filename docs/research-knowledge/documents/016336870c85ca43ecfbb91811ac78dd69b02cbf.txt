# Anonymous complete-output construction experiment

Proposed ADR0063 backend. This is a local research prototype with fresh
synthetic owner material, no KAS interface, old wallet backup or financial
proving key. Execution waits for the common session and circuit contract to
be frozen. Passing this experiment will not prove cryptographic correctness,
network anonymity, abort unlinkability or production security.

## Existing engine

Use the already selected official MP-SPDZ v0.4.4 distribution, commit
`113c4e47dd94bca9ecab029d2f0abe649bea5c52`, archive SHA256
`73d6473526101b4433999fc4f7521fdfdc53ddf018e5f64480518d6293f62760`.
The unmodified Linux-adx `mascot-party.x` SHA256 is
`47d9ae6f52003825946a4abb6cf9dc62f62a4e2fc2c19a5e3ee6f59a6889b07e`.
Select live, malicious MASCOT; never fake preprocessing, unchecked opening,
an INSECURE build, semi-honest mode or a public permutation.

The arithmetic field is exactly the BabyJubjub subgroup order:

```text
2736030358979909402780800718157159386076813972158567259200215660948447373041
```

Compile with `-P <this prime> -F 249`. The integer workspace is separate from
raw canonical field inputs. This is a different field from ADR0062's Jubjub
experiment, which remains unchanged. The actual compiled schedule and each
party's runtime prime must agree.

## Complete row and input contract

Three owners each contribute exactly two complete confidential output rows
and one scalar beta contribution. Provisional fixed row serialization,
pending the circuit author's final agreement:

```text
CM[32] || CV.x[32LE] || CV.y[32LE] || CF[264] || CFH[32] || OutputG16[128]
```

This is 520 bytes. Pack each row losslessly into seventeen 31-byte little
endian limbs with seven final zero bytes. Every limb is below 2^248, below
the MPC prime; reject wider limbs, nonzero padding or wrong row length on
decoding. Never reduce a serialized row modulo the MPC field. Point base
coordinates are canonical in BN254 Fr; point/proof/CF semantics belong to
the selected circuit verifier, not an invented MPC curve implementation.

Each owner's private input stream contains `row0[17], row1[17], beta_i` in
that order. Beta_i is canonical in the MPC scalar field. An owner worker
writes this stream in its own opaque directory; the public controller must
never open, hash, copy, parse or log it. An engine wrapper inside that
owner's isolated container opens its own stream and connects it to its own
engine stdin. No input content traverses the controller. No input tuple,
input proof hash, tuple commitment, per-owner beta or owner-to-row link is
published before mixing.

The engine program creates a `6 x 17` secret `sint` matrix, inputs the six
whole rows and three betas, invokes stock `secure_shuffle()` once on the
matrix, and uses checked reveals for the resulting entire matrix and the
field sum of the three betas. All three parties must exit successfully and
produce the exact same final output before a result is COMPLETE. A failed
party/session is INCOMPLETE, never a reduced-membership result.

Only the six mixed rows, their mixed indices, aggregate delta, public
session identifier and public program identity cross the coordinator
boundary. The coordinator receives no permutation, original indices,
uploader-to-tuple/proof correspondence or secret opening. It does learn
participating endpoints, fixed contribution counts, scheduling and the
complete final public tuples. Each owner knows its own outputs. Those
inherent observations must remain in the frozen observer model.

## Joint session and final authorization

The public session specification selects a fresh session ID, circuit
profile/digests, prior accepted state, public fee/effect parameters, exact
row schema, engine/compiled program and all three participants. Every owner
independently checks the same specification before providing any input.
The session ID is compiled into the program and included in every final
party report; output proofs bind the agreed pre-mix domain. The aggregate
and rows are one program's outputs, not separately reusable sum and mix
artifacts. The final accepted verifier recomputes all output-proof statements
and value-balance checks, then requires each spending owner's genuine
post-mix proof/authorization over the entire final effects digest.

MASCOT transport authentication is not a KAS financial authorization.
Malformed rows, dishonest beta, changed output, replayed context, stale
state, missing proof or missing final authorization must prevent native
acceptance. The backend itself cannot certify financial validity. Dropout
or dependency loss aborts construction; original independent recovery
remains separate, without an administrative rescue path.

## Source-grounded shuffle semantics

These are the pinned engine's existing APIs, not a new shuffle design:

- `Compiler/types.py:7750` shuffles complete matrix rows using
  `self.get_vector().secure_shuffle(self.part_size())`; `sint.secure_shuffle`
  at line2526 emits `secshuffle` with a complete-row unit size.
- `Protocols/SecureShuffle.hpp:119` composes secret-shared participant
  permutations through Waksman rounds. `generate` at line366 obtains each
  relevant participant's private random permutation. One honest permutation
  is sufficient for the implementation's stated hidden-composition premise.
- `Protocols/Replicated.hpp:211` selects `threshold(n)+1` contributors;
  malicious SPDZ's dishonest-majority threshold is `n-1`, selecting all3.
- `SecureShuffle.hpp:379` authenticates secret switch bits, checks their
  Boolean constraint in the malicious path and calls the protocol checker.
- `SecureShuffle.hpp:244` handles six rows by internal padding to eight with
  authenticated real-row flags; line296 reveals only the final real/dummy
  flags, filters dummy rows and checks the resulting count is six. It does
  not reveal an original owner or original row index.

Primary source: [pinned SecureShuffle.hpp](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/SecureShuffle.hpp).
The implementation references Keller--Scholl 2014, section4.3; the compiler
also documents this existing reference. Source inspection does not replace
an independent audit of that implementation or its binary provenance.

## Isolation and resources

Reuse only the already installed image
`sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea`.
No image pull, global installation, privilege addition, host networking or
security-policy change. One owned `network=none` anchor supplies shared
loopback; each of three separate read-only containers runs as the current
UID/GID, drops all capabilities and enables no-new-privileges. Each gets
only its own private input/key directory, public peer TLS certificates,
authenticated public program/engine and writable own scratch. No other
owner root, host home, global output directory or daemon socket is mounted.
Host `/usr` is read-only, as in the preceding calibrated harness.

Initial ceiling: three parties each0.9CPU/1GiB, anchor0.1CPU/32MiB,
controller1CPU/512MiB, total3.8CPU/3616MiB; no swap or GPU. Compilation is a
separate bounded public phase. Every owned container must be identity
checked, removed and verified absent after success or failure. Resource
limits and scheduling waits classify an incomplete attempt; they never
relax a financial check or produce a partial accepted session.

Docker daemon and host root remain trusted isolation administrators. A
public coordinator process observes only public descriptors and final
outputs; a malicious host administrator could inspect local test mounts.
Three isolated workers on one machine are useful process isolation evidence,
not independent operators or protection from that administrator.

## Frozen experiment gates

Before an actual privacy experiment, freeze the observer, hidden ownership
truth, classification rule and success/failure thresholds with the attack
lane. Required implementation controls include complete-row preservation,
exact prime and padding, same-session output equality, wrong session/prime,
changed complete row, changed aggregate, omission/duplication, and actual
party loss without reduced membership. Genuine owner output proofs and
native acceptance are separate required integration gates; opaque random
bytes or a passing sum alone cannot stand in for them.
