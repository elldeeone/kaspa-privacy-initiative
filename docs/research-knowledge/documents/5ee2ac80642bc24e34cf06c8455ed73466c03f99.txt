# Privacy argument: obligations, not a proof

2026-10-24. The prototype removes an explicit grouping certificate. Its local
native acceptance and finite observations do not establish a composed privacy
theorem. This note makes the remaining proof obligations explicit rather than
inferring security from a shuffle or passing tests.

## Target

Compare two assignments of the honest complete output tuples to their creators
that agree on information the coordinator and one participant legitimately
already know. That includes the colluder's created outputs, openings, incoming
notes and actual invoice issuance. Public input-owner labels, endpoints,
counts, timing, roots, fees and final pool remain visible. At least two eligible
owners are honest. The desired claim is that the allowed full transcript does
not distinguish those assignments beyond the declared knowledge and priors.

This is a target definition, not an achieved claim. Same-host launcher/root,
daemon and selected software are trusted in the implementation experiment.
They are not independent operators. Anonymous transport, adaptive corruption
and robust termination are outside the demonstrated boundary.

## Components that need to compose

| Component | Required argument and current limitation |
| --- | --- |
| Value commitments | Uniform secret blindings hide values in the selected prime-order group. Unknown discrete log between the fixed value/blinding generators provides binding; strict integer bounds prevent value wrap. Fresh input blindings must not link a spend to its previous output commitment. Generator sampling and canonical encodings were source-reviewed; that is not a cryptographic audit. |
| Note commitments | Fresh secret 32-byte rho and the note encoding must hide low-entropy values and recipient/authority fields under the adopted hash assumptions. Public invoice knowledge alone must not enable a note dictionary attack. Never reuse rho as an operational shortcut. |
| Component proofs | The same Output key and shape are used for every row. Spend statements bind the entire common effects digest without an output subset. The proof system's witness hiding must survive these shared public inputs, separate setups and the surrounding protocol. Correct relations and correctly generated parameters remain assumptions. |
| Ciphertexts | The actual CF encoding must hide the receiver/creator information needed by this observer, including when candidate invoice public keys are known. Ciphertext length is fixed. Confidentiality and sender anonymity alone are not a complete recipient-key-privacy proof. The Output relation binds a ciphertext hash without proving correct encryption. |
| MPC transcript and sorting | The selected malicious MPC implementation must hide honest contributions, bits, keys and preprocessing state while evaluating the fixed whole-row sort. Public collision/abort status must not open rows or private maps. Active behavior and selective abort must compose with later owner authorization. |
| Failure and retry | An invalid global pool must fail before an owner-specific delivery check becomes a useful oracle for an unrelated honest row. No blame/reconnect/retry path may disclose a creator map. Previously authorized effects may still settle after timeout. |

The underlying Groth16 paper describes a zero-knowledge proof system; that
property does not validate this implementation's relation, setup, randomness
or composition. [Groth, EUROCRYPT 2016](https://eprint.iacr.org/2016/260).

MASCOT addresses malicious arithmetic computation with dishonest majorities.
Applying its results requires the implementation and preprocessing to satisfy
its assumptions; a pinned executable and successful run are not a substitute
for that argument. [Keller, Orsini and Scholl, CCS 2016](https://eprint.iacr.org/2016/505).

Libsodium documents per-message ephemeral keys, recipient confidentiality and
sender anonymity for sealed boxes, with X25519 and XSalsa20-Poly1305. The page
does not supply the full recipient-key-privacy composition theorem required
here. Treat that stronger requirement as an open obligation, rather than
silently equating it with sender anonymity. [Official sealed-box documentation](https://doc.libsodium.org/public-key_cryptography/sealed_boxes).

## Why the old algebraic certificate is absent

Publishing a per-creator scalar beta permits a public equality test between an
input commitment and a candidate two-output subset. The new body exposes only global
Delta. Every point in the selected prime-order group is some multiple of R;
membership in that group cannot itself certify which pair belongs to an input.
An observer is not given the individual scalar needed for the old equality.

This explains the structural change. It does not prove that no different
predicate, proof correlation, ciphertext feature, amount prior or failure
channel recovers the grouping. A full argument must account for the joint
distribution of all commitments, global Delta, proofs and permitted private
colluder information, rather than analyzing each field independently.

Independent uniform secret sorting keys produce a uniform relative order
conditional on no collision. For six 128-bit keys, the union-bound collision
probability is at most 15/2^128. The implementation must actually provide those
keys and authenticated comparison bits, swap every tuple column together,
reject collisions before row opening and reveal no permutation certificate.
The selected stock-sort source and actual MPC controls support those finite
implementation facts; they do not establish the complete protocol theorem.

## Active-path questions to retain

The owner checks its own authentic MPC result and all public proofs/balance
before authorizing effects. A coordinator changing an honest CF also changes
its bound CF hash and Output statement. A complete active argument must show
that substitution, replay, malformed delivery and participant loss cannot
turn later owner behavior into an oracle for an unrelated honest grouping.
A malicious creator may tag or deliberately break its own outputs; that does
not automatically demonstrate a leak of an honest creator's unknown outputs.
State exactly which knowledge is new in any claimed counterexample.

The current supplied genesis and P0 continuation are unfunded. This argument
assumes valid financial state; it does not establish native backing, current
accepted history, an independent exit or availability of future recovery data
and proving keys. Those are separate obligations for a complete payment system.

## What the cohort can answer

The [frozen cohort](COHORT-CONTRACT-01.md) uses independently generated genuine
worlds and one sealed query per owner. Its exact tail compares one frozen
strategy with an explicitly idealized conditional-uniform independent-world
model. Feasibility enumeration does not prove equal candidate probabilities.
No excess success for that strategy would remain a bounded negative result;
it would not prove this target or qualify financial privacy. Existing stronger
requirements and retained failures remain unchanged.
