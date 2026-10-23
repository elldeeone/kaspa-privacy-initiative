# ADR-0051: Match dummy ciphertexts to the real sealed-box format

**Status:** Accepted client-generation correction before new action fixtures.
**Date:** 2026-10-23 UTC.

## Finding

The new continuing private-action assembler initially pads dummy output slots
with 264 uniformly random bytes. Real SalsaBox sealed ciphertexts start with a
32-byte X25519 ephemeral public key. Its canonical encoding has a cleared high
bit; random padding sets that bit half the time. Equal lengths alone therefore
do not make these slots indistinguishable. Preserve this implementation finding
and its source/control evidence. No prior funded instance is rewritten.

## Decision

For each continuing dummy output, use the existing pinned crypto_box SalsaBox
implementation to seal 216 fresh random plaintext bytes to a fresh throwaway
X25519 recipient public key. Discard that recipient secret. Use the resulting
264-byte sealed ciphertext and bind it through the existing Auth ciphertext
hash. Keep independent fresh rho in dummy commitments. Do not merely clear the
random prefix's top bit: that would not reproduce actual public-key encodings.

The declared terminal case still has zero cipher528 and no output CM appends;
terminal status is already public. Note/Auth/native byte layouts, the hash
relation and matrices do not change. Existing true positive-payment ciphertexts
are untouched. New actual dummy-bearing authorization fixtures are constructed
after this correction and before their source/input freeze. Key generation may
use the unchanged fixed relation; a changed ciphertext needs its actual new
authorization/proof, not a replacement key.

Independently inspect the pinned library format, freeze and execute a separate
byte-classifier control before any privacy claim. This removes this specific
format channel under honest client generation; it is not a key-privacy theorem,
proof of correct receiver encryption, population qualification or global privacy
guarantee. Counterparty records, arithmetic, old disclosures and prior failures
remain in the observation horizon.
