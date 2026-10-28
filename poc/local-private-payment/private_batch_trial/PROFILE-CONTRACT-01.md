# New-profile delivery, restoration and independent exit

Implementation contract following RFC-0030/ADR-0074. No legacy funded note,
backup, setup identity or financial profile is reinterpreted. The component
implementation must use a selected new profile domain and separate setup IDs.

## Reuse

Reuse the existing Note168 and encrypted Receipt216 encodings, SHA256/HMAC
commitment and nullifier constructions, positioned CM membership, integer sompi
ranges, mature sealed-box delivery and secp256k1 payout key derivation. Reuse the
stock Circomlib Babyjub EdDSA/Poseidon authorization implementation and actual
matrix join from the retained NativeAuth source. A new versioned KDF binds the
selected profile domain and derives separate signing, nullifier, native-payout
and delivery roles; only an owner worker may receive its original seed.

`Note.owner = SHA256(KPBPOW01 || D32 || AK64LE || incoming32)`.
AK is the canonical subgroup-checked Babyjub public key. The signing seed,
expanded scalar and nonce never enter the shared payment witness. The existing
NF construction remains stable for the same unspent note and position.

## Delivery and restoration

The sender receives a public invoice only. The receiver decrypts with its
profile-domain delivery key, rederives the invoice index from the original seed,
compares every owner/incoming/NK/native field, recomputes Note168/CM and checks
the selected actual Output proof and authenticated accepted position before
recognizing a claim. Received and change notes follow the same derivation and
scan path; no coordinator output partition or pending-intent journal is needed.
Deterministic wallet rejection of poisoned ciphertext remains distinct from
circuit-enforced encryption correctness.

## Independent AuthExit

The direct exit statement binds selected domain, accepted CM anchor, stable NF,
exact current-state/native-effects digest, integer payout and fee. Its native
component checks the actual note owner's AK commitment, NK commitment, occupied
positioned membership, NF, note range and exact `note_value = payout + fee`.
Its joined mature signature component verifies owner-local authorization of
the complete exit statement under the same hidden AK. The native policy must
reconstruct the effects digest from the actual destination, amount, reserve
outpoint, old/new state and authorized fee before accepting the new Exit VK.
No committee, service-history permission or MPC backend is an exit dependency.

Required negatives include wrong AK, wrong signature, redirected payout,
changed fee, stale root, high membership-position bits, already-spent NF,
cross-domain/profile statement, overflow and malformed/noncanonical signatures.
Every-path authorization and a fresh setup/VK are mandatory. A checked matrix
or a host signature verdict alone does not establish a native Exit proof.

## Actual trial finish line

The 3-owner/3-NF/6-output profile needs its actual aggregate relation, Output
delivery and direct AuthExit setup identities before any funding. A supplied
context rehearsal must complete original-seed received/change spending and
service-loss exits first. The later fresh testnet trial must confirm the exact
whole CASE and payout UTXO for every withdrawal, reach zero reserve, and repeat
original-seed terminal scans using the finite downloaded public package.
Frozen observer predictions precede owner-local truth access. Missing views,
missing recovery, a missing payout or a toy proof leaves the trial incomplete;
the old changed-cohort intersection failure remains retained.
