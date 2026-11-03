# ADR-0042: Separate delivery encryption from the note receive field

**Status:** Accepted for the prospective offline receive-V2 experiment.
**Date:** 2026-10-23 UTC. No existing note, proof key or result is migrated.

## Context

Source review of the first recipient implementation identified an avoidable
equality channel before integrated proof/native execution. Its domain-stable
sealed-box delivery public key also occupied the note's `incoming` field.
Publishing that field at public admission or revealing exit would link distinct
notes, even when their ownership/nullifier/native signing keys were fresh.
The first frozen recipient suite passed25 checks; those source/results remain
unchanged. The V1 privacy evaluation had not executed and its cancellation is
retained separately. This decision changes no old privacy score or threshold.

## Decision

For the new receive-V2 experiment, derive note `incoming_i` using the existing
HMAC derivation with the eight-byte role `INCOMING` at invoice index i. Keep
sealed-box delivery secret under `DELIVERY` at index zero. This uses the same
established keyed derivation and encryption implementations, not new primitives.

Use a208-byte invoice with magic `KPX2IN01`: preserve the previous descriptor
field ordering and append the separate32-byte delivery public key. Sender
encryption targets this delivery key. Receiver derives both roles from its
pre-payment backup and rejects substituted descriptor/delivery fields before
normal credit. Restoration decrypts with the stable delivery secret, reads the
encrypted invoice index, and reconstructs the expected note/descriptor fields.

Note168, plaintext216, ciphertext264, State112, Auth484, CM/NF formulas and
private/native relation layouts remain unchanged. Native public admission and
reveal expose Note168 only; they must not expose Invoice208 or the stable
delivery public key. Root, architecture and independent adversarial/privacy
reviewers accepted this narrow difference before V2 source/trace freeze.
The exact supplement is [the receive-V2 contract](../../research/next-session/private-integration/INVOICE-V2-CONTRACT.md).

## Consequences and limits

Fresh indices no longer share this particular public-note equality field.
Invoice holders/directory observers still see a stable delivery public key and
can link invoices. Reused indices/credentials, recipient knowledge, native
amounts/funding ancestry, selected-note emergency disclosure and orphaned
publication remain privacy inputs. No whole-system unlinkability or RFC-0012
qualification follows. Existing21.09772557% prior failure remains unchanged.

Preserve V1 code/test evidence and use a separately frozen V2 package/trace.
This does not require a new private circuit shape or reuse an old rejected
wallet/replay/DRAIN workflow. All identities are public synthetic DO_NOT_FUND.
