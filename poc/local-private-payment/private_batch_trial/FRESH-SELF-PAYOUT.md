# Fresh self payout wallet policy

ADR0080 removes a direct lookup: an invoice holder knows `Invoice208.native_pk`,
while the old wallet required that same key as the eventual native payout.
New preparation derives a separate self-controlled key inside the owner role;
authorization independently rederives its script and rejects both the invoice
key and arbitrary caller-selected destinations. The existing exact AK-bound
signature, value, fee, NF, membership, head and native policy checks remain.

The AuthExit circuit already signs the complete destination through the effects
digest. D, ProfileID, Note168, Invoice208, CM/NF, signature matrix, public ABI,
AuthExit PK/VK and native verifier are unchanged. `Note.native_pk` retains its
existing commitment meaning. No new cryptographic primitive is introduced.

The owner-only key encoding is exact:

```text
root = HMAC-SHA256(Original32,
  "KPBKDF01" || ProfileID32 || D32 || "EXITPAY1" || u64le(0) || u32le(0))
identity = Context276 || NF32 || public_Exit_action32
candidate_r = HMAC-SHA256(root,
  "KPB_FRESH_SELF_PAYOUT_V1\0" || identity || u32le(r))
```

Use the first r starting at0 whose32-byte big-endian integer is strictly between
zero and the secp256k1 order. No modular reduction occurs. The existing selected
native secp implementation derives the X-only public key and the standard36-byte
P2PK script. The action is the existing nonzero32-byte field in Body1604, not a
new hidden nonce or ABI field. Context276 includes the exact old head and all
profile/state/reserve identities. No mutable reservation, sender state or private
payout journal is required.

`fresh_self_payout.derive(receiver, head, nf, action)` returns a private
`OwnedPayout`. Its repr and default JSON cannot expose the key. Never serialize
it into a public status. The production worker creates the action and script
locally; the controller receives no destination-approval Boolean or private key.

`recover_public(receiver, actual_projection, tail)` rederives a matching fresh
native key from the Original and public Exit alone. It needs no invoice, note
opening, sender data or cached note index. Full chain/proof admission remains
external. `recover_history` additionally reconciles a recovered private claim's
NF/value and returns `fresh-self`, `legacy-invoice-key`, or `other-destination`.
The latter can be a valid owner-authorized historical withdrawal; absence of a
self-owned key does not invalidate the history or unspend its NF. Creating a new
withdrawal never falls back to the old invoice key.

Old source is preserved before changes under
`.local/fresh-self-payout-baseline-20261028-01/`, including its exact source
manifest. Old genuine component evidence and the frozen cyclic workload/H1
failure are not relabelled. Complete clear Invoice208 catalogs remain blocked;
the stable delivery key links descriptors and remaining fields need a separate
recipient-oblivious transport design.

Eleven focused public known-seed tests use the real selected secp and EdDSA
implementations. They cover strict scalar rejection, exact fresh authorization,
signature tampering, wrong owner/profile, nonce/head/NF separation, Original-only
public-projection key restoration, old/external historical compatibility and
non-exportable private key objects. Five Exit and eleven wallet/history controls
also pass. The separate public-synthetic control has now produced two genuine
existing-key AuthExit proofs, independent Ark verification and Native Full/all
input-engine positives. Six coherent destination/fee/head native mutations and
two stale-signature cases refused. D/ProfileID, PK/VK and native ABI stayed
unchanged. This is actual component evidence, not funding or accepted-chain
qualification. The frozen private-Original paired measurement remains separate.

Fresh keys remove one exact invoice-address join. They do not hide public
amounts, fees, time, clear owner-labelled release routing, social knowledge or
the old deterministic cyclic workload. The full dispatcher/server/terminal
union cannot be called private from this repair alone.
