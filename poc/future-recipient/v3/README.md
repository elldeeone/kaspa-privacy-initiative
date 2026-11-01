# V3 one-use hidden invoice-key reference

This directory implements phase 1 of
[ADR-0092](../../../docs/adr/0092-v3-one-use-hidden-invoice-keys.md) as an
offline, public-synthetic reference. It does not modify or migrate V2, launch a
private-payment lifecycle, prove accepted KAS backing, or qualify privacy.

## Exact change

V2 derives every sealed-box delivery secret at index zero. V3 uses the exact
invoice index:

```text
delivery_secret_i = HMAC-SHA256(
  seed,
  "KPBKDF01" || profile_id32 || domain32 || "DELIVERY" || u64le(i))
```

The other owner fields use the same HMAC envelope with distinct eight-byte
roles. The retained bridge binary, SHA-256
`6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff`,
continues to supply RustCrypto `crypto_box` 0.9.1 sealed boxes and secp256k1
public keys. On every call, V3 opens it without following the final symlink,
checks the exact content, copies those checked bytes into a write/grow/shrink-
sealed anonymous file descriptor, and invokes that sealed copy. V3 introduces
no encryption primitive.

Fixed formats remain:

```text
Invoice208 = "KPX3IN01" || domain32 || index_u64le ||
             owner32 || incoming32 || key_commitment32 ||
             native_pk32 || delivery_pk32

Receipt216 = "KPX3RC01" || domain32 || index_u64le || Note168
ciphertext264 = retained crypto_box seal(Receipt216)
```

`Note168`, its commitment formula, receipt value range, and the public
ciphertext width are unchanged. No circuit-equivalence claim follows; that
requires a separate source-to-matrix comparison.

## One-use seam

The reference separates allocation, private export, sender acceptance, and
output use. `IssuanceWallet.allocate(index)` returns an allocation capability;
`export_private_invoice()` turns it into a one-shot private offer;
`take_invoice_bytes()` releases Invoice208 once; and
`accept_private_invoice()` exact-matches those bytes and returns the only
capability that `deliver()` accepts. The ledger records every transition:

```text
ALLOCATED -> EXPORTED -> ACCEPTED -> CONSUMED
     |          |          |             |
     +----------+----------+-----------> POISONED
```

An altered private invoice or wrong attempt poisons the offer. Encryption
failure after consumption began records `CONSUMED -> POISONED`. Index reuse,
duplicate export/accept/use, capability copying, another crypto adapter, a
second delivery, or use after abandonment fails. A fresh retry must allocate a
new index and therefore a new delivery key.

These capabilities are only a reference seam. Python underscores, a module
sentinel, and object identity are forgeable by code already executing in the
same interpreter; they do not establish honest production provenance. The
adapter remains `CONFIGURED0`. A selected lifecycle must replace this seam
with the authenticated private route, durable transition store, and OS/C++
capabilities required by ADR-0092.

## Native authority checkpoint

`v3_native_authority.{hpp,cpp}` now implements a network-off parent boundary
without selecting a ciphertext construction. It admits only fixed Invoice208,
the exact canonical `RunBinding`, and a one-shot `SOCK_SEQPACKET` owner
acknowledgement. Every allocation/export/accept/consume/poison edge is written
to the authenticated local journal, synchronized through its head chain and
directory, and then committed to a distinct authenticated external latest-head
file and directory. The open file descriptions, inode/mode/name checks, sealed
MAC-key descriptors, and exclusive locks remain parent-owned.

The hidden fresh-owner supervisor now emits one opaque V3 history residual only
after its existing Round 1 input and successor-history authorities, all six
private owner lineages, and the hidden plan's full canonical RunBinding
identity have passed the original issuance gates. The complete
`V3LifecycleControllerMinter` consumes that residual and the external updater
once; moved-from/replayed, cross-trial, or altered-head joins fail. It exposes
no receipt, head, path, body, hash, invoice, or reconstruction accessor.

The controller-consuming open now retains only private binding, accepted-
history, and fresh per-open instance identities. A complete source-owned
material minter is the sole non-test constructor for `InvoiceMaterialAuthority`.
It carries those identities plus one opaque pre-generation identity through
allocation, export, owner acceptance, and output consumption. The final join
requires the same live parent and exact source-owned output authority; wrong
round, owner, output slot, invoice, generation, parent, or replay refuses. A
source/output mismatch under the correct parent appends `POISONED`; a failure
inside a durability boundary poisons the in-memory core and makes recovery
refuse. A substituted parent burns the one-shot capability and leaves the
genuine lane nonterminal, so restart refuses rather than reconstructing
authority.

This is still source-only. The current accepted-history authorities have only
test minters; no selected Testnet confirmation/history producer supplies them.
Only test setup can open the external anchor. The source-owned join has no
production invoice or output source-worker minter, and no selected owner
launcher, profile, lifecycle-controller callsite, or authenticated private
route invokes it. Rolling back only the local store or only the external anchor
is detected, but rolling both authentic files to the same old snapshot is not:
production still needs a separately trusted monotonic/latest-head service and
its live OS capability. Recovery of a committed nonterminal state also refuses
because its one-shot continuation cannot be reconstructed from disk. All
selection and configuration flags therefore remain false.

## Private ledger and recovery

The private ledger is canonical JSON with:

- exact domain/profile/owner/attempt binding;
- an ordered SHA-256 event chain;
- fixed Invoice208 bytes for every event; and
- a final HMAC-SHA256 over the complete export under a seed-derived ledger key.

It contains invoice descriptors and public delivery keys, but no owner,
nullifier, native or delivery secret. Restore re-derives every invoice and
rejects altered, truncated, reordered, duplicated, noncanonical or cross-bound
artifacts. Restored state is recovery-only and cannot mint a capability.

Recovery requires:

```text
seed + complete authenticated private ledger + complete public deliveries
```

Seed-only recovery refuses. Each public ciphertext is tried against the finite
ledger-derived key set. Successful decryption must match the exact invoice
descriptor and public commitment. Multiple successful key trials, repeated
invoice use, noncanonical positions, wrong commitment, a missing `CONSUMED`
output, or malformed public rows halt. A poisoned invoice can still recover a
potential liability, but `phase1_route_completed` is false. Even true means
only that this in-process reference reached `CONSUMED`; it is never production
honest-producer authority and cannot by itself support the bounded privacy
hybrid.

The `Delivery` list is a caller-supplied reference input, not an authenticated
accepted-chain/history authority. The selected lifecycle must bind the same
checks to complete accepted public history before any recovered amount can be
treated as a spendable note or backed liability.

The export is authenticated and append-only within one artifact, but has no
external monotonic anchor or atomic durable writer. An older authentic export
cannot be distinguished from the latest one by seed plus export alone, and a
process crash between an in-memory transition and external persistence can
lose the newest state. Production recovery therefore still needs write-ahead
durability, durable replication, and a separately authenticated latest-head
binding. Python memory is not zeroized.

## Test

```sh
cd poc/future-recipient/v3
KPX_RECIPIENT_CRYPTO=/absolute/path/to/kpi-future-recipient-crypto \
  python3 -B -m unittest -v test_recipient_v3.py

cd ../../local-private-payment/private_batch_trial
KPX_RECIPIENT_CRYPTO=/absolute/path/to/kpi-future-recipient-crypto \
  python3 -B -m unittest -v test_wallet_profile_v3.py

cd ../../future-recipient/v3
python3 -B -m unittest -v test_v3_native_authority.py

cd ../../local-private-payment/mpc-prover/financial/controls
python3 -B -m unittest -v test_fresh_owner_process_adapter.py \
  test_fresh_owner_friend_seams.py

cd ../../../private_batch_trial
python3 -B -m unittest -v test_honest_owner_material_authority.py
```

The tests use only public synthetic `DO NOT FUND` inputs. They cover the exact
KDF vector, fixed widths, V2 confusion, every reference lifecycle edge,
one-use/retry/abandon behavior, crypto identity and substitution, ledger
authentication, seed-plus-ledger restore, corruption and cross-binding,
missing/malformed history, descriptor/CM substitution, duplicate use, and
ambiguous decryption. Passing them is implementation evidence, not a
cryptographic proof, crash-durability proof, or production/privacy
qualification.
