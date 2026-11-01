# ADR-0092: One-use hidden invoice keys for the bounded V3 experiment

**Status:** Accepted for design and implementation of the bounded passive
observer experiment only; runtime selection, setup qualification, and launch
remain `CONFIGURED0`.

**Date:** 2026-10-29

## Context

Receive V2 deliberately separates the private note receive field from one
domain-stable `DELIVERY/0` X25519 key. This preserves seed-only scanning, but
every party that receives two invoices can link them by the repeated delivery
public key. The current RustCrypto sealed-box construction has no reviewed
recipient-key-privacy theorem matching the complete P1+C1+public auxiliary
view. Plaintext confidentiality is not recipient anonymity.

The next experiment asks a narrower question: does mapping privacy materially
improve for the exact pinned passive P1 process plus passive owner C1 and the
public projection? ADR-0088 limits only that empirical population. It does not
weaken the active-malicious-server, arbitrary-host, retry, network, or
production threat model.

Three choices were reviewed:

1. one-use public keys carried only by authenticated private invoices, with a
   private recovery ledger;
2. a same-width DHAES-shaped X25519/KDF/ChaCha20-Poly1305 redesign; or
3. no selectable bounded path.

The same-width design is the preferred recovery architecture, but is not yet a
selectable cryptographic assumption. The primary anonymity theorem covers a
prime-order-group DHIES construction with `H(shared)` and separate symmetric
encryption/MAC keys, not the exact X25519, `H(shared || epk)`, single-key AEAD
profile. The one-use-key path instead removes known honest candidate keys from
this bounded view and has a finite hybrid argument, at the cost of requiring a
private ledger.

## Decision

Create a separately versioned receive V3 profile for this experiment. Every
logical output uses a unique hidden delivery key:

```text
delivery_secret_i = HMAC-SHA256(
  owner_seed,
  "KPBKDF01" || profile_id || domain || "DELIVERY" || u64le(invoice_index_i))
delivery_public_i = X25519-Public(delivery_secret_i)
```

This is the existing `derive(seed, profile, role, index)` construction with a
uniquely allocated invoice index instead of the same index zero for every
invoice. Index zero may occur once in a V3 profile. The V3 profile identifier
and invoice/receipt tags must differ from retained V2; the domain choice must be
frozen in the profile. Honest key provenance comes from the admitted owner
wallet process and pinned crypto bridge; arbitrary caller-supplied 32-byte
public keys do not qualify as honest outputs.

The authenticated private invoice carries `invoice_index_i` and
`delivery_public_i`. Neither value, nor a key hash, directory identifier, or
ledger position, may enter the public projection, P1 capture, launcher receipt,
general parent process, or model export. C1's genuinely issued or accepted
invoice remains its direct auxiliary knowledge and must constrain candidates.

### One-use and retry rules

1. The owner-local ledger allocates each 64-bit invoice index once per V3
   profile. Allocation, export, acceptance, output use, abandonment, and
   poisoning are authenticated state transitions.
2. One invoice may authorize one immutable logical output exactly once.
   Payment and change each consume their own invoice.
3. Allocation is permanent. An abandoned attempt, failed launch, retry, or
   partial send poisons the index and key; neither may be reissued or used to
   re-encrypt.
4. A fresh trial identity/profile and fresh indices are mandatory. Retrying
   means a new attempt and new invoices, never resuming old encryption state.
5. Retransmitting an already committed immutable ciphertext, where the selected
   transport explicitly permits it, is recorded as repeated metadata; creating
   a second ciphertext under the same delivery key is forbidden.
6. Duplicate index, public key, ciphertext, ambiguous state transition, or
   exhausted index allocation safely halts before output admission.

### Recovery contract

V3 recovery is `seed + authenticated private invoice ledger + authenticated
public history`. It is not seed-only recovery.

The ledger stores enough authenticated issuance state to reconstruct the
finite set of V3 indices and invoice descriptors; it need not store raw
delivery secrets because those are re-derived from the seed. Recovery derives
each admitted key, trials the finite key set against every complete 264-byte
ciphertext, and accepts only one result whose receipt:

- has the V3 receipt/domain/profile tag;
- reconstructs the exact ledger invoice descriptor and delivery public key;
- commits to the public `CM`; and
- appears in authenticated ordered public history.

Missing, truncated, reordered, duplicated, cross-owner, cross-profile,
cross-attempt, or unauthenticated ledger state is a hard recovery failure.
Zero matches is an ordinary not-owned result only when the complete admitted
ledger is present. Multiple matches or a valid decrypt with the wrong
descriptor/commitment safely halts. Public status must say `seed_only: false`
and `private_maps_imported: true`; losing the ledger cannot report successful
empty recovery.

### Exact privacy scope and assumptions

This decision permits one bounded hybrid only:

1. Under the exact domain-separated HMAC-SHA256 multi-output PRF assumption,
   replace honest V3 delivery secrets at unique indices with independent
   uniform secrets.
2. Under S5 confidentiality for the exact pinned honest `crypto_box` producer,
   replace equal-width honest receipt plaintexts with a fixed dummy. This step
   does not alter C1 decryptions, invoice contacts, sender knowledge, failures,
   or metadata.
3. After the actual sealed capture proves that honest keys, key hashes,
   indices, and directory identifiers are absent, swapping honest recipient
   labels is an exact renaming of hidden independent key/plaintext/ephemeral
   samples.
4. Restore real plaintexts and PRF-derived keys in reverse.

The hybrid additionally requires authenticated honest-output-producer
authority, valid generated X25519 keys, fresh sealed-box ephemeral randomness,
fixed widths, one-use retry state, and the genuine C1 v2 contact/value
constraints. Direct ciphertext bytes, positions, hashes, equality, timing,
length, abort, retry, and partial-tail effects remain candidate inputs. A
corrupt sender or C1 knows every invoice it actually receives; those edges are
not hidden.

This does not establish BBDP key privacy for current `crypto_box`, general
recipient anonymity, directory privacy, active-malicious-server privacy,
selective-failure resistance, arbitrary-host privacy, network privacy, or a
production claim. A passing bounded observer run cannot be generalized beyond
ADR-0088.

## Groth16 setup boundary

The Output and aggregate proof CRSs are a separate condition. For this bounded
Testnet observer only, a fresh one-party setup may be admitted under the
explicit candidate assumption `A-CRS-LOCAL-BOUNDED-V1`: the exact source-closed
setup process honestly follows Groth16 `Setup`, samples uncompromised fresh
randomness outside the P1+C1 view, exposes only the CRS, erases its random tape,
and never colludes with the observer.

That assumption is selectable only after reproducing the exact current Output
and aggregate matrices, producing the complete isolation/erasure and
source/build/output receipt, independently checking conversion/query order, and
binding the keys to the two predeclared hypothesis-symmetric runs. Process
attestation does not prove honest entropy or erasure. The current old setup,
and setup labels
`PRIVATE_OS_RNG_NOT_RETAINED` and
`FRESH_LOCAL_RESEARCH_SETUP_NOT_CEREMONY_OR_FINANCIAL_ACCEPTANCE` remain
ineligible.

The 2026-10-29 aggregate regeneration now closes source drift: the current
48-file source table produced all 13,093,029 rows and A/B/C artifacts
byte-for-byte identical to the retained setup matrices. This preserves the
mathematical PK/VK relation but does not improve setup trust, erasure, or
selection evidence.

This local trusted setup is never ceremony evidence. Production or any
trust-minimized claim still requires a verified Phase 1 and separate
circuit-specific Phase-2 MPC ceremonies, unchanged audited circuits, durable
transcripts, and the one-honest-contributor assumptions.

## Minimal implementation boundary

Retain V2 source and evidence unchanged. V3 requires these narrow changes:

| Surface | Required V3 change |
|---|---|
| `poc/future-recipient/v3/` | New profile/invoice/receipt version; delivery derivation at the allocated invoice index; V2 refusal |
| `private_batch_trial/wallet_profile.py` | V3 key/invoice/open APIs that require an admitted ledger entry; remove any V3 fallback to `DELIVERY/0` |
| owner wallet worker/backup | Private append-only authenticated issuance ledger, one-shot state machine, export/restore, safe-halt status |
| payment/lifecycle worker | Consume exact recipient and change invoices once; poison them on abandonment/retry; no caller-synthesized indices/keys |
| output producer | Accept only the authenticated V3 invoice and honest-producer capability; continue fixed Receipt216/ciphertext264 output |
| recovery history | Trial the finite ledger-derived key set; enforce unique descriptor/CM match and authenticated complete history |
| C1 v2 observer | Bind genuine issued/accepted invoice index/key/contact and decrypted value facts; apply them to the candidate lattice |
| P1/public observer | Negative-scan hidden honest key/index identifiers; model all ciphertext/metadata effects and actual candidate pruning |

V3 intentionally retains `Note168`, `Receipt216`, ciphertext width 264,
`SHA256(ciphertext)`, CM/NF formulas, state rows, and proof encodings. The Output
relation currently treats ciphertext as opaque bytes plus its digest. Before
claiming no circuit change, a source-to-matrix comparison must prove that V3
changes no statement, witness, constraint, ordering, or domain field. The
current aggregate source-to-matrix comparison is complete and byte-identical.
Any later actual relation change forces new circuit artifacts and setup.

## Required controls before selection

1. **Derivation:** distinct V3 invoices yield distinct delivery keys; fixed
   vectors match the exact HMAC preimage; V2/V3 and cross-profile keys differ;
   malformed or arbitrary public keys are refused as honest provenance.
2. **One use:** duplicate allocation/export/accept/use, same-key second
   encryption, replay, retry reuse, abandoned reuse, cross-round/trial use, and
   index collision all fail before admission.
3. **Ledger:** round-trip restore succeeds with seed+complete ledger+history;
   missing, truncated, reordered, duplicated, stale, cross-owner/profile, and
   partially committed ledgers safely halt; seed-only restore refuses.
4. **Decryption:** wrong key, tag, descriptor, domain/profile, index, CM,
   ciphertext width, and ambiguous multi-decrypt fail uniformly.
5. **Lifecycle:** payment and change consume distinct authenticated invoices;
   every failed attempt creates fresh poisoned state and the next attempt uses
   fresh indices/keys.
6. **Observer:** actual source-bound P1+C1+public capture finds no hidden honest
   key/index/hash; C1 facts and every ciphertext/metadata lane filter the frozen
   four-view candidate lattice; missing coverage remains unqualified.
7. **Setup/circuit:** current source reproduces the selected matrices, fresh
   bounded setup receipts satisfy the explicit assumption, conversions and
   proofs cross-verify, and no old setup/key is accepted.

Passing unit controls, decrypting receipts, verifying proofs, or obtaining an
ambiguous synthetic fixture is not selection. The genuine two-round run must
use the prospectively frozen observer, truth separation, stop rules, and zero
unmodeled required fields.

## Alternatives considered

### Same-width `KPB-DHAES-264`

Preferred as a recoverable architecture, deferred for this experiment. It can
keep the stable private delivery key and seed-only scanning while changing the
wire to `epk32 || ciphertext216 || tag16`. Zcash uses the same broad
`shared || epk` KDF and zero-nonce ChaCha20-Poly1305 shape. However, no inspected
source directly proves ANO-CCA/key privacy for the exact X25519 cofactor and
encoding rules, `epk`-indexed BLAKE2b ODH family, single-key AEAD composition,
and complete auxiliary view. Structural similarity cannot authorize S6.

### Exact Orchard recipient encryption

Primary-source follow-up selects this as the mature production-oriented design
candidate, not as evidence for V3 or a present S6 qualification. The candidate
reuses released `orchard` 0.16.0 and `zcash_note_encryption` 0.5.1 without a
custom encryption domain, places `Receipt216` in the fixed Orchard memo, uses
an `Invoice219` raw Orchard receiver, and preserves integer sompi/native-KAS
semantics. It requires diversified addresses, a 692-byte envelope, new
note/wire fields, outgoing-recovery decisions, new circuit closures, and a new
ADR before implementation. The Zcash specification requires BBDP key privacy,
but that requirement is not yet a theorem for KPB's complete auxiliary view.
It is not the smallest bounded experiment.

### Keep V2 stable delivery keys

Rejected for the bounded S6 question. Invoice holders can compare the repeated
public key directly; confidentiality does not remove that link.

### Stop with no bounded path

Rejected. The V3 one-use-key hybrid is finite and non-circular within the
explicit passive observer, provided the private ledger, genuine capture, C1
constraints, S5/PRF/honest-producer conditions, and metadata coverage all land.

## Consequences

Phase 1 now exists as the new `poc/future-recipient/v3/` public-synthetic
reference, a network-off native source-only authority layer in the same
directory, and the unselected
`private_batch_trial/wallet_profile_v3.py` adapter. The reference records
`ALLOCATED -> EXPORTED -> ACCEPTED -> CONSUMED` and terminal poisoning,
requires an accepted opaque object rather than caller invoice bytes, preserves
Invoice208/Receipt216/ciphertext264, and requires seed plus the authenticated
private ledger for recovery. The adapter hardcodes `CONFIGURED0` and reports
that OS private-route authority, atomic durable transitions, an external latest
ledger head, an authenticated accepted-public-history adapter,
shared-lifecycle selection, and production honest provenance are all absent.

Its Python object identity is not a security boundary. Authenticated snapshots
also cannot distinguish an older authentic export or close a crash window
between an in-memory transition and durable persistence. These are retained
phase-1 blockers, not inferred qualifications.

A subsequent network-off native checkpoint adds a parent-owned descriptor
boundary, an authenticated local event/head journal, and a distinct external
latest-head updater. It also extends the existing fresh-owner supervisor: only
after both typed Round 1 history gates and all six private owner lineages pass
does Round 2 expose one opaque V3 residual bound to the complete canonical
`RunBinding`. A complete nonforgeable controller minter consumes that residual
and the external updater once. The opened parent retains private binding,
history, and fresh instance identities; the only non-test material constructor
is the complete source-owned minter. Binding, history, instance, and an opaque
round/owner/slot/index pre-generation identity remain attached through owner
acceptance and exact output consumption. Controls cover moved-from/replay,
cross-parent material and output, wrong round/owner/output slot, altered
accepted head, one-sided rollback, inode/mode/HMAC/truncation, and every
local/external durability boundary. The native source accepts Invoice208 only;
it does not select or mention a ciphertext profile.

This checkpoint does not change the ADR's selection state. The accepted-
history types still have no production Testnet confirmation/history minter;
the external updater has no selected monotonic-storage minter; the source-owned
invoice/output authorities have no genuine production worker minter; and no
selected owner launcher or shared lifecycle consumes the controller. A
simultaneous rollback of both authentic local and external files remains
indistinguishable without that separately trusted monotonic/latest-head
authority. Production accepted-history, source-worker, selected lifecycle-
controller, owner-launcher, profile, and `CONFIGURED` flags remain false.

- V2 results and byte formats remain retained and reproducible. This ADR
  supersedes only ADR-0042's stable `DELIVERY/0` and seed-only recovery choices
  for the new V3 bounded experiment.
- V3 adds availability-sensitive private state. Ledger loss safely halts and
  can make funds unavailable; it must never weaken ownership, proof, nullifier,
  or exit checks.
- The selected bounded experiment can avoid assuming recipient-key privacy for
  current `crypto_box`; the finite ledger names its replacement
  `S6A-V3-HIDDEN-DELIVERY-PRF`. It still depends on S5, exact HMAC PRF security,
  honest producer provenance, native proof that one-use keys/indices are absent,
  fresh randomness, and complete direct leakage measurement.
- Exact released Orchard note encryption is now the preferred
  production-oriented reuse candidate. `KPB-DHAES-264` is retained only as a
  same-width research proposal and cannot enter an acceptance authority.
- Production Groth16 setup remains ceremony-based. The local setup exception is
  explicitly trusted, Testnet-only, passive-observer-only, and conditional.

## Documentation synchronization still required

After implementation ownership stabilizes, update `docs/ARCHITECTURE.md`,
`THREAT-MODEL.md`, the affected recovery contract/RFC, the finite assumption
ledger, and `docs/adr/README.md`. Those shared files are intentionally not
changed by this ADR draft. Synchronization must preserve the global active
threat model and label V3 recovery as seed plus private ledger.

## Reconsideration

Revisit this bounded decision if the exact Orchard profile is ready for a
separate ADR and reviewed auxiliary-view mapping. Reject V3 if the genuine
capture exposes honest key/index identifiers, retry freshness cannot be
authenticated, C1 facts are not applied to candidates, ledger loss can appear
as successful recovery, or the circuit/setup closure cannot be reproduced.

## Evidence

- [CRS and recipient-key-privacy remediation](../../research/crs-and-recipient-key-privacy-remediation-2026-10-29.md)
- [Recipient-key privacy and exact Orchard reuse](../../research/recipient-key-privacy-orchard-reuse-2026-10-29.md)
- [Combined P1+C1+public finite assumption ledger](../../research/combined-p1-c1-public-finite-assumption-ledger-2026-10-29.md)
- [ADR-0042: separate delivery and note receive fields](0042-separate-delivery-and-note-receive-fields.md)
- [ADR-0088: passive pinned-P1 observer scope](0088-passive-pinned-p1-empirical-observer-scope.md)
- [ADR-0089: authenticated C1 contact/value capture](0089-authenticated-c1-contact-value-capture.md)
- [Zcash Protocol Specification, revision `2bdf394`](https://zips.z.cash/protocol/protocol.pdf)
- [Abdalla--Bellare--Neven, *Robust Encryption*, Theorem 6.2](https://eprint.iacr.org/2008/440)
- [RFC 7748: X25519 and X448](https://www.rfc-editor.org/rfc/rfc7748.html)
