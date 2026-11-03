# Desired two-v6-bundle binding contract

**Status: source/design contract only; implementation and settlement remain
deferred.** This specifies a narrow proof-verification statement for the same
RISC Zero 3.0.3 route reviewed in
[source selection](OUTER-VERIFIER-SOURCE-SELECTION.md). It does not implement a
guest, select an image ID, qualify serialization or receipt interoperability,
change the existing pool, or demonstrate privacy. A complete native batch cannot
be specified as accepted by the unchanged v6 covenant; its settlement and exit
obligations remain separate blockers rather than weakened requirements.

## Ownership, time and source identity

| Item | Identity |
| --- | --- |
| Owner | Existing batching source reviewer, `/root/next_direction_sources` |
| Start | 2026-10-22 10:31:22 UTC / 21:31:22 AEDT |
| Deadline | 2026-10-22 11:01:22 UTC / 22:01:22 AEDT |
| Finish | 2026-10-22 10:38:43 UTC / 21:38:43 AEDT |
| Documentation HEAD at start | `6b4fc65d5e64a91a134e722ff88ebc429960abe9` |
| Scientific source commit | `ec6aa15d586bcc8a90f7232b433fd48d8c73d509` |

Only named committed public source and the known public rehearsal JSON were
read. There was no implementation, experimental import, build, setup, proof,
runtime execution, fixture generation, benchmark, GPU use, private evaluation
or new attack design. Parked attack-design and recovery jobs/wrappers were not
inspected, reconstructed or retried. This note does not authorize a rehearsal.

## Concrete existing instance

Use the **rehearsal** instance under
`poc/shared-pool/evidence/2026-10-20-two-input-tn10/`, never the trial instance or
an attacker-supplied VK/domain. At the source commit above:

- Domain `D` is the literal 32 bytes
  `d36fda2e668fa858ae852484e63ea6dabb259403901fd9c88a16e9c5b17e5baa`.
- `VK` is the exact **328 decoded bytes** of `verification-key.json.hex`.
  `K = SHA256(VK)` is
  `9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef`,
  matching the rehearsal descriptor's `vk_sha256`.
- The descriptor identifies `testnet-10`, genesis
  `f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370`.
  These identify the source instance; the verifier-only statement below does
  **not** authenticate that chain or its accepted state.

The known public receipt has 15 transaction bodies and thirteen `KPICR06\0`
payload prefixes. This is a version/identity observation, not a rerun or proof
verification. No pair of compatible operations has been selected or extracted
into a new fixture. The intended program must fix `D`, `VK` and this contract;
accepting a prover-chosen key or merely echoing its digest is forbidden.

| Public source | Git blob | File SHA-256 |
| --- | --- | --- |
| `rehearsal/descriptor.json` | `219aba5aae61aa09dcfba8cceb38181e8858b596` | `795eebdefb3eabea6446b3b1a9bd8c80e7f262fe32f7dfcf39efccbe7bbc07ac` |
| `verification-key.json` | `b2d4336e5b3083386df5de911d242ef3df42a3b3` | `4fd7dc563e4a1f843c99d5517485ba7664a7dcb69057784ca2fac066b20cddaf` |
| `rehearsal/chain-confirmed.json` | `1d3af74733bd743a393d8c81cea230b3aa8f3b1d` | `75ad01a25b1c534a59f5690c69556584a72e31cb6afeb914530104f00962b3b8` |

## Admissible inner statements

The desired gate accepts exactly **two mode-1, zero-payout SPEND bundles**:
private payment/change or self-merge are not distinguished. This is a restriction
on the proposed gate, not a change to the v6 inner relation or a claim to support
all its operations. ADMIT, DRAIN, partial native payout and bootstrap are rejected.

For each bundle `i`, retain the exact 377 authorization bytes `A_i`, exact
128 proof bytes `Q_i`, and its two ordered 185-byte ciphertexts `C_i,0`, `C_i,1`.
Decode using the existing [authorization layout][auth]. No normalized JSON,
floating amount, alternative byte encoding or truncated input is equivalent.
All current authorization bytes have an explicit disposition:

| Authorization bytes, half-open offsets | Desired check and visibility |
| --- | --- |
| `[0,8)` magic | Exactly `KPICU06\0`; fixed public contract constant. |
| `[8,40)` domain | Exactly `D`; fixed public instance constant. |
| `[40,44)` count; `[44,76)` anchor | Private authorizations, proof-bound. Require **equal count and equal anchor across the two bundles**. This excludes ordinary sequential proofs using the post-first-operation anchor; it does not prove that the common anchor was ever accepted. No per-bundle anchor/count handle is published. |
| `[76,140)` two nullifiers | Both nonzero; all four active nullifiers must be distinct. Bound bijectively to the complete public nullifier vector below. This does not prove absence from an existing spent set. |
| `[140,204)` two commitments | Each bundle's two commitments must be nonzero and distinct as required by the inner relation. Across bundles, repeated commitments are **permitted**, with multiplicity retained. Bound together with their corresponding ciphertexts. |
| `[204,205)` mode | Exactly one; fixed public profile. |
| `[205,213)` payout | Exactly zero. |
| `[213,221)` fee | Positive bounded integer sompi under the unchanged relation, also checked as `1 <= fee_i <= MAX_SOMPI`. Individual fees remain private; their exact checked sum is public. Do not replace this with an assumed 40,000,000 wallet fee. |
| `[221,257)` native destination SPK | Exactly 36 zero bytes because payout is zero. |
| `[257,265)` deposit; `[265,301)` funding; `[301,337)` funding SPK | Exactly 8, 36 and 36 zero bytes respectively. No admission/native funding effect is supported. |
| `[337,345)` bootstrap | Exactly eight zero bytes. |
| `[345,377)` ciphertext digest | Private, proof-bound, and separately required to equal `SHA256(C_i,0 || C_i,1)` in **original slot order**. Never publish this per-bundle hash as a grouping handle. |

`MAX_SOMPI = 2,900,000,000,000,000,000` is the current
[source constant][hash-and-bound]. The source circuit binds all authorization
bytes by its [two digest limbs][circuit-binding]. The guest must recompute
`h_i = SHA256(A_i)` and verify `Q_i` against the fixed `VK` with exactly:

```text
x_i,0 = unsigned little-endian integer h_i[0:16]
x_i,1 = unsigned little-endian integer h_i[16:32]
```

These are two 128-bit values, embedded exactly in BN254 Fr; no endian swap,
whole-digest reduction, alternate journal-to-field encoding or host verdict is
allowed. The generic helper's Arkworks 0.5.0 proof/VK serialization versus v6's
0.6.0 remains **unqualified**. A future implementation must establish checked,
canonical compatibility rather than assume that both use BN254/128-byte proofs.
The fixed VK must undergo checked curve/subgroup decoding, complete byte
consumption and byte-identical canonical re-encoding, with exactly three IC
points for the two inputs and the existing verifier's required nonidentity
conditions. Submitted proofs require the same checked/canonical treatment and
explicit rejection of identity A, B or C, as in the existing helper. An unchecked
constructor is usable only after its exact fixed-key validation precondition is
independently satisfied; image-pinning alone does not establish that validation.
These are desired acceptance conditions, not results of a decoder run here.
No spending key, note opening, private membership path or changed inner setup is
an input to this desired outer statement.

## Complete public view and hidden bijections

The public view contains four nullifiers and **four complete
`(commitment, ciphertext)` records**, not four independent commitment and
ciphertext sets. Let `N[0..4]` be the nullifiers, strictly increasing under
unsigned lexicographic comparison of their 32 raw bytes. Let `O[0..4]` contain
`CM[32] || ciphertext[185]`, nondecreasing by unsigned lexicographic comparison
of all 217 bytes. Sorting is a proposed public-view convention, not an existing
native append order or a demonstrated wallet discovery rule.

The private witness includes two permutations `p` and `q`, each a bijection of
indices `{0,1,2,3}`. For `k = 2*i+s`, where `i,s` are zero or one, require:

```text
N[p[k]] = A_i.nullifier[s]
O[q[k]].CM = A_i.commitment[s]
O[q[k]].ciphertext = C_i,s
```

Every public index is used **exactly once**. Equal commitment or even equal
complete-record bytes at different indices do not permit index reuse,
deduplication or omission. Independently sorting commitments/ciphertexts is
forbidden. The original ciphertext-pair hash check above remains mandatory
after public permutation; hashing sorted ciphertexts is not equivalent.

This establishes an existential partition into two independently verified,
complete authorizations. A collector cannot re-pair a ciphertext, replace a CM,
reuse a public index, or assert a new authorization partition without satisfying
both original inner-proof bindings and both bijections. It does **not** certify
fair inclusion, a unique historical partition, named submitting wallets, or an
original submission order. Another pair of independently valid authorizations
yielding identical declared public data is another possible witness, not an
authenticated claim about which wallets submitted first. If those additional
properties are required, this contract is insufficient and must remain deferred.

## Canonical aggregate bytes and desired journal

All encodings below are newly specified **desired byte contracts**, not existing
RISC Zero/native formats. `u16le` and `u128le` mean fixed-width unsigned
little-endian integers. Hashes/keys are raw bytes in their stored order, not hex
strings, integer reductions or arrays of host-endian words.

Compute `F = fee_0 + fee_1` with checked u128 integer arithmetic; require
`2 <= F <= 2*MAX_SOMPI`. This aggregate is sompi, never KAS floats. Native fee
adequacy and reserve ability to pay it remain outside this verifier-only gate.

```text
P = ASCII("KPI2V6P1")                 # exactly 8 bytes
    || u16le(1)                      # this narrow profile
    || u16le(2)                      # exactly two inner bundles
    || D[32] || K[32]
    || u128le(F)
    || N[0] || N[1] || N[2] || N[3]
    || O[0] || O[1] || O[2] || O[3]  # complete 217-byte records
H = SHA256(P)
J = ASCII("KPI2V6J1") || u16le(1) || H[32]
```

`P` is exactly **1,088 bytes**; `J` is exactly **42 bytes**. The intended zkVM
journal is exactly `J`, with no appended status, per-operation digest, proof,
index, anchor, individual fee or other field. The declared public contract also
includes all `P` bytes. A publisher must make those complete bytes available;
an independent consumer must hash them and match `H` in the verified journal.
A receipt for a digest without available matching `P` does not meet this
publication contract. No digest of private authorizations/proofs is substituted
for `H`; such hashes can themselves provide grouping/equality handles.

For a desired unambiguous guest-input encoding, take exactly
`P || B_0 || B_1 || p[4] || q[4]`, where
`B_i = A_i[377] || Q_i[128] || C_i,0[185] || C_i,1[185]`.
Each permutation entry is one byte in `0..3`, used once. The input is exactly
**2,846 bytes**, and trailing bytes or alternative encodings are rejected.
This specifies semantics only; no guest/parser was written or image derived.
The full input is visible to the outer prover/collector, even though only `P`
and `J` belong to the declared public surface.

The only field-scalar conversion specified here is the existing v6 pair of
128-bit digest limbs. The completed
[native source inventory](../native/OUTER-RECEIPT-SOURCE-CONSTRAINTS.md) records
that the native boundary uses a digest of the actual zkVM journal bytes: for
this desired `J`, that would be `SHA256(J)`, **not** the inner `H = SHA256(P)`.
The inventory's SHA-256 is
`7d3cfb438f398edf5fed9018f13808098f24692f3065631ee8fa2674b3fb4e6c`.
It establishes no v6 execution/interoperability result. Native wire, claim,
image/control selection and settlement integration are not inferred from these
new byte contracts and remain separately unqualified.

## What this statement deliberately does not establish

| Obligation | Remaining boundary |
| --- | --- |
| Inner proof validity | Desired fixed-VK verification and exact input binding; still not implemented or qualified across Arkworks versions. |
| Historical anchor acceptance | Equal private anchor/count is not membership in accepted history. The guest has no authenticated historical-state input or accepted-root witness. |
| Current single spending | Four distinct active NFs prevent intra-pair collisions only. No existing spent-set root/nonmembership or state transition is verified. |
| Native backing and reserve movement | No actual reserve input, native transaction outputs, fee subtraction, predecessor/successor covenant or chain acceptance is bound. An external caller cannot promote `F` or `H` into settlement authority. |
| Public append order and recovery | Sorted public records do not implement a new commitment/history tree, position-aware scanner, authenticated public-data availability or recovery. |
| Recipient delivery | Exact CM/ciphertext pairing and ordered ciphertext digest do not prove correct encryption, recipient spendability or decryption. The existing [settle binding][settle] checks the ciphertext digest separately; the inner proof does not establish encryption correctness. |
| Independent exits | No new batch pool/covenant or exit relation is supplied. Existing holders' exits remain unchanged; no collector/operator permission becomes an exit condition. |
| Privacy | Absence of explicit grouping in this proposed journal does not prevent inference, candidate enumeration, participant subtraction or collector disclosure. The collector knows the complete grouping. Previously published development bundles retain their public history; a new projection cannot erase it. No benefit is measured or claimed. |

**Stop boundary:** do not turn this verifier-only contract into a complete
settlement contract by assuming accepted anchors, current spentness, native
backing, correct delivery or independent exits. Those checks require a separately
specified and reviewed composition; the unchanged pool does not accept this
new four-record layout. No heavy experiment follows from this document.

## Cross-review gates and source pins

Minimum independent review before treating even the desired binding as complete:

1. Check every authorization offset, forced-zero/profile rule, exact SHA256
   limb encoding, fee bound and both permutation/multiplicity conditions against
   the pinned sources. Confirm no hidden per-bundle identifier leaks into the
   declared journal/public envelope.
2. Independently check the formal implication: every accepted `P` is exactly the
   multiset of four NFs and four correctly paired records from two valid,
   same-anchor, profile-conforming proofs. Check that this implication is not
   mistaken for anchor acceptance, current spentness or complete settlement.
3. Resolve checked serialization compatibility and independently expected guest
   image/journal binding. The completed native receipt source inventory above
   owns native wire/tag/claim/image/setup constraints; it does not qualify an
   actual v6 guest/receipt. Any incompatibility keeps execution deferred; no new
   backend/version or receipt mapping is silently substituted.

Source-selection pins remain authoritative for
`poc/accelerated-bn254/common/src/lib.rs` (SHA-256
`ff8ef9d2ea1ef93440cadcfaac086ebafad33b2ae505ba3880b596b34660041e`),
its manifests/lock and the v6 dependencies. Additional directly used primary
files at the scientific commit above are:

| Source path | SHA-256 |
| --- | --- |
| `poc/shared-pool/src/two_input/mod.rs` | `255f8e908fcb1c4a76dcc8ebe0ca5f4e9ddbadc8ba46f63036cb413298bc8150` |
| `poc/shared-pool/src/two_input/circuit.rs` | `59071901c3abc25daab68c982ef065f8755c09abbb2ce30e6010d821813dd2a7` |
| `poc/shared-pool/src/protocol.rs` | `5243cab1b36e0d9cae8bf13e81b7fcdb033c8dc1bc7405daa401c69334cc4ec4` |

## Completion and review

The independent diagnostic reviewer checked the actual draft against source and
found no material semantic, binding or encoding correction; the 1,088/42/2,846
byte calculations were independently checked. Root separately reviewed the
native cross-boundary interpretation. Those are source/design reviews, not an
implemented guest, checked 0.5/0.6 interoperability, verified receipt, native
settlement result or privacy assurance. Execution remains deferred.

[auth]: /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/two_input/mod.rs:24
[circuit-binding]: /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/two_input/circuit.rs:275
[hash-and-bound]: /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/protocol.rs:25
[settle]: /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/two_input/mod.rs:158
