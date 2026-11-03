# Native shielded KAS: consensus specification draft 1

**Status:** proposed rules for review, not an accepted KIP or implemented Kaspa
feature. **Date:** 4 November 2026 (Australia/Sydney).
Authorization and scope: [ADR-0103](../../adr/0103-native-shielded-consensus-specification.md).
Origin and unchanged privacy boundary: [RFC-0004](../../rfc/0004-native-kas-private-payment-boundary.md).

## Documents and authority

| Document | Defines |
| --- | --- |
| [Transactions](transactions.md) | Canonical bytes, native input authentication, IDs, complete signature messages, validation and fees. |
| [State and headers](state-header.md) | Forest, global nullifiers, anchors, accepted events, exact commitments, DAG application/undo and header hash integration. |
| [Bootstrap](bootstrap.md) | Activation, full replay, authenticated state export/import, wallet recovery and retention. |
| [Key identity](key-identity.md) | Portable actual VK/parameter capsule, compatibility transcript scalar and profile identity. |
| [Accounting](accounting.md) | Exact native equations, induction, reward flow, resource accounting and proposed invariant wording. |
| [Conformance and review](CONFORMANCE.md) | Exact public vectors/checker, adversarial review and remaining implementation/activation gates. |

`MUST`, `REJECT` and `MAY` are requirements of **this draft**, not statements
about today's network. No production choice, activation DAA score, priced mass
schedule or independent security approval is inferred from the owner asking for
a specification. An activation manifest with any unassigned parameter is not
valid for activation. Native KAS stays the asset; notes are its consensus value
representation, not an issued token.

## Reused construction and source authority

Use exactly repaired Orchard V2 at
`616a669df8c9a59c33d47064d3ce04b25d026b2e`: `orchard_v2()`,
`FixedPostNu6_2`, note V2, default flags `0x03`, two complete Actions. Preserve
Halo2/Pasta, both RedPallas signature roles, standard encryption/decryption,
note/key/nullifier/tree derivations and role-specific canonical encodings.
The local [interoperability package](../../../poc/orchard-interop/README.md)
remains a frozen experimental comparator; its bytes/signatures are not v2
transactions. No hidden native-maximum range gadget is added.

Kaspa source is pinned at `b85380d16514e65136001530e7c717eef304e654`; docs at
`0ac77d043a802fc8196abfd5812ac2afbd97a2b9`; KIPs at
`d832dbd89347dcb16d3d83bf6755b081714cbcb2`. Official HEADs were rechecked;
Kaspa then advanced to `af6ff23a0b3e8271407da3203ce4017dd188d7ec` during
finalization. The [delta review](../../../research/native-shielded-upstream-delta-2026-11-04.md)
records the new optional covenant UTXO RPC and verifies 25 relevant protocol
files remain byte-identical. Baseline citations below remain exact source pins.
The [source-bound review](../../../research/native-kas-consensus-boundary-2026-11-03.md)
and [five-protocol reuse review](../../../research/native-kas-shielded-value-sources-2026-11-03.md)
retain the evidence for Toccata, vProgs, Orchard, MWEB, Monero, Aztec and RAILGUN.
Inline-ZK/vProgs cannot make an ordinary transparent native payout confidential.

## Shared byte and hash rules

- `U8/U16/U32/U64` and `I64` are exact little-endian integers; no wrapping,
  platform-sized integers, floating sompi or alternative variable integers.
- `V64(x) = U64(byte_length(x)) || x`; `List64` starts with `U64(count)`.
  A bounded parser validates counts/lengths and available bytes before allocation.
- `Hash32` is 32 bytes in the exact order emitted by the underlying hash,
  without RPC-display reversal. Cryptographic field/group encodings follow the
  selected Orchard/Pasta role. Canonical encodings consume all bytes.
- `H(tag,x)` is BLAKE2b with 32-byte output and **key** the ASCII bytes
  `KNS1/` followed by the exact case-sensitive tag, hashing `x`. No NUL, length
  prefix or BLAKE personalization is added to that key. Each tag below is a
  distinct domain. This follows Kaspa's existing keyed-hasher convention;
  it is deliberately different from the experimental interoperability digest.
- `SHA256(x)` is standard SHA-256. Capsule identity uses it directly.

## Fixed first-profile limits

| Item | Draft value |
| --- | --- |
| Transaction/header versions | Proposed 2 / 3; source header 2 already exists. |
| Bundle/profile-record/state schema | 1 / 1 / 1. |
| Actions and canonical proof length | 2 and 7,264 bytes. |
| Maximum native transaction bytes | 262,144. |
| Ordinary inputs/outputs | Each at most 16. |
| Script/payload byte vector | Each at most 4,096; first-profile standard key scripts are much shorter. |
| Per-tree note depth/capacity | 32 / `2^32` leaves; leaf count is U64, including exactly full. |
| Global position/event counters | U64 with checked arithmetic; 2 leaves/markers per event. Never wrap. |
| Native monetary maximum | `M = 2,900,000,000,000,000,000` sompi. |
| Old anchor retention | All completed accepted roots in the current branch's state; no time expiry. |

These bounded research rules are not measured production capacity or fees.
Only ordinary key-authorized funding/payouts, direct atomic boundary actions and
one immutable native pool are in profile 1. No coinbase notes, old reserve/note
imports, queues, privileged withdrawal, administrator mint or automatic profile
migration. General scripts/covenants and other profiles require a separate
reviewed extension. An owner may use an ordinary existing-format transaction to
move other script types into supported key-controlled KAS first.

## Activation manifest and domain

`ActivationManifest` bytes are, in order:

```text
ASCII("KNSACT01")[8] || U16(1) || genesis_hash[32] || U64(activation_daa)
|| U16(2) || U16(3) || profile_id[32] || mass_schedule[see accounting]
```

`activation_id = H("Activation", manifest_bytes)` and
`domain_id = H("Domain", genesis_hash || activation_id)`.
This domain is the immutable original pool identity and global spentness domain.
The node obtains the exact manifest through consensus configuration, never a
transaction witness or RPC server. A different genesis/activation/profile has
a different domain. Verifier-only maintenance accepting the same notes MUST
preserve this origin domain and spentness; changing the active key is not a new
entitlement. A changed profile is not implicitly enabled by this draft.

Activation is explicit network/governance work. This document configures no
network, assigns no real activation score and changes no existing rules.
