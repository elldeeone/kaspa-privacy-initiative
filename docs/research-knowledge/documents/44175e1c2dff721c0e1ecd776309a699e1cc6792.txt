# Future private/native note and state contract

**Selected supplement:** [Invoice V2](INVOICE-V2-CONTRACT.md) prospectively
separates per-invoice note incoming from stable deliveryPK. The V1 text/freeze
below is retained; Note168/Auth484/private/native bytes remain unchanged.

**Status: core sections 1–5 ACKed by root and independent adversary; experimental
implementation contract, not a production design.** Source/key/proof freeze
and runtime release remain separate gates. Scope is recorded in
[RFC-0020](../../../docs/rfc/0020-private-proof-and-native-exit-integration.md)
and [ADR-0041](../../../docs/adr/0041-new-format-private-native-integration.md).
Baseline
`0c2f4c788a4274b381c4838e05cce5e9c32e8536`. Existing notes, source snapshots and
native-probe results remain unchanged. This document owns no implementation.

The smallest common implementation is a genuine private **two-input/two-output
SPEND** plus a native revealing whole-note exit under one new immutable policy.
Admission is a separate extension below. No old S7 owner/replay/DRAIN/restored-PK
workflow is resumed. Tests use deliberately public development credentials and
supplied contexts; accepted chain/backing/privacy are separate qualifications.

## 1. Hashes, notes and domain

SHA means SHA256; HMAC means standard HMAC-SHA256. Preserve these exact bytes
from the [public probe](../../../poc/future-exit-feasibility/src/main.rs):

| Name | Exact Rust byte literal |
| --- | --- |
| OWNER_TAG | `b"KPX1OWN\0"` |
| KEY_TAG | `b"KPX1KEY\0"` |
| NOTE_TAG | `b"KPX1NOT\0"` |
| NF_TAG | `b"KPX1NF\0\0"` |
| NF leaf / NF parent | `b"KPX1NFL\0"` / `b"KPX1NFN\0"` |
| CM parent / empty leaf | `b"KPX1CMN\0"` / `b"KPX1CME\0"` |
| NF empty leaf | `b"KPX1NFE\0"` |

Each tag is eight bytes. Root selected the fresh public D[32]:

```text
preimage = exact ASCII KPI/future-private-native-integration/DO-NOT-FUND/v1/2026-10-23
D = SHA256(preimage) = 9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c
```

There is no NUL or newline in that preimage. Its SHA256 was independently
recounted before publication. The immutable policy fixes D and the new private
VK. D differs from old instances and does not depend on policy/VK bytes.
Any new setup is separate, development-only and untrusted. No old note gains a
new spending branch. All sample seeds/keys are deliberately public synthetic
DO_NOT_FUND credentials.

```text
O  = SHA(OWNER_TAG || D || s[32] || incoming[32])
K  = SHA(KEY_TAG || D || k[32])
note168 = O[32] || incoming[32] || u64LE(V) || rho[32] || K[32] || PK[32]
CM = SHA(NOTE_TAG || D || note168)
NF = HMAC(k, NF_TAG || D || CM || u32LE(position))
```

PK is the canonical x-only secp256k1 native payout public key. Native payout
uses its canonical P2PK script. This is the exact public-probe relation, with
new instance/state/authorization framing, not Orchard cryptography.

Amounts are unsigned integer sompi: `NOTE_FLOOR=60_000_000`,
`PAYOUT_FLOOR=10_000_000`, `MAX=2_870_000_000_000_000_000` as in the public
probe. This profile MAX is explicit; old v6's different MAX is not imported.
Fee is `1..=MAX`. All sums use bounded integer/slack relations, never modular
field equality without a bound.

## 2. Receiver-issued invoice and backup derivation

Select an **interactive one-time invoice** for this experiment. A receiver's
pre-payment backup contains root seed q[32] and authenticated profile/D pins;
it does not contain a later note, invoice log or precomputed exit. The sender
gets public descriptor fields only, never s, k or native signing secret.

```text
derive(role,index) = HMAC(q, b"KPX1DRV\0" || role[8] || D || u64LE(index))
s_i = derive(b"OWNSEC\0\0", i)
k_i = derive(b"KSECRET\0", i)
delivery_secret = derive(b"DELIVERY", 0)
incoming = crypto_box::SecretKey(delivery_secret).public_key()
native_candidate(i,j) = HMAC(q,
    b"KPX1DRV\0" || b"NATIVE\0\0" || D || u64LE(i) || u32LE(j))
```

Native j starts at zero **including its suffix on the first attempt**. Select
the first candidate accepted by the existing secp256k1 SecretKey parser; never
reduce modulo the curve order. Derive PK with the library. No hand-written
curve arithmetic. Exhausted counters fail explicitly. Invoice indices are
unsigned u64 and never wrap. The four roles separate derived authority; the
HMAC PRF/key-separation assumption is explicit.

| Object | Exact layout / bytes |
| --- | --- |
| Invoice176 | `b"KPX1IN01" || D32 || u64LE(i) || O32 || incoming32 || K32 || PK32` |
| Receipt plaintext216 | `b"KPX1RC01" || D32 || u64LE(i) || note168` |
| Ciphertext264 | Existing `crypto_box` 0.9.1 SalsaBox sealed box over plaintext216; 48-byte overhead. |

The sender chooses fresh rho and V and can construct CM from the public invoice.
Its output proof **must not require knowledge of receiver s or k**. Stable
delivery key/index zero permits decrypting the receipt before learning i; a
per-invoice delivery key would otherwise require public index metadata or a
bounded discovery/lookahead assumption. This choice deliberately exposes equal
incoming keys to invoice holders and later revealing observers. Fresh O/K/PK
does not remove that linkage. No financial-privacy target is qualified by it.

Receiver acceptance, separate from sender proof validity:

1. Authenticate profile/current public data and the ciphertext-to-CM position
   binding. Decrypt locally with the domain-stable delivery key; require exact
   length/magic/D. Parse all amounts/fields canonically.
2. Derive s_i/k_i/PK_i from backup and receipt index; reconstruct O, incoming,
   K and PK. Require exact field equality, `NOTE_FLOOR <= V <= MAX`, exact CM
   and authenticated position. Decryption alone is insufficient.
3. Use complete ordered accepted delivery history and current NF state before
   labeling a receipt unspent/spendable. Missing authenticated ciphertext data
   is an availability failure, never a fabricated receipt or zero balance.
4. Treat the earliest canonical positive receipt for i as its first ordinary
   credit. Later reused-index deliveries are flagged `UNSAFE_DUPLICATE` rather
   than silently auto-credited. Preserve **every** positive position/liability,
   including repeated CM bytes, and all owner-controlled spend/reveal authority.
   Later unsolicited reuse must not freeze or revoke the first owned claim.

Reuse may contaminate privacy of all notes under that k; a public descriptor
cannot enforce consensus-level uniqueness. Zero-valued dummy records are not
positive liabilities or ordinary credit. Reorg rollback does not erase observed
invoice use or disclosed k/openings. A seed plus accepted-chain history cannot
reconstruct orphan-only disclosures; any monotone local/archived disclosure
journal and counter-reuse assumptions must be reported. Without them, access
may be reconstructible while clean one-time privacy is not. Preissued invoices
allow an offline recipient to receive; issuing a new invoice needs receiver
participation. A general noninteractive reusable address is not solved here.

## 3. Private relation and padding

Each of two input slots has a private real bit. Require at least one real.
Real slots prove their exact note membership against the **current** CM root,
`position < n`, knowledge of s satisfying O and k satisfying K, and exact NF.
Both real positions differ. A 16-level path uses low 16 bits of the u32 position;
high bits are zero. Native current NF insertion determines spentness.

Dummy input slots have zero note fields, s/k/position/path. Their NF is:

```text
HMAC(dummy_key32, b"KPX2DMY\0" || D || dummy_seed32 || u8(slot))
```

Real slots have zero dummy-key/seed witnesses. Both public NFs are nonzero and
distinct. Insert them in **slot order 0 then 1**, against successive current
roots; no raw-byte sorting is introduced. Indexed-tree order is unsigned
256-bit little endian, not raw lexicographic order. Dummy NFs still consume
state capacity, just as real ones do.

Two output slots are always appended. A positive slot has `60M <= V <= MAX` and
public invoice fields; the recipient, not the sender's circuit, checks ownership
of those fields. A dummy output has zero O/incoming/V/K/PK but private fresh rho;
do not force rho zero and create a publicly constant dummy CM. Use opaque
264-byte random delivery padding for the dummy. Require at least one positive
output and distinct output CMs within this transaction. Do not impose global
CM uniqueness or collapse distinct positions across transactions.

```text
real_input_sum <= R <= MAX
real_input_sum = Vout0 + Vout1 + f <= MAX
R' = R − f >= 60M
n' = n + 2; m' = m + 2
```

No native payout in this private SPEND. Public input is SHA256(Auth484), split
into two unsigned little-endian 128-bit BN254 Fr elements. Circuit constraints
bind ownership, membership, exact CM/NF, value and relevant state/count/domain
fields to that digest. Native code authenticates every public NF/CM path and
actual transaction context; it must not assume the private circuit supplies
those public update checks. Correct encryption is **not** proved in-circuit:
the ciphertext hash binds durable records, while strict recipient acceptance
detects malformed deliveries. All positive outputs remain liabilities even if
malformed, undiscovered or quarantined.

## 4. Canonical state, authorization and public witnesses

All offsets are zero-based half-open byte intervals. Exact lengths; reject
trailing data. Counts are unsigned u32LE and amounts unsigned u64LE.

| State112 field | Offset / size |
| --- | --- |
| `b"KPX2ST01"` | 0 / 8 |
| D | 8 / 32 |
| current CM root | 40 / 32 |
| n, total appended CM positions | 72 / 4 |
| current indexed NF root | 76 / 32 |
| m, occupied NF leaves **including sentinel** | 108 / 4 |

CM depth is 16, NF depth 17. CM leaves are **raw CM**, not old v6's
`SHA(0 || CM)`. Empty CM leaf is SHA(CM-empty-tag); parents use the exact table
tags. NF leaf is `SHA(NF-leaf-tag || value32 || next_value32 || u32LE(next_index))`;
empty NF leaf is SHA(NF-empty-tag). Sentinel is zero value with the proper
linked successor. Preserve authenticated predecessor/index, strict range,
sentinel equivalence, next-link validity and empty-append/intermediate-root
checks from the reviewed public probe.

| Auth484 field | Offset / size |
| --- | --- |
| `b"KPX2AU01"` | 0 / 8 |
| D | 8 / 32 |
| actual previous outpoint, raw TxId bytes then u32LE index | 40 / 36 |
| prior State112 | 76 / 112 |
| actual input reserve R | 188 / 8 |
| owner-authorized actual fee f | 196 / 8 |
| NF0, NF1 | 204, 236 / 32 each |
| CM0, CM1 in append order | 268, 300 / 32 each |
| SHA(cipher0[264] || cipher1[264]) | 332 / 32 |
| next State112 | 364 / 112 |
| reserve R' | 476 / 8 |

PRIVATE payload is exactly `Auth484 || cipher528 || public_witness3344` = 4,356
bytes, with no additional header. Magic selects this branch. Witness layout:
NF0[1160], NF1[1160], CM-append0[512], CM-append1[512]. Each NF witness is
`pred_index4 || leaf68 || pred_path544 || empty_append_path544`. All paths are
leaf-to-root and evolve sequentially. Native verifies empty CM slots before
appending each output, and actual final roots/counts/immutable successor.

REVEAL payload keeps the probe's 2,029-byte field offsets, but magic becomes
`b"KPX2RV01"`; mode byte at 8 remains 1 and exact length selects this branch.
It authenticates the current CM root, reveals opening+k, recomputes the exact
same CM/NF, inserts one real NF, and requires the CM-bound PK's exact
SIG_HASH_ALL signature. `V = payout + f`, `R' = R − V`, payout at least 10M.
There is one input and no external fee input, admin or sponsor. The CM root/n
are unchanged; m increases by one. No old m-parity or m<=n rule survives here.

Proposed common scriptSig is canonical push65(sig65), push128(proof128),
PUSHDATA2(redeem), giving redeem offset 199. PRIVATE requires zero sig65 and a
real proof; REVEAL requires zero proof128 and a real signature65 ending in
exact ALL. Verify offsets/stack limits against the actual emitter before
freezing. Native checks exact version, input/output counts, metadata, payload,
fees/amounts, immutable profile and mass; no arbitrary output or fee namespace.

## 5. Capacity and exact backing

Select `1 <= n <= 65_535`, `1 <= m <= 2n+1 <= 131_071`, no parity rule. Private
append requires `n+2 <= 65_535`; public NF appends must fit depth17. This cap is
intentional: n=65,536 with two-NF padding could require 131,073 leaves including
sentinel, exceeding 131,072. Existing wider public-probe contexts are retained,
not retrospectively relabeled as passing this new profile.

Let C count all positive notes ever created and U all globally unspent positive
notes, including quarantined/lost/undiscovered ones. With initialized singleton
`C=U=1,m=1`, enforce inductively:

```text
m − 1 <= 2(C − U); C <= n
therefore m + 2U <= 2C + 1 <= 2n + 1 <= 131_071.
```

A private action consumes r>=1 real notes and adds two NFs, so 2<=2r; reveal
consumes one and adds one; admission increases C/U equally. Every still-unspent
real note therefore retains sufficient NF exit capacity. C/U are mathematical
ghost counts, not public identity metadata or a native global-liability oracle.
CM exhaustion may stop private append while no-append revealing exits remain.
Count-only supplied contexts outside that ghost invariant are not accepted
lineage evidence. In particular, a private action needs old n<=65,533; any
larger physical-NF-index exercise must be labeled by whether it satisfies the
ghost invariant, rather than treating every encodable state as reachable.

This note-only profile has no pending entitlements/rent/refundable credits or
donation merge. Authentic initialization establishes `R=L`, where L is **all**
positive unspent liabilities. Private SPEND lowers both by f; whole-note reveal
lowers both by V. Thus continuing reserve is at least 60M or zero. Terminal
R=V is sound under complete prior I-1 (`V<=L<=R`); create no zero reserve output.
Do not infer initialization from a supplied UTXO or current root. A public
test genesis may disclose its sole opening/value and empty NF state, but its
native founding/initialization validity must be separately checked before any
accepted-backing claim. No old subfloor credit or surplus is erased.
[Backing argument](../exit-fee/BACKING-AND-TAILS.md).

## 6. Admission extension: explicit candidate, not frozen core

Before a fee-bearing ADMIT circuit is selected, evaluate native public admission:
ingress already exposes value and the sender can disclose note168 without k/s.
Native code could recompute CM and append it with its 264-byte bound receipt,
using one 512-byte empty CM path, leaving NF state unchanged. Minimal funding
equations for one signed external P2PK input E are:

```text
R' = R + V; E = V + admission_fee + authorized_funding_change
```

No existing user's reserve pays that ingress fee. Exact funding authority,
change destination, native signature/hash type, immutable successor, initialized
genesis and all integer/mass bounds must be specified/reviewed before code.
One-note admission increments n by one, m unchanged. Publishing
incoming/O/K/PK/rho/V exposes the stable incoming key directly to chain observers
and links it to native funding ancestry, beyond the invoice/reveal disclosure
in the core. This is not equivalent to a private transfer; the privacy lane must
include those ingress fields if the extension is selected. Multi-user/batched
ingress remains a later cost option.

Even free admission does not remove the direct Groth16 ordinary-payment floor:
147,500 mass at rate 100 costs 14.75M, above 1% of a 10-KAS payment. Change is
not a second useful payment. Aggregate fee allocation and whole-lifecycle
economics remain independent gates; no new proof is repriced by a cheaper quote.

## 7. Reuse, alternatives and release gates

This adapts established HMAC/SHA and existing library key derivation/encryption,
not a new primitive or an audited construction. [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104)
defines the HMAC composition. The local
[`Wallet` derivations](../../../poc/shared-pool/src/protocol.rs) already use
purpose/domain-separated HMAC and native scalar rejection. Preserve the
candidate-C native source, not old note/tree framing.

The [Orchard source](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note/nullifier.rs)
illustrates sender-independent keyed NF derivation and the separation from
spend authorization; its curve/PRF construction is not imported.
[Orchard](../../zcash-orchard.md), [Aztec](../../aztec.md),
[RAILGUN](../../railgun.md), [Monero](../../monero.md) and
[MWEB](../../litecoin-mweb.md) comparisons were reread: reuse separate
view/spend roles, recipient reconstruction, exact value relations, current
exclusion and data-availability obligations. Their native consensus, ownership
formats, cryptography or fee guarantees are not inherited. Existing
[Kaspa/vProgs source comparison](../exit-fee/PRIMARY-SOURCE-OPTIONS.md) already
distinguishes accepted terminal claims from current private notes.

Alternative per-invoice delivery keys need discovery metadata/lookahead;
sender-derived DH delivery secrets also known to the sender cannot simply be
used as k. A reusable public descriptor K is rejected for clean one-time NF
privacy. No established noninteractive replacement is selected by this scope.

Before key/proof freeze: root ADR and independent
[adversarial gates](ADVERSARIAL-GATES.md), shared known-answer bytes, malformed/
boundary/cross-domain tests, descriptor reuse without freeze, s+k versus k-only
control, both private/reveal orderings, and full accepted-state/backing oracle.
Genuine private proof and actual immutable union must replace their reference
stand-ins. Actual full mass/fees, CPU/GPU resources, DA, latency and financial
privacy remain separate qualifications. The old 21.0977% prior-floor failure
and all frozen economic failures remain unchanged.
