# Unified private payment and private native exit contract

**Status:** root-selected prospective experiment, 2026-10-23; independent
source/contract review precedes implementation/setup. This does not modify an
existing funded pool, its verification key or its note authority.

## Scope and reused relation

Preserve Note168, Invoice208 V2, receipt216/cipher264, State112, SHA256/HMAC
tags, raw-CM membership, indexed-NF ordering, separated private ownership `s+k`,
two real/dummy input slots and integer-slack conservation from the
[KPX2 contract](../private-integration/NOTE-STATE-CONTRACT.md). Use a fresh
root-selected domain D and fresh Groth16 matrices/PK/VK for the whole new union.
Old proof parameters are incompatible. Local development setup is not a ceremony
or cryptographic/security certification.

Root selected the unfunded public development D as SHA256 of exact ASCII
`KPI/private-exit/DO-NOT-FUND/v1/2026-10-23` (no NUL/newline):
`aa39ad5d2da85dfd1695cc74ce3e0f23e713f315d6e5341bccc8a060111354c2`.
Never fund its deliberately public development identities. A funded trial needs
its own fresh domain/secrets/matching setup.

The new private relation accepts public value leaving the pool without revealing
an input Note168, input CM, position, k or note-native key. It can produce private
change. This adapts established shielded value-balance semantics; it imports no
Orchard, Aztec or RAILGUN cryptography. The public payout amount/address, fees,
timing, public ingress and complete drainage still permit inference. This is an
exposure-reduction hypothesis, not privacy qualification.

## Exact authorization and payload

The authorization is **528 bytes**, called Auth528. Offsets are zero-based;
amounts/counts are canonical u64LE/u32LE, never field-wrap arithmetic.

| Field | Offset / size |
| --- | --- |
| exact magic `b"KPX3AU01"` | 0 / 8 |
| fixed new D | 8 / 32 |
| actual prior raw TxId + u32LE output index | 40 / 36 |
| prior State112 | 76 / 112 |
| actual input reserve R | 188 / 8 |
| owner-authorized actual fee f | 196 / 8 |
| NF0, NF1 in insertion order | 204, 236 / 32 each |
| private output CM0, CM1 | 268, 300 / 32 each |
| SHA256(cipher0[264] || cipher1[264]) | 332 / 32 |
| next State112 | 364 / 112 |
| remaining reserve R' | 476 / 8 |
| public native payout P | 484 / 8 |
| complete destination SPK | 492 / 36 |

Public inputs remain SHA256(Auth528) split into two unsigned little-endian
128-bit BN254 Fr limbs. The selected immutable VK has that exact arity.
Payload is `Auth528 || cipher528 || public-update-witness3344`, exactly
**4,400 bytes**, with no extra branch header or trailing bytes.

Witness remains NF0[1160], NF1[1160], CM-append0[512], CM-append1[512]. Global
payload offsets are 1056, 2216, 3376 and 3888 respectively. Both NF witnesses
are mandatory sequential authenticated updates, including terminal exit.
The common input script frame remains zero sig65, genuine proof128 and the
canonical full redeem at byte offset199.

## Public/private amount and destination rules

Use `MAX=2,870,000,000,000,000,000`, note floor60M and payout floor10M sompi.
At least one real input is mandatory. Preserve distinct real positions,
canonical real/dummy fields, nonzero distinct public NFs and current CM proofs.

```text
0 < input_sum <= R <= MAX
1 <= f <= MAX; 0 <= P <= MAX; 0 <= output_sum <= MAX
input_sum = output_sum + P + f <= MAX
R' = R - P - f;  R' is 0 or >=60M
```

All additions/subtractions have explicit range/slack constraints. Private
ownership authorizes the entire exact public statement, including the chosen
destination, actual outpoint, fee, reserve effects, state and ciphertext binding.

- **P=0:** destination36 is all zero, no native payout output exists and at least
  one private output is positive. R'>=60M. This is ordinary private SPEND under
  the new relation, not compatibility with old Auth484 proofs.
- **P>0:** require P>=10M and destination36 exactly
  `00 00 || 20 || xonly_PK32 || ac` (version-zero P2PK). The destination is chosen
  by the owner. The R1CS additionally enforces, conditional on each real input,
  **payout_PK32 != input.note.nativePK32**. This prevents exact reuse of a
  consumed note's public emergency key and its direct ADMIT/invoice equality
  channel; malformed/reused-real-input-key controls must be unsatisfied.

The native policy and circuit bind the **entire SPK36**, not merely an amount or
caller-declared hash. Byte-template checks do not prove curve-point validity or
control, global freshness or randomness of a destination key. The per-real-input
inequality proves only that specific non-equality. The wallet must use the
established secp256k1 parser, choose a fresh destination and authenticate its
intended owner before proof authorization. Arbitrary externally requested
canonical destinations are allowed unless equal to a consumed real note's key.
External recipients need not reveal their native signing secret to the prover.

## Continuing and terminal state

**Continuing, R'>=60M:** append two CM slots and insert two NFs; n'=n+2,
m'=m+2. Retain positive-output floors and canonical dummy outputs (zero
O/incoming/V/K/PK, fresh rho and opaque padded ciphertext). P=0 needs at least
one positive output; P>0 permits zero, one or two positive private outputs.
Output CMs must be distinct and each public append witness must authenticate the
current empty slot in sequence. All positive outputs remain liabilities even if
delivery is malformed or quarantined.

**Terminal, R'=0:** require P>0 and both complete private Note168 witnesses all
zero, **including rho**. Auth CM0/CM1, cipher528 and both CM append witnesses
(1024 bytes) are all zero. Enforce these zero checks before omitting append
work. No CM is appended: n'=n and CMroot'=prior CMroot. Both NF insertions still
execute, giving m'=m+2 and the authenticated next NFroot. The final State112 is
retained in the payload; no reserve UTXO or phantom dummy delivery survives.
Auth's ciphertext-hash field remains **SHA256(528 zero bytes)**, not a zero
digest. Hash binding, real/dummy NF derivation, nonzero/distinct NFs, current
absence and both sequential NF witnesses remain fully enforced at terminal.
Output-CM recomputation/equality/distinctness checks apply only to continuing
outputs; terminal inactive zero fields are explicitly constrained instead.

Native bounds are n<=65,533 for continuing append and n<=65,535 for terminal.
Both require available two-NF capacity and final m'<=2n'+1<=131,071. From the
existing exact-backing history, let C be all positive notes ever created and U
all unspent positives. `m-1<=2(C-U)` and `C<=n` remain inductive: consuming
r>=1 notes adds2 NFs with2<=2r; creating o notes increments C/U equally. Terminal
creates no notes/CMs and conserves this bound even at full CM capacity.

Exact prior `R=L`, counting **all** positive liabilities, plus terminal
conservation forces input_sum=R=P+f and no surviving positive liability. A
supplied R/root alone does not establish that premise. Continuing CM exhaustion
still blocks private appends; explicit revealing fallback remains available,
with its privacy loss. This limitation is not an ordinary-private-exit pass.

## Actual native transaction checks

One noncoinbase pool input only; executing input index0, exact actual prior
outpoint/R/SPK, sequence u64::MAX, version1, zero subnet/gas/locktime and no
external fee/sponsor or privileged signature. Every output has version-zero SPK
and absent covenant/authorizing-input metadata. The exact transaction fee is f.

| Mode | Exact outputs |
| --- | --- |
| P=0, R'>0 | output0: R' at the exact immutable union with only next State112 substituted |
| P>0, R'>0 | output0: same reserve successor; output1: P at exact Auth destination36 |
| P>0, R'=0 | output0: P at exact destination36; no reserve successor |

No arbitrary destination, hidden change output, code/VK/domain replacement,
zero-valued reserve or output reordering is allowed. Native verifies every
public NF update, required CM append, actual state/count/context, fixed VK and
proof/public-input relation. P0/P>0 share one verifier path, avoiding duplicated
private bytecode. Actual Full/engine/mass/fee measurements are required.

## Fallback, privacy and fees

ADMIT1344, REVEAL2029 and genesis536 retain their framing within the **new**
domain/union. REVEAL keeps its CM-bound nativePK and exact ALL signature; it is
an explicit owner-consented privacy-degrading escape, never automatic fallback
or operator permission. Genesis is source-verified
`KPX2GN01 || D32 || Note168 || CM32 || cipher264 || SHA(cipher)` (536 bytes).
An earlier finite-adapter narrative saying genesis omitted D was wrong; accepted
bodies/native source remain unchanged and authoritative.

The current direct verifier floor alone is147,500 mass. At reference100, one
private EXIT therefore costs at least14,750,000 sompi. Adding the existing
two-recipient prefix share13,543,900 already exceeds the20M (2% of10KAS)
lifecycle target before the larger new union/body. This unamortized route is
**not fee-qualified**. Privacy, general independent recovery, public prior-floor
failures and p95 targets remain separate. No new token, admin withdrawal,
witness pooling or hidden payer is selected.

Required controls include destination/value/fee/domain/outpoint substitution,
malformed SPK/version/metadata, exact consumed-note payout-key reuse, both spend/exit race orders, current occupied
NF, wrong ownership/root/path, integer boundaries, nonterminal dummy handling,
each forbidden terminal nonzero field and full-CM terminal success. Valid
alternative owner-chosen statements need fresh proofs; replaying the original
proof for them must reject. A copied k without s must not spend privately.
