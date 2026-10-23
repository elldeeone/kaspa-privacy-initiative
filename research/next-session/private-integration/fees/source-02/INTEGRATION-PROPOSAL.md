# Native private-proof/reveal union proposal

**Proposal only; contract/ADR gate pending. No new subsystem or runtime yet.**
Baseline0c2f4c788a42. User authorizes new-format integration, not changes to the
frozen candidateC evidence, old S7 owner/replay/DRAIN workflows, old PKs,
requirements or invariant meanings. Only new `poc/future-native-union/` and this
native evidence subtree are owned here. Native stays pinned to01b532e.

## Minimal actual union

One immutable P2SH redeem contains a REAL native direct-Groth16 branch and a
REAL revealing branch selected by a canonical public operation mode. No NOP
stand-in, RISC0 wrapper, unchecked host oracle or accepted-state assertion can
stand in for the private circuit. The same actual immutable script, VK, domain,
CM/NF tags and state propagate to every successor.

Propose common canonical witness stack `[signature65][proof128][redeem]`:
65-byte native signature is a canonical66-byte push;128-byte compressed proof
uses130 bytes; redeem PUSHDATA2 header3 gives fixed redeem offset199. Private
requires signature65 allzero and consumes genuine proof; reveal requires proof128
allzero and consumes genuine SIG_HASH_ALL=1. This avoids branch-dependent old
state/successor byte offsets, at the explicit130-byte cheap-path overhead.
No branch reinterprets witness bytes or silently falls through to another mode.

Native reconstructs public transcript from actual old-state bytes in executing
redeem, actual prior outpoint/index, input reserve/native amounts, authorized
operation/next state/fees and public payload commitments. `SHA256(transcript)`
is split into two LE128 Fr scalars, preserving all256 bits without reduction.
The circuit must reconstruct/constrain the same transcript. The native script
reconstructs the immutable successor using the actual executing policy suffix,
not a caller-supplied script hash. New current-CM/current-NF state is shared;
private/reveal consumption inserts the exact same real positioned HMAC NF.

The private branch must not reveal the consumed CM, position, amount, s or k.
Ciphertexts/other public bytes need exact transcript binding and recipient
validation. A payload hash does not prove correct encryption. A genuine proof
is not enough unless its public context is reconstructed from native values.

## Contract inputs required before implementation

Architecture must pin operation modes, header/domain/chain binding, state
layout/counters/capacity; circuit2-in/2-out real/dummy rules and exact dummy-NF
derivation; CM append and current indexed-NF updates; public payload/ciphertext
layout; exact SHA transcript; principal/fee/mode conservation; genesis/admission
meaning and terminal rule. Need fresh genuine VK328 and compressed proof128
with the two exact public scalars, independently verified, under the final
circuit relation. No old VK/domain/PK/proof or old owner workflow is imported.

Provisional architecture says retain candidateC primitive tags/CM168 bytes,
NEW domain/header/state, CMdepth16/NFdepth17, CMcap65535, private2NF slots and
reveal1NF, sentinel-inclusive m<=2n+1. This is incompatible with silently
retaining the old public probe's active guard m<=n. A separate real-consumption
ghost invariant must justify headroom; even n/m counts alone do not prove it.
Capacity checks and top17-bit append controls must follow the final contract.

## Public native admission proposal

After the union transfer core, the simplest fee-saving admission branch needs
no private proof: note public receive fields O/incoming/K/nativePK, rho and
public V form CM, authentic empty current-CM path at n appends exactly that CM,
CMcount increments once, NFroot/count unchanged, immutable successor preserved.
Use exactly two inputs: current reserve0 plus canonical native P2PK funding1.
Require funding1's actual SIG_HASH_ALL canonical signature/witness and bound
P2PK key. Let native funding amount Din, fee F, minted liability V=Din-F:
`R'=R+V`, so no existing reserve pays the depositor's fee. Native Full verifies
funding authorization and all amounts; branch checks exact input/output shape,
actual R/Din, integer ranges, V floor, exact CM/current-root append and newstate.
There is no operator signature or reserve decrement shortcut.

The native chain does not independently know whether supplied K/PK belong to
the recipient's pre-payment descriptor. Recipient must validate those bindings
before accepting value; malformed recipient data cannot be called spendable.
A public admission reveals its deposited amount and receive commitments.
Initial construction/backing needs an explicit genesis story, not an arbitrary
host root or a zero-value reserve workaround. No initialization is qualified by
this proposal, and no funding/broadcast is authorized.

## Honest early stop bounds

Pinned native G16 tag0x20 charges14,000,000 units plus250,000 for each VK
`gamma_abc` point. Two public inputs require3 points, hence14,750,000 units,
necessary budget1475 and147,500 mass before context/witness/script overhead.
A private payment's necessary fee is14,750,000 at100 and73,750,000 at500. Its
own exact circuit/VK/public bytes cannot remove this current-native tariff.

Therefore an individually verified10-tKAS payment already exceeds RFC0012's
1% ordinary payment ceiling of10,000,000 at reference100. This is a retained
route failure before implementation. Public admission and cheap reveal can
reduce complete-lifecycle fees but cannot repair that single-payment bound.
Aggregation/amortization would be a separate architecture/authorization design,
not something this single-proof union can claim. Larger payment success cannot
silently redefine the normal10–1000 range. Fee/privacy/latency targets stay fixed.

The skipped private branch does NOT pay the G16 tariff on a reveal, but its real
bytecode/VK remain in the witness. With transient factor4 and normalized factor1/2,
mining mass is at least2*estimated serialized size. A60M principal with10M payout
at500 permits at most100,000 mass, hence total estimated bytes<=50,000 even
before compute/storage constraints. Thus a redeem approaching50KiB is already
impossible;32KiB is a hypothesis, not a qualified result. Actual minimal code
size, witness/payload bytes and branch-specific budget must be measured before
any proving work is justified by an economic claim.

Storage alone also rules out some reserve states regardless of union code.
For a standard one-input/two-output exit, q=R-V, P=V-f and C=10^12:
`storage=floor(C/q)+floor(C/(V-f))-floor(C/R)` when positive. With V60M,
q10M or20M, and500, no f<=50M can self-fund while retaining P>=10M. This follows
from a continuous upper bound that includes the floor's full one-unit slack,
not a failed fixed-point iteration alone. [Exact integer bounds](STORAGE-LOWER-BOUNDS.json).
With A=floor(C/q)-floor(C/R) and b=500*(A-1), necessary affordability implies
`(f-b)*(V-f)>=500*C`; its maximum over f0..50M is smaller than500*C for both.
q60M is not ruled out by this relaxation, which is not positive qualification.
Any new-format floor/admission policy intended to avoid these states requires
explicit architecture agreement; old liabilities/economic failures stay intact.

## Release gate

Wait for final contract/ADR, independent adversarial review and frozen complete
sources/wires/expected results before native runtime. Runtime must use actual
private proof and full native isolation/Full/ScriptEngine and complete official
mass dimensions, then fee fixed points over actual payout layouts. Retain every
failure; verify both cross-path losing attempts with intact authenticated
membership and rejection at current spentness. Synthetic chained contexts are
not accepted-chain backing. No mainnet, real funds, privileged rescue, old PK,
funding or broadcast. Heavy native build cap3CPU/5GiB/swap0, isolated systemd,
private external target; no extra GPU proof from this workstream.
