# Native private exit and independent reveal construction

Status: source/design only, pending the root ADR and exact contract release.
Baseline: `63f494053b743ac9bfbd2d1842f69e0f806ef8e3`.
No implementation, key load, native execution, funding or broadcast is part of
this note. Existing funded and closed source remains unchanged.

## Smallest private-exit policy

Extend the existing private action rather than copy it into a fourth branch.
The current private branch already verifies two ordered NF insertions, two CM
appends, ciphertext binding, immutable successor and a fixed two-public-input
Groth16 proof. It currently permits only one reserve output and `R'=R-f`.
See [current source](../../../../poc/future-native-union/src/policy.rs).

Proposed shared Auth528 preserves the first 484 bytes' field offsets, changes
its magic to `KPX3AU01`, and adds:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 484 | 8 | Public native payout P, u64 little endian |
| 492 | 36 | Exact native output SPK: version `0000`, `20`, x-only PK32, `ac` |

P=0 requires a zero36 SPK and denotes ordinary private transfer. P>0 requires
the exact canonical version-zero P2PK representation and a positive payout.
The destination is proof-bound but independent of an input note's emergency
PK. Reusing that PK could expose equality to public ADMIT or invoice fields.
The wallet must validate the intended destination before proving.

The payload is Auth528 + ciphertext528 + public update witness3344 = 4400
bytes. SHA256(Auth528) still maps to the same two LE128 public field elements;
the new circuit/matrices/VK and new immutable policy/domain are a new instance.
No old note or funded instance acquires a new branch.

Native checks bind exact current State112, current outpoint, input reserve R,
fee f, P and R'. All arithmetic uses bounded native integers:

`R' = R - P - f`, and the proof enforces
`sum(real private inputs) = sum(private outputs) + P + f <= R <= MAX`.

The input count is exactly one. No external fee/sponsor input or implicit admin
authorization is added. The proof, rather than an operator/native signature,
authorizes the payout and destination. The inactive common signature65 is zero.
All output covenant authorizing-input metadata must be absent (`-1`), not merely
the output SPK/value. Official introspection exposes both exact SPK bytes and
this metadata. [Output introspection](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L1151-L1173),
[authorizing input](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L1421-L1433).

| Condition | Exact native outputs |
| --- | --- |
| R'>=60M, P=0 | Reserve output0 only |
| R'>=60M, P>0 | Reserve output0 and exact payout output1 |
| R'=0, P>0 | Exact payout output0 only; no reserve successor |

Continuing actions append two private/dummy CMs with the existing opaque padding
profile. Terminal actions skip CM appends and preserve CM root/n; every unused
output witness, CM0/CM1, ciphertext528 and CM-append witness1024 must be canonical
zero before skipping. Both ordered real/dummy NF insertions remain valid and
`m'=m+2`. This avoids requiring a revealing fallback merely because CM capacity
is full. The existing liability-capacity argument must be explicitly rechecked
for the new terminal case. The proofless owner REVEAL path remains available
with its unchanged public opening, original NF and CM-bound native key/ALL
signature; disclosure is a distinct user choice, never automatic privacy.

## Economic lower bound, before a new native body exists

The pinned native verifier charges 140,000 grams plus 250,000 script units for
each of three gamma-ABC elements (two public inputs plus one). There are 100
script units per gram: the verifier alone therefore costs at least **147,500
mass**, before transaction bytes, state hashing, compute-budget rounding,
storage or transient mass. Sources:
[tag tariff](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs#L29-L35),
[VK tariff](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L18-L46),
[units](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L1-L7).

For one actual two-recipient private payment followed by two independent private
cashouts, three verifiers cost at least 44,250,000 sompi at reference100. The
per-useful-10-KAS-payment floor is 22,125,000 sompi, **2.2125%**, already above
the unchanged 2% complete-lifecycle target. All admission/founding/tails/bytes
remain additional costs. A one-useful-payment-plus-change route with two final
claims is worse. No performance optimization changes this native tariff. A
proof/private-exit prototype may close a disclosure channel without qualifying
the economic target. Shared secrets or another future user's arrival may not be
silently used to amortize independent exits.

Actual script size, native units, budgets and complete bodies must be measured
after implementation; there is no new size/fee result in this source note.
The current full union is 22,388 bytes; duplicating its expensive private path
would raise all branch fees, which is why shared action logic is preferred.

## Generic proofless recovery builder seam

`native::execute` / `validate-transaction` already validates arbitrary actual
redeem scripts with official native APIs. Its validation path does not require
the source's compiled development domain. In contrast, `reveal_body` regenerates
the policy through `policy::redeem`, which does require that compiled domain.
[Existing factory/validator](../../../../poc/future-native-union/src/native.rs).

A new small generic helper can take the authenticated current redeem from
independent replay, verify its State112/domain and current P2SH, preserve the
immutable tail exactly, replace only the initial state for a continuing
successor, and construct/sign a native REVEAL with official Schnorr ALL and
mass APIs. It needs no PK, prover, source-specific VK loader or per-domain build.
The caller must select/pin this helper's source/binary before passing one owner's
secret on stdin. Quote mode needs no secret and uses a zero65 signature.
Outputs are only public transaction/context/mass/Full reports. The helper never
logs the request or secret, and has no RPC/broadcast path.

Official `v2.1.0` remains `01b532e8b553523216471682649693af92f0fd16`; master
remains `4edcbbccb449f84832afb1ca157904b35f37d006` in a read-only ref check for
this note. The source-compatible release pin is retained, not replaced by master.
