# Public settlement-transcript source audit

Scope: read-only audit at workspace `5aaf99532d8714e510d421102df719f60f54d073`.
Only the finite public canary/competition cases, public parameter manifests and
selected source were read. No main history, nominal note witness, backup, PK,
private truth, native VM, prover or network operation was accessed. This is
pre-implementation guidance, not a new settlement or native-acceptance result.

## Exact reusable public inputs

All private-action proofs, Auth528 bytes, both NF update witnesses, ordered CM
list, ciphertext bytes, CM boundary path and entire23575-byte redeem program
are already present in each `validation-case.json`. They need no note openings.
Paths below are relative to `research/next-session/compact-batch/lifecycle/`.

| Purpose | Public case path | SHA256 |
| --- | --- | --- |
| First ordered action | `public-native-canaries-01/wide32/validation-case.json` | `308e841e4b212bfc67aad79bcab0a61698c0ce294fdbded7d3697137809b3f23` |
| Second ordered action | `competition-01/native-01/compact2-positive/validation-case.json` | `ae757a390a0a630e1b0678335536580cf9f82a5f10bdfe790503b0216252fc06` |
| Mutually exclusive alternative | `competition-01/native-01/wide32-positive/validation-case.json` | `c96a4eb95480839ae5446993b683ffd596f1d91954ae1b55f90169435dcdf2ed` |
| Public post-REVEAL anchor | `competition-01/native-01/reveal-positive/validation-case.json` | `4325269b133d5e2f0baffea52552f16a5a5daec78c1143edd92befa48207b8cb` |
| Fresh private-valid/occupied-NF negative | `competition-01/finish-01/genuine-current-compact-after-REVEAL-NF-duplicate/validation-case.json` | `ab39c204efb45952d17896882fc07d197edc2893eb91807197ec0ccabaa321a6` |
| Stale compact Auth with rebased body | `competition-01/native-01/old-compact2-proof-rebased-after-wide32-STALE-AUTH/validation-case.json` | `153c7005769793b7562a5506f48e22a4cfd677431924c46065dbda6539d3e270` |
| Stale wide Auth with rebased body | `competition-01/native-01/old-wide32-proof-rebased-after-compact2-STALE-AUTH/validation-case.json` | `59533c72b61c51e10f2c2f912b1810c20a51db9ffe038b990c02649fd9b63916` |

The old finite selections have SHA256 `01bc2bbb54c42aadc8d37204ab0eefad6cf307931a7a57be0673d1e9a9beac3f`
and `61d8dce37aee8443902a7e0b7bfc3ed5625da85838f4dc3ffdcd14b2c05449b5`.
They authenticate fixture acquisition only; their recorded acceptance booleans
must not replace current byte-derived semantic or cryptographic checks.

Public parameter manifests under `prover/parameters-{role}-01/public-parameters.json`
have hashes compact2=`f27a806928b5c2409d4e4c5428a75deabef6ecf9601b60889667e90363f26043`,
wide32=`b1f0e93bf153c423c669524318efe276917a902d4e9e6b250fba564face94149`.
Their exact VK hashes are respectively `bf033abd75237c3f04f4b8ca19ef93c115b192d04eb8360b8d5060ccdb9bed78`
and `a1be8ead145bd5fa65702f7eb3d2246dea307138f2915e5847a03813d70373fb`.
Every selected case has the same immutable redeem tail `redeem[114:]`, hash
`67ffaf246b915dfd1835d9a39401d72c9a197ea1e148a976a4f70305c70ce284`.
Select these identities externally; a transcript's own hash is not authority.

The positive chain is wide `n1/m1/R32000001000` → `n64/m3/R32000000000`,
then compact → `n66/m5/R31999999000`; both fees are1000 and P0.
The compact/wide alternatives both consume the same resulting wide outpoint,
same current state/reserve and same NF pair, but create different successors.
The fresh post-REVEAL negative starts at `n64/m4/R31000000000` and proposes
`n66/m6/R30999999000`. Its genuine private proof cannot establish NF absence.
All these fees deliberately fail reference-rate100 pricing.

## Byte-derived checks required

The pinned [native policy](../../../../poc/compact-batch-lifecycle/native/src/policy.rs)
(SHA256 `7e61c6060291f500fc0faa49ff3b467a9f9d6d8d1bff4d6fc52e8b87a94ba714`)
is the source of these public obligations, especially lines193–259 and329–399:

1. Parse strict canonical public fields and ranges. Extract the canonical
   65-zero-byte private signature,128-byte proof and complete redeem frame.
   Match externally selected domain/immutable tail/VKs, actual P2SH input SPK,
   exact previous outpoint, prior state and reserve. Recompute body IDs rather
   than trusting JSON `id`. Successor consumption must match the actual prior
   body's output0 amount/SPK and the newly derived state.
2. For each1160-byte NF witness, authenticate its predecessor leaf under the
   current17-level NF root. Check predecessor/next indices below append count,
   sentinel/index consistency, nonzero NF and strict **unsigned little-endian
   256-bit** predecessor<NF<next (unless next is the zero tail). Derive the
   predecessor replacement, authenticate the empty append slot under that
   middle root, then derive the inserted leaf/new root. Repeat sequentially;
   require final root and count `m+2` to equal Auth. Equality at an occupied
   predecessor must fail even when the ordinary proof verifies.
3. Continuing mode2/32 must authenticate the empty aligned target subtree under
   the prior CM root, derive its new ordered CM subtree and next root/count,
   and check SHA256 of the exact CM and ciphertext arrays. Check reserved bytes,
   exact lengths and `start=ceil(n/N)*N`, `n'=start+N<=65535`. Terminal mode0
   omits the append, carries CM root/count and fixes inactive metadata and
   SHA256(zero528) ciphertext sentinel.
4. Check `R=R'+P+fee`, all bounds/floors, exact native output count/amount/SPK,
   unchanged successor policy and mode→trusted VK selection. Actually verify
   ordinary G16 against the two LE128 halves of SHA256(Auth528). Curve/pairing
   verification must not be replaced by stored proof/report hashes.

Starting-state reachability, empty-suffix induction and accepted current-head
authority remain external premises. Missing currentness evidence is incomplete,
not proof of a current spendable head. A supplied synthetic head is sufficient
for this bounded semantic experiment but establishes no accepted-chain backing.
If REVEAL Schnorr verification is not implemented, use its post-state only as an
externally selected starting head; do not claim newly validated REVEAL execution.

## Upstream provenance and decisive controls

Pinned rusty-kaspa `01b532e8b553523216471682649693af92f0fd16` was read through
local Git objects. [hashing/tx.rs:99–134,207–235](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/tx.rs#L207-L235)
has SHA256 `965772f8daf6a941625c1c3b4601c1ee2dc4031d402bae98339064113c0ac5f1`:
version1 ID binds payload/rest digests while excluding signature scripts and
mass/compute commitments. Thus proof bytes need not serialize proving, and ID
equality alone cannot validate changed mass/budget. The copied private branch
does not itself require budget1600; fixed-budget research-profile checks and
actual meter/fee qualification must be labeled separately.

The pinned [hashers.rs:39–43,120–154](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/hashes/src/hashers.rs#L39-L43)
(SHA256 `752f6e6353b1316732e3141c8ac8a92094be70314e47ea83bb6dd68d5ca951c5`)
registers all three v1 ID hashes as **keyed BLAKE3**, with32-byte zero-padded
domain keys. Reusing the older keyed BLAKE2b transaction-hash construction would
be incorrect. P2SH redeem hashing remains unkeyed BLAKE2b32. Prefer the already
selected Rust normalizer over a handwritten primitive or silent substitution.

[groth16/mod.rs:74–120](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L74-L120)
has SHA256 `cb9fa14115d445c727cb8639ba384bde37d9a01f6c6f7fd1c92f77861f8a388d`:
it parses one checked ordinary BN254 proof, rejects trailing bytes and verifies
under the selected VK/public inputs. This is distinct from the surrounding
native NF/state/output checks. A public semantic mirror is not a new NativeFull
or consensus verification result.

Retain negatives for reversed actions, duplicated/replayed action, mutually
exclusive alternatives, occupied NF, rebased stale Auth, missing/incorrect
external head, wrong role/domain/tail/VK, corrupted NF/CM paths or array order,
CF corruption, changed destination/output amount, fee/reserve/context mismatch,
unknown/trailing fields and malformed proofs. To isolate public obligations,
mutate public witnesses/body outputs without changing Auth/proof, recompute any
derived body ID, and first establish that the unchanged ordinary proof still
verifies. Auth mutations additionally exercise actual statement-binding failure.
No positive transcript alone authorizes omission of intermediate UTXOs or an
aggregate fee/rebate: that remains a separately reviewed settlement policy.
