# Independent exit-probe gates

Status: **closed**. Raw terminal source/input/result review, future-exit
source/input/result review and model controls-03 review are complete.
This is a new follow-up; the previously closed `EXIT-OBLIGATIONS-REVIEW.md`
remains unchanged at SHA256
`4d98585f66f35ba05ae573f2d5b33c239f9833bdac83260b03703295a5f83cd5`.

Reviewer: independent binding/adversarial lane. Reviews used source reads,
SHA256 checks and independent Python standard-library arithmetic/encoding
checks. The reviewer did not build software, generate proofs, execute native
scripts, fund accounts or broadcast transactions. Native outcomes below come
from the named producer's saved output, independently recounted.

## Raw terminal permission claim: completed

The reviewed experiment uses the frozen upstream permission emitter only for
its depth-one, count-one-to-zero terminal case. Independent old/new Merkle
walks are not accepted as a safe continuing-state update. No continuing claim
tree, private-note authorization, accepted backing or chain inclusion is
qualified by this experiment.

| Identity | SHA256 |
| --- | --- |
| `poc/native-terminal-claim-cost/src/main.rs` | `16003552e9168444484e7e7627fadfa9077cea3e098df7dceb49bde7b944f5af` |
| `poc/native-terminal-claim-cost/src/native.rs` | `4c701280b797ea4f8b69e9c3a6a76a5425fc0370ef81d9cf6af86957a3b979db` |
| Stage-02 source freeze | `bff1f2074a6479b083f292dc14f9210f15a8367a88bf1863be4d1f4223c10125` |
| Immutable stage-02 checker | `6549a955731710d330cc2b138050a888f2d068852ee5b09eb930ecb7ee5fbd69` |
| `native-claim/preparation-01/public/manifest.json` | `2dc7a4fc92ceb96072adc1c630584f2724be55f7cba5ad26744c0519d31b8f6f` |
| Saved `native-claim-target/execution-01/results/report.json` | `d26f552d1889b21c17ac3dac2ce6b667235560effad555015ae9f7f156ff9d64` |

The source review checked sponsor change, exact payouts, fixed permission
destination, separate rent and principal, actual signature hash types and
precise rejection layers. Semantic mutations re-sign the sponsor so failure
does not merely demonstrate an invalid retained signature. Tiny-output storage
confounds were removed before the selected preparation; earlier stages remain
preserved.

Independent input checks consumed all 22 Borsh transactions and supplied UTXO
vectors exactly, checked 44 body/context hashes and checked cached transaction
IDs against metadata. Independent SHA256 leaf/root and BLAKE2b P2SH/witness
checks matched the original 467-byte emitter. Size, compute, transient,
storage, mining mass and fees were recomputed from the pinned native formulas.

The saved report has **22/22 exact expected outcomes**:

- Four accepted cases: sponsored rates 100/200/500 and the separate zero-fee
  case.
- Fourteen semantic failures: Full `SignatureInvalid(VerifyError)` and native
  input-zero `VerifyError`.
- Three payer-signature failures: Full `SignatureInvalid(EvalFalse)` and
  native payer-input-two `EvalFalse`.
- One isolation failure: `TxDuplicateInputs`.

Sponsored positives use estimated size 1,067 bytes and mining mass 4,987,
with required fees 498,700 / 997,400 / 2,493,500 sompi. Measured native units
are 2,553 permission, 181 delegate and 100,001 payer. Those observations do
not change the executed committed budgets 22/0/10. A lower 0/0/10 commitment
and its corresponding mass remain derived-only.

The 60M principal plus 50M permission rent pay 110M to the fixed destination.
A separate 100M P2PK fee input, less returned change, pays the miner. This
does not establish a self-funded 60M exit. The zero-fee case is a consensus
validation observation, not relay or inclusion readiness. A missing-entry
lookup control is separate from Full validation and from actual chain
spentness. The supplied UTXOs are not an authenticated accepted chain view.

## Future revealing exit: source and prepared inputs completed

| Identity | SHA256 |
| --- | --- |
| `poc/future-exit-feasibility/src/main.rs` and frozen source-03 | `29f4d40c0e9457fb541411ad5b92beed3b357c2e0e8e9b4de8816686a3691bf8` |
| `future-exit/PRE-EXECUTION-FREEZE-02.json` | `1c8d432425ced73fc4f7e9a0d74cf992c86d0ad41dc3001504cd1998ba4a3983` |
| Prepared checker binary | `a329090e81466a7f2c134c9f826322b9277197c3bf288bac26011cfd3c1a5b50` |

All **191 frozen members** were independently rehashed. The freeze records
190 paths relative to the future-exit packet and one explicitly
repository-relative `poc/future-exit-feasibility/verify-prepared.py` path.
Current source and checker identities matched. The source-02-to-03 delta
contains only borrowed message digest arguments and an explicit `u64` fee
variable type; no transition semantics changed.

All **60 positive prepared transaction bodies** were independently checked:
15 fixed-fee fixtures plus 45 fee-agility fixtures. Their 99 supplied contexts
also cover 39 frozen negatives. The independent checks reconstruct from the
actual witness, payload and UTXO bytes:

- The key commitment, note commitment, exact tagged HMAC nullifier and current
  commitment-root membership with unsigned position/count bounds.
- Authenticated predecessor membership, strict little-endian numeric NF
  order, replacement using the same path/index, intermediate root, empty
  append authentication and final indexed-NF root.
- Exact next-state bytes, unchanged commitment root/count/domain/policy
  suffix, successor P2SH hash, `R' = R - V`, committed payout key and
  `payout + fee = V`.
- Exact estimated bytes, compute/transient/storage/relay/mining mass, actual
  fees and each reported fee quote.

The current-spent-NF equality negative independently authenticates the exact
already-present NF leaf to the **current** input NF root at its valid index.
It then violates strict insertion order. This is distinct from the retained
stale-witness control.

The source uses the actual selected `SigHashType` when signing. The weak-NONE
negative has an independently verified valid Schnorr signature for NONE,
while the covenant requires ALL. The extra-input negative uses a distinct
outpoint. Semantic negatives require both exact native `VerifyError` and
Full `SignatureInvalid(VerifyError)`, rather than arbitrary rejection.

All 45 frozen fee-agility outcomes are retained: **36 pass, nine fail**.
Native validity cannot replace an economic failure. In particular, small
continuing reserve remnants may impose a prohibitive storage mass. The
10M/20M-remnant rows are supplied-context boundaries and are not retroactively
made reachable under a proposed 60M positive-note floor.

The proposed private-reference contract assumes independent secrets `s` and
`k`; the public fixture checks both hash credentials, and its native witness
discloses `k` but not `s`. Native authorization additionally
requires the CM-bound Schnorr key. The rejected single-credential variant
allows a copied reveal to authorize an attacker private spend before the
honest reveal; sharing an NF only makes that race first-writer-wins. Hash
checks on public fixture secrets are not a cryptographic secrecy proof.

The terminal `R = V` case is conditional on complete, valid prior backing:
an authenticated unspent whole note gives `V <= L <= R`, hence `L = R = V`
and no remaining positive liability after consumption. Membership plus
supplied UTXOs does not establish that inductive premise. Surplus, pending
claims and refundable credits must remain in the complete liability equation.
The probe implements neither the new private circuit nor authenticated
genesis/lineage, migration, descriptor recovery or a complete private lifecycle.
Padded envelope cases approximate byte/mass cost; their NOP padding does not
implement a private branch. The format is not adopted or declared secure.

### Saved native result

The saved `future-exit/execution-01/results/` files were independently rehashed:

| File | SHA256 |
| --- | --- |
| `positive-results.json` | `c57af252b7a72da8dc9860dde9870bd477a22354a570d8acff86f5a50123ad54` |
| `fee-agility-results.json` | `028503259c04aefc068790880e5beab6e345ab3b38b22049df12f64a669d9f95` |
| `negative-results.json` | `ec1b4e4729fdf3c89d9caf22b3b71c0042cc8dd90ddc2554834b3c0cfe213b9d` |

All **99 actual transaction files** are byte-identical to the frozen
preparation. Every fixed positive and fee-agility row, excluding its newly
added execution result, equals its frozen metadata/metrics row. All 60 have
isolation PASS, Full acceptance with the exact expected fee, and native
ScriptEngine acceptance. Positive native units range from 140,945 to 425,140
under the executed typed `computeBudget = 200` commitment.

All **39 negatives** match the frozen case order and have isolation PASS,
native `VerifyError` and Full `SignatureInvalid(VerifyError)`. This includes
the valid-NONE-signature control and the independently authenticated
current-spent-NF equality control. The VM unit count also places the latter
past the early frame checks, but this is a typed/source-supported rejection
claim, not an instrumented assertion of a particular opcode program counter.

The 36/9 fee-agility split remains unchanged. The nine failures are six
10M/20M-remnant cases at rate 500 plus three 49,152-byte envelope cases
(terminal, 60M remnant and high-index) at that rate. Every failed economic
case still has native Full/VM acceptance; those outcomes answer different
questions. No threshold or fixture was retuned after execution.

`execution-01/frozen-body-comparison.json` is
`5794edbcef85132e650601748bba891432fca7bda5379272ce4cb71e10156600`.
The binary/source identity list is
`afa441689b1205c8ba1db721adb1cfb40f83695c74b6c488791c3c8a169aa546`
and the execution runner is
`387e1681d2350af1efea406ad1a37a0870c4c6750ec5aac5bda7796cd0444600`.
The runner verifies those source/binary hashes and uses network-isolated
bubblewrap with a read-only checker and a fresh writable execution directory.

Saved cleanup SHA256 is
`1feffc639b06682e92f72cf387dc4940f4597111bc660f62371c43383660becc`.
The reviewer separately queried all five named build/freeze/native units;
each was inactive/dead with MainPID zero and an empty ControlGroup. No GPU
work was used. These checks establish the recorded supplied-context seam,
not accepted-chain spentness, full relay-policy evaluation, public network
inclusion, cryptographic private ownership or a complete private lifecycle.

## Liability-model controls: source correction reviewed

Reviewed `poc/exit-liability-model/controls.py` SHA256
`cfed5316d33d3c2474370206a4c0293f53f4e5561ca16332ae09f6ceeab2b691`.
The source correction restores the ancestor financial state while explicitly
carrying the current quote, service/data flags and published credential
knowledge. It performs a real quote-rise action before rollback, covers
8 environments × 4 knowledge states × 2 quotes = 64 products, and directly
attempts all nine same-original-NF private/accept/ideal-reveal competitors
outside the action generator's unspent filter. It separately checks usable
historical accepted roots, current and historical-paid replay rejection, and
duplicate-batch rejection. Revealing authorization here remains an explicitly
ideal oracle.

The prior freeze-02 rollback helper's quote reset is preserved as a failing
regression. It was confined to controls; the closed graph exploration did not
call that helper. No repeat of the unchanged graph search is implied.

Unchanged reviewed core identities:

| File | SHA256 |
| --- | --- |
| `model.py` | `81e6604ea69402280acfcdf291a84d5eef31686c23386521e0dcf9ca503ab30f` |
| `oracle.py` | `915f4540323982fb1c47236c8085ae991a3909a66aea7656162df98f94cb71ce` |
| `search.py` | `69d795a27bdf7f8b4465a449bb0f13012e4a59772a2f04390cabfbb39db4c94a` |

The selected controls-03 source freeze is
`412d758552bc17f09cab138a0549b73f3f10479bd0fd5bb006886e73aeadab9c`.
The saved `exit-model-runtime/controls-03/result/controls.json` was independently
rehashed at
`d9c2b4977a40cf585c95f1e490ceaeea994d48c840dfbf455ff1f58438633721`;
its 64 rollback products, nine direct competitors and eleven must-detect
mutants match the reviewed control definitions. The original quote-reset
failure remains at regression SHA256
`6d031c9d36e0873a5fece9d473e8b6bf718e64333e4d5b4d59b37a2524d24bee`.
These finite models do not qualify cryptographic authorization, native
execution, real reorg acceptance or operational liveness.
