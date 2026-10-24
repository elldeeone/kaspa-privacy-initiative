# New owner-private native verifier — measured result 01

Classification: **unfunded research prototype, ADR0063**. No network, funding,
broadcast, accepted backing, current UTXO, withdrawal, or production-security
claim is made by this result.

The actual assembled batch contains three genuine Spend proofs and six genuine
Output proofs. The fixed public predicate verifies both proof roles, the full
financial effects authorization, value-commitment balance, unique nullifiers,
state transitions, and the selected native transaction context. It exposes no
per-owner output subset. Recipient delivery still requires the recipient's
local decrypt/invoice/note checks; Output G16 does not prove ciphertext encryption.

## Executed path

1. Independent standard Arkworks pairing cross-check passed all nine component
   proofs against the same final body.
2. The new R0 guest executed on CPU: **487,068,688 cycles, 8.603369678 seconds**.
   Development mode was absent. This execution generated no receipt.
3. The exact new image and projection produced a genuine succinct receipt on
   GPU in **1,854.358 seconds**. Proving reported 1,051 segments and 551,026,688
   total cycles; this includes proving/segmentation overhead and is a different
   statistic from the CPU execution cycle count.
4. Genuine Groth16 compression and a separate CPU receipt verification passed.
   The selected receipt has the exact journal and no unresolved assumptions.
5. The native077 Full validator and its only input ScriptEngine accepted the
   actual 128-byte proof. Usage was **15,548,275 / 18,009,999 script units**.
   Actual fee **19,332,300 sompi** equaled mass **193,323** at reference rate100.
6. All **12 canonical transactions reusing the identical outer proof and redeem**
   were rejected: two changed body/proof bytes reached `ZkIntegrity`; ten changed
   native context/header/effect fields reached `VerifyError`. The latter include
   a consensus-valid output genesis covenant binding, not an arbitrary invalid ID.

The first output-count fixture duplicated the full output, correctly failing
`SpendTooHigh` and `VerifyError`; its negative-fee metrics were unavailable.
That complete failed run is retained. An additive V2 fixture splits the original
output into two outputs of at least60,000,000 sompi, preserving total value and
fee. Its rejection isolates the selected one-output policy. Production code,
image, keys, session, owner proofs, and all financial checks were unchanged.

## Exact identities

| Object | SHA-256 / image |
| --- | --- |
| Component profile | `41fa85a1633c7df78970b9c4f4b5cf0a9ae8280e8ea3605a2377088ab8476fa0` |
| New R0 image | `797bc8c94159c0d159887578d5c3f33c7b354f68b3392a3d80b3303322ae93b2` |
| Program binary | `c1f7471c06c098d2e3a9fe2402cb6f88829f5cb7168331558a001a7fa9eeb9c1` |
| Final projection10973 | `d971317a4b17d1ef0f0967155cb412360924f1fcc165298942103e33c3f30e55` |
| Exact journal104 | `9253d67b3cc2f81f3f6f2a1c52985cbd1e4e8fa8428cdc033c308bcaa0c3a6e1` |
| Succinct receipt | `b748fbc6673e036e5769b3225189058a24d847464c59fb17738e616145ccd5c5` |
| Compressed receipt705 | `62207d40aeecde49f315b07e8155210a1895f688afd7e85662ff3b4bedab84c5` |
| Native proof128 | `77789708f4ff8e1951d23d60c9d19716e927688a7be73208dbe1c8eb8c6a309c` |
| CPU execute report | `5e3a7080077ab2b78831503432a937805833795e281d9026ae31aa9200f900b7` |
| Separate CPU receipt verification | `4b5ea7784cff4c68c05f665f7c31ced42e3788a281a27577c89c1ba062e84f37` |
| Native baseline Full report | `869ed4db6ea0fed69aa7ea3dbd7bb1ea331fb5e2db9f3e414224242e24d2bc6c` |
| Native positive +12 control result | `261de7a53d2aae52331b2f8841669b5dba07f1ab9fe2afdde909cd7e728be816` |
| Frozen verifier source40 | `c8d6e0596b0eb6e428b39ba5d5606c4991c45ff61a0514405808ce79061a6314` |

All public ingress excluded the eight original owner directories/backups and
three new party parents. After controller-private custody was introduced, it
was also excluded as a fourth new whole parent, with its metadata identities
included in the fd reader's forbidden set. No private file contents or hashes
were used in this verifier/native lane. Closed proof/VM namespaces mounted only
explicit public inputs and selected executables.

## Limits

This proves the measured implementation path can pass the selected native
validator. It does not prove cryptographic correctness, production safety,
accepted-chain admission, or financial privacy. The initial CM occupied-prefix
and ordinary input admission are supplied-context premises. Passing membership
at a16-bit position composes with that prefix invariant; the Spend circuit does
not directly constrain a public note count. Native input covenant-ID zero alone
does not distinguish None from Some(ZERO_HASH); ordinary admission remains an
explicit premise. Actual output covenant absence is enforced by
`OpOutputAuthorizingInput == -1`.

The component Groth16 setup is fresh research setup, not a production ceremony.
Spend proofs authorize financial effects and may be replaced by another valid
proof of the same statement; this is not a literal seal of all wire bytes.
The P0 prototype has one reserve input, one reserve successor, and zero native
payouts. Independent recovery and exits are not implemented by this new profile.
Privacy observer results and the multi-world cohort are separate measurements.
The measured pairing optimization lead is retained for later work; no image,
setup, financial limit, or validation check was changed for a performance pass.
