# Native batch economics and owner integration review

Status: **source and selected aggregate ledger review ACK;34 recorded native
bodies and33 genuine proof records close at1.9486784375% of useful payments.**
No duplicate VM, proof, setup or network execution was performed for this review.
Source logic, public source freezes, matched-key byte result and the sanitized
selected ledger were inspected. Five new public arithmetic/mock-report controls
passed; private witnesses, backups, ownership maps and controller plans were
not opened. Rust relation/runtime source remains frozen.

The selected [client source freeze](../lifecycle/client-source-01/SOURCE-FREEZE.json)
contains byte-identical copies of every source below at this review. Any change
requires a scoped source follow-up before relying on this ACK.

| Public source | SHA256 |
| --- | --- |
| `actions.py` | `a1b725e026dc7403bbe4a3d6c1f713bf48d4e67ecdbed67facda7d6098658484` |
| `native_runtime.py` | `dac6d42987a9419864c967773677a033c143028053f33f5f6ad506739ef005af` |
| `owner.py` | `8d6a0bfedc9072039ad6a8d126af78ef2222274d8aa14b493c15968c6c2b1a49` |
| `history.py` | `b24f5712d16b75e5d1c33e6021e7f3e06e3bf180926af00f5ee01a09e1060202` |
| `prepare.py` | `d5ba604b3f18e45b0a92186702df990ff7ef5fb36063a8d52066d316ed01f916` |
| `receiver.py` | `9733a7c97baaef3b91c70766007173c41d770e6f260fb7f0bf3116ad95c0665b` |
| `run_owner.py` | `c620788d4f694ea25f4876c49a4f853d39224eef83e91501ad819796c2cc5185` |
| `primitives.py` | `184463d416a8e3c5605ce929bf2cead378c00e82d3827d30c83f8a6e19de5986` |

## Exact candidate, quote and proof substitution

`actions.assemble` uses one independently recognized owned positioned claim,
checks original unspent real NF against the replayed sparse snapshot, and builds
one real plus one fresh dummy input in privately sampled slots. Dummy HMAC uses
its actual slot; both native insertions follow Auth order. It enforces Python
integer `input = all private outputs + payout + fee`, input<=reserve<=MAX, floors,
P0 zero destination, private-output count/mode and all output commitment uniqueness.
No other-owner witness is requested. Real/dummy private output records use the
same established ciphertext format, and sparse physical positions remain intact.

The quote hash normalizes **only** bytes68..196 of the canonical private frame
(the proof) and derived transaction ID. It includes the rest of the complete
body, all canonical native context fields and fee rate. Finalization independently
normalizes the ID/storage mass, compares every remaining body/context/metric,
reproduces the quote ID, runs pinned SDK reconstruction and requires native Full,
isolation and every input engine. Replacing the whole ScriptSig in the expected
body does not permit other changes: the quote digest freezes the unchanged
signature header and full redeem program around the excluded proof bytes.

An early review found that `public_case` initially projected coinbase/covenant
flags to false/null without validating its inputs. This was fixed before main
execution: exact five context keys, canonical bounded decimal amounts/DAA and
hex SPK, false coinbase and null covenant are now required before projection.
Malformed flag/type/extra-field changes reject instead of disappearing from the
quote. Current body constructors and strict history contexts also enforce that
same canonical representation. No relation, matrix or key was changed.

`owner` authenticates descriptor/role/manifest/build/prover pins, replays provided
history, starts an empty witness FD and waits for whole-PK-authenticated READY
before reading the original own backup. It recognizes exactly one current
claim, constructs one legal candidate, obtains an exact actual minimum-fee quote,
and only then sends the witness. It does not serialize a diagnostic/sizing
candidate or clip recipient intent/change to make a quote pass. All three SDK
files join the metadata-alias guard before public byte reads, including hardlinks.

## Whole program, fees and denominator

The copied native policy is byte-identical to the previously reviewed complete
compact policy after removing only documentation lines and its fresh DOMAIN
constant. Its baseline SHA is `45a520be265cb3dfcbfb73009bbd02cb1a75f5339ab57bd5390a6d84edd4f759`;
the new copy SHA is `7e61c6060291f500fc0faa49ff3b467a9f9d6d8d1bff4d6fc52e8b87a94ba714`.
The [matched-key byte result](../lifecycle/MATCHED-KEY-BYTES-01.json) reports
actual complete redeem length **23575 bytes** with the genuine distinct
compact/wide VKs, preserving the **1600** private budget. Byte emission alone
is not a financial positive; actual matched-proof Full acceptance remains required.

At that actual length and rate100, the selected main ledger records these exact
fees. The reviewed collector requires each to equal its normalized body quote
and actual mining mass times the reference rate, including official storage mass:

| Shape | Recorded exact fee, integer sompi |
| --- | ---: |
| Wide32 P0 |19701700|
| Compact continuing payout |18867700|
| Compact terminal payout |18718200|

Every recipient's gross note is `1000000000 + 18867700 = 1018867700` sompi.
The payer's initial reserve is `32*gross + 19701700 = 32623468100`.
The first31 full cashouts therefore pay1000000000 each; the last uses the
smaller actual terminal fee and pays1000149500. **149500 is returned exit-credit
surplus, not useful payment demand and not a donated fee.** Terminal private
notes/cipher metadata are canonical inactive zeros and no CM append occurs.

The actual selected source equation is:

```text
42623726600 ordinary input
=10000000000 ordinary change
+32000149500 native payouts (includes149500 refund)
+623577100 complete fees
+0 terminal reserve
```

`623577100 / (32*1000000000) *100 = 1.9486784375%`.
The denominator remains **32000000000** useful sompi; neither gross-note fee
credits, ordinary change, dummy outputs nor the149500 refund increase it. The
old conservative149500 terminal-overpayment projection remains separately
preserved. The collector checks actual storage, selected native reports, every
withdrawal, all33 proof-normalized quotes and final sparse-state drainage.

The initializer uses **one supplied synthetic ordinary source directly in GN**;
it constructs no separate funding merge/transfer. Its258500 recorded entry
fee is included above. This does not price any extra future live funding-prep
transaction: if one is used, its actual fee must be added. Source contexts are
synthetic, not accepted-chain backing,32 humans or demonstrated market demand.

## Backing, replay and remaining boundaries

| Risk | Source finding and remaining boundary |
| --- | --- |
| Inflation | Exact nonnegative private balance, bounded values and input<=reserve in the reviewed relation; actual native reserve/payout/fee equation and whole-output equality retained. Direct CSR controls are separate evidence; source arithmetic is not proof soundness. |
| Double spend | Original positioned real NF is unchanged across roles/REVEAL; native and replay require both sequential absence/insertion witnesses. Known spent claims cannot be selected by this workflow. |
| Wrong release | Payout amount/destination and current outpoint/state/reserve are Auth-bound and checked against the actual body/context; immutable successor program contains both selected role keys. |
| Privacy leakage | No witness, owner-to-CM/index map or discarded preparation is exported by this review. Same-format padding does not prove anonymity; public modes, timing and amounts remain observer surfaces. |
| Dependency loss | Own backup is sufficient only alongside authenticated role parameters, complete public data and selected software. Mirrored local paths are not long-term independent-provider availability. |
| Reorg/stale state | History replay explicitly reports synthetic supplied-prefix validity and false currentness/accepted backing. A live spender needs separately authenticated fresh acceptance/UTXO reconciliation; no currentness is inferred from this fixture. |
| Hidden trust | Trusted host/readonly selected software and single-party development setup remain premises. Capsule-supplied authority cannot replace externally installed descriptor/program/VK/role pins. |
| Capacity | Sparse gaps remain empty and real positions are never renumbered. The bounded final CM126/NF67 route does not resolve arbitrary full-capacity private exits; no-append continuing exits remain unselected. |

## Actual selected ledger closure

The [sanitized main closure](../lifecycle/main-synthetic-01/FINANCIAL-CLOSURE.json)
has SHA256 `fe1e375517cee5159ba067338498c99e96872af413fcba1f513a321f533c2069`.
Its entry in the [finite public selection](../lifecycle/PUBLIC-SELECTION-01.json)
(SHA256 `01bc2bbb54c42aadc8d37204ab0eefad6cf307931a7a57be0673d1e9a9beac3f`)
matches its exact bytes and length. The selected aggregate contains no raw main
body, Auth, NF, transaction/quote ID, owner map, backup path or witness hash.
Selected proof/Auth hashes identify only the actually chosen public effects.

The new read-only `closure.py` collector (SHA256
`7d3fa8d489dbabb04f412b71400fb4fe2afd3ed71c8fea97f1f987fa7704397a`)
completed the actual34-record/33-result collection. Its finite inputs are public
descriptors, manifests, history, selected bodies/contexts, execution metrics and
proof reports. It does not open a controller plan, PK, backup or private witness,
and invokes no native VM, SDK, prover, setup or network operation. The collector
replays public sparse CM/NF updates, authenticates role/report/manifest matches,
matches exact selected cases, reproduces quotes and reconciles every source sompi.
Five focused [collector controls](../lifecycle/FINANCIAL-CLOSURE-CONTROLS-01.json)
cover exact fee/refund arithmetic and rejection of omitted exits, hidden source
tails, donated refunds, refund reclassification and changed recorded metrics.
These mock-report controls do not establish genuine proof/native validity.

Independent rechecking of the sanitized33 effects confirmed sequence/role/mode,
distinct opaque proof/Auth hashes, every reserve decrement,31 ordinary payouts,
the exact terminal refund,258500 entry fee, whole-source equality and the fixed
32B denominator. Final state is **R0, CM cursor126,95 delivery records,67 NFs**.
No new proof or execution was needed for this arithmetic recheck.

This is measured supplied-context integration evidence backed by the recorded
genuine owner-proof/native runs. The collector is not a cryptographic verifier
of its execution reports, and this review did not reopen raw main bodies or
independently rerun those executions. Accepted-chain backing, fresh currentness,
live payouts,32 independent humans, general privacy and production safety remain
outside this result. The same first compact owner proof also served the separate
portable-recovery experiment; it is not counted twice here.
