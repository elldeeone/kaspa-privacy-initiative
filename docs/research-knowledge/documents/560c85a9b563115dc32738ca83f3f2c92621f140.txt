# Independent initial-four-proof public math oracle

This directory freezes finite arithmetic expectations and independently derives
public roots, pair bytes and state-assertion bytes from the separately published
initial four development fixtures. It is **not a ledger replayer or owner tool**.
The public replay/owner CLI and withdrawal-proof workflow are permanently parked
for this run after automatic tool-safety rejection. Nothing here substitutes for
their missing evidence or establishes a completed owner lifecycle.

The scalar plan preserves pool input `1740000000 = 1500000000 + 240000000` sompi.
The last two owner-exit rows are arithmetic only. The actual permitted fixture
sequence ends at `(n,m,R) = (9,6,1580000000)`, after genesis `(1,0,800000000)`,
bootstrap `(3,2,760000000)` and admission `(5,2,1660000000)`.

## Frozen inputs and source

| File | SHA-256 |
| --- | --- |
| `freeze_plan.py` | `2d2fd25be928b13425e1b5f2c311b42b48e8b392e0dffd4d5a0bb89666542c3f` |
| `frozen/parameter-independent-plan.json` | `2b2fa60ad7211e9233f0a85cb514bcc59f53935944f112aa8c6be143a66e2c9f` |
| `frozen/parameter-independent-vectors.json` | `8c337963cf38c180d2b77d1be807a96f744fcb57ba3e9012a57cf48212366620` |
| `initial_four_public_oracle.py` | `62a8343ae57e3aca17ea4e70a1e29ebae68a664e8c35021f50c2d926f27102af` |
| `check_public_preparation.py` | `a3c4ab2cdcf7ddae374380282efa2e76edb5649299c80ec6c55fe1c66d2ff0fb` |

The 14 plan entries are frozen expectations, not 14 independently executed
native or cryptographic tests. The plan's scalar/comparator/multiplicity checks
and the oracle's small public arithmetic self-check passed before any actual
fresh fixture check. A second source reviewer found no wire/tree mismatch.
Actual fixture qualification remains pending until its report exists.

The separate `public-preparation-check/report.json` now records agreement for
the prepared named public constants, ownership metadata, four value equalities,
genesis and pre-pair CM/NF/history trees. Its SHA-256 is
`e23e9fcd3d868893f7fbe0cb0a441c179e87c14b5622d383363e01ce4abc33b3`.
The genesis/pre-pair S105 hashes are respectively
`917f70f10b6af9f762be91673923ad1bd410fd5940148efe1368c0bf3943e236`
and `c282d73547faa9e31d92e8f40fb7537898e81cf1146b9fc1eddbc30545d6e2b0`;
a second independent public-tree recount agrees. This early check uses no VK
or generated bundle and does not qualify their later cryptographic validity.

`public-profile-check/oracle-result.json`, SHA-256
`e2dcc8d4f9f09dec06194aebf760d0971952b672ccd09353b9d4d80149a18658`,
subsequently checks the published 328-byte VK identity against the early
verification profile and independently derived domain/pool labels. The VK hash
is `28ae722b8a01773a8abdef4825b32af1b03c1ee9498b75b9516419a947010e28`.
It performs no curve/subgroup or proof-validity check.

`public-initial-four-check/oracle-result.json`, SHA-256
`773f81a5a21c1b051aeeba832c38f091e5a78a6c20658d0901528d08cc258fc2`,
then passes the unchanged oracle against all four published bundle JSON/binary
pairs and the initial-proof manifest. The derived public bytes are:

| Output | Bytes | SHA-256 |
| --- | ---: | --- |
| `expected-public.bin` | 1,088 | `70d89b257a6ec611db4775b4c8b0c0db2372cf8f75d084325be89d7d455c6cca` |
| `expected-pair-input.bin` | 2,846 | `2822ce58c2527f48183fad3593b4147c4821f903da6752d57fb293cb1f5648e4` |
| `expected-next-state.bin` | 105 | `be1ee2536445d5b5548fe032de533aa653db8cb7243879c3c289fbbccca6f6b5` |

Actual raw-lex NF order differs from numeric-LE order. The record positions 5–8
map to original bundle slots 3,1,2,0. The recomputed count-7 root is
`5c719f7876e16adb3b3a278fdc2511afb40323e0d857e7d51cb1d7a52230ffba`,
and its membership under the final declared history root checks. These remain
public byte/tree checks, without Groth16 or native validity claims.

The fresh genuine pair's common inner anchor is **count 5**, the current prior
commitment root. Its state guest input's anchor-history path also checks count
5. The report field `historical_count7_membership_checked` means only that the
oracle constructed and folded the count-7 CM-prefix membership path under the
next history root. No genuine inner or owner proof using count 7 has run; the
owner workflow remains parked. The older count-3-anchor/historical-n5 guest
receipt is separate evidence under its earlier instance and image.

The selected native predecessor tuple is now independently bound to the public
ADMIT fields/rest preimage/ID hash as described in `OUTPOINT-BYTE-ORDER.md`.
`public-actual-pair-context-check/oracle-result.json`, SHA-256
`97e5bdd277bfa4c12b979436d52c6dcd78e6201a6961b66215fcf329fcfa28ab`,
freezes `expected-journal.bin` (336 bytes), SHA-256
`699697f07565d28faad6e45b9e6daa0a09dbcea3f475d51880a75289f7e49b57`,
and `expected-state-input.bin` (11,219 bytes), SHA-256
`eab451e4701d2fa65c5a5a2cf23a0d1c9483723951c0382989c8e0e9decfaa39`.
Both were delivered before the corresponding selected paired guest/proof run;
the journal matches the second independent tree/J recount. The oracle itself
continues to report native context authentication as false.

## Scope and outputs

The stdlib-only oracle opens a fixed allowlist of named files directly inside a
directory named `public`. It does not enumerate directories or read wallets,
note openings, producer plans, proving keys, funding bodies or ledgers. Public
verification-key bytes are checked for length and identity; curve/subgroup and
Groth16 checks belong to the independent verifier lane.

For the four published bundles it checks exact 875-byte framing and declared
authorization fields, independently constructs tagged SHA-256 commitment,
history and indexed-nullifier trees, and rebuilds numeric-LE nullifier links
from physical insertion order. The pair uses raw-byte ordering for its four
nullifiers and four complete 217-byte records, retaining duplicate-record
multiplicity. Appended commitment positions are 5–8; count 7 is a commitment
prefix in declared history, not a separately accepted native UTXO state.

Outputs include exact `P[1088]`, pair input `[2846]`, prior/next `S7[105]` and
intermediate roots. An optional caller-supplied public tuple contains only
`prior_outpoint_hex` (raw ID32 plus u32le index) and `reserve_sompi` (canonical
decimal string `1660000000`). With that tuple the oracle also constructs
`J[336]` and state input `[11219]`; it does not authenticate the native tuple.

Every report records opened public-file hashes and the oracle source hash.
Output directories must be new. Mismatches and missing artifacts are retained;
cases or fixture seeds must not be tuned to remove them.

## Commands

Run from this directory, with an explicit published public directory and a new
output directory. These commands perform byte/hash/tree arithmetic only.

```sh
python3 freeze_plan.py frozen --check
python3 initial_four_public_oracle.py --self-check
PYTHONDONTWRITEBYTECODE=1 python3 check_public_preparation.py --public-dir /absolute/path/public --output /absolute/path/new-preparation-check
python3 initial_four_public_oracle.py --public-dir /absolute/path/public --profile-only --output /absolute/path/new-profile-check
python3 initial_four_public_oracle.py --public-dir /absolute/path/public --output /absolute/path/new-initial-four-check
python3 initial_four_public_oracle.py --public-dir /absolute/path/public --pair-context /absolute/path/public-pair-context.json --output /absolute/path/new-pair-context-check
```

No setup, proving, Rust/SDK/Gate import, native validation, funding, broadcast,
chain acceptance, public replay, owner CLI or withdrawal workflow is performed.
Public math agreement does not establish private-opening correctness, proof
validity, backing, accepted lineage, independent exits or useful privacy.
