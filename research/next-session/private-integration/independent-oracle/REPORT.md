# Independent authorization and primary lifecycle review

**All three separately frozen authorization cases pass exact relation,
public-update and native-body byte inspection.** Evaluation 01 inspected the
pre-proof body; evaluation 02 inspected the genuine-proof-bearing primary body;
evaluation 03 adds an accepted recipient private spend with one real input and
one canonical dummy. The stdlib oracle verifies neither Groth16 nor native
execution.
A separate read-only review below closes the six actual native reports,
physical output links and complete source-to-returned-value accounting.

The independently reviewed stdlib source SHA256 is
`2998655a8243f61da61f9de6cf6442d2069addf4ca6d67c9e97cb48c6cb0cf18`.
It was prepared and reviewed before materialized artifact evaluation. The
[freeze](PRE-RUN-FREEZE-01.json), SHA256
`6b276f9eb6f6cbf99694e3ecb9d10711e09fb261636c516a316ee3481a6ccb72`,
closes 12 source/contract snapshot members and the producer cases SHA256
`59e54ee73ae4eed175b5e9c9c4d6796156ba3f06e71a3c58276a8c3a8808f7a2`.
The [first result](RESULT-01.json), SHA256
`3ec73436fcb65f33eaab0e5f9018df26aa43639d142214d33b9a0327b840495c`,
records no rerun or repaired artifact.

The case consumes both original Alice notes and creates the two actual 10-KAS
recipient notes. The oracle independently verifies exact Auth484/State112/
Note168 encodings, s+k/O/K/positioned-HMAC authority, current raw-CM membership,
bounded value conservation, ciphertext binding, all 3,344 sequential NF/CM
update-witness bytes and both little-endian 128-bit public limbs. It also reads
the actual source-pinned native serde transaction and supplied UTXO context,
checks outpoint/amount/fee/payload/witness metadata, hashes the executing redeem
with standard BLAKE2b-256 and reconstructs the exact immutable successor P2SH
with only its State112 replaced.

Actual transaction SHA256:
`95aa6c19605293aa5dbf08bf8c7f2a47b05a17388101783bed2d003309d9fa19`.
Supplied context SHA256:
`7d9a345457b2f5960d2f6c05071624563a857d5f0cc2e1a672266a264cb11ac1`.
Auth SHA256:
`f686cf1ce6d66f7a5c65a04890b0dcadbf293eb35b9fd9c33962e508269c318a`.

There is no candidate implementation import, Groth16 verifier, native engine,
wallet RPC or old workflow in this evaluator. V1 transaction IDs use BLAKE3,
which hashlib does not supply; no independent transaction-ID rehash is claimed.
The complete accepted genesis/current-head/archive inputs remain external.

Runtime used one stdlib thread with a 1 GiB address-space limit. Code-body wall
time was 0.000919 seconds. The raw process resource counter reports
ru_maxrss=1,950,208 KiB, also seen in the tool-hosted privacy inspection; it cannot
be interpreted as a qualified wallet peak or evidence of memory-target
compliance. No hardware/performance qualification follows from this short
conformance run. No child process or continuing job was started.

## Genuine body: separate frozen evaluation 02

The [second freeze](PRE-RUN-FREEZE-02.json), SHA256
`b3b5579dfe279dec7ff2f284c008d29c508f859bd631e1106b55704f41253e9d`,
uses the identical reviewed evaluator and 12 source snapshot pins. Only the new
producer case and actual proof-bearing transaction are separately selected.
Case SHA256:
`5148f00dcbd8b469c844261a73fbc2a3f9dc6ec564de4a9c63871afa10879754`.
The old placeholder case and result remain unchanged.

The [second result](RESULT-02.json), SHA256
`998f64f34a719d7b0aceafa321c97b41a05bc3987aac038474c53d712be1ca2b`,
passes the same exact relation, all public update witnesses and actual immutable
P2SH checks. Its native transaction SHA256 is
`71e11b27bd21cde4abd7e839c78ccd3c742dac7c168ea7818cb0e2cb26261949`.
The supplied context, Auth digest and both public limbs are unchanged. The
producer stage is GENUINE_NATIVE_VALIDATED; the evaluator requires a nonzero
128-byte proof but does not treat that requirement as proof verification.
All 12 source members and the selected case were rehashed after evaluation.
Code-body wall time was 0.000925 seconds; the same unqualified resource-counter
limitation applies. No native/proof semantics were rerun by this reviewer.

## Complete primary artifact closure

The [primary result](../lifecycle/execution-01/RESULTS.json), SHA256
`ab9ab27688ba762551900343add9e3a9e7b0a46c081ad476e5fc6b5099b9c50f`,
was compared with all six actual Full reports and every input engine. Each
accepts with isolation PASS. The six previous-output edges match the actual
earlier transaction's outpoint, amount and script: preparation→founding,
preparation→ADMIT, founding→ADMIT, ADMIT→private, private→Bob reveal and
Bob reveal→Charlie terminal reveal. Seven consumed outpoints are distinct.
The first three operations reside in prefix-01 and were reused without another
native run; the remaining three reside in execution-01.

| Operation | Actual fee, sompi | Mining mass | Input-engine units |
| --- | ---: | ---: | --- |
| Funding preparation | 911,400 | 9,114 | 100,001 |
| Founding | 2,574,600 | 25,746 | 100,001 |
| ADMIT | 4,850,400 | 48,504 | 150,289;100,001 |
| Genuine private | 18,751,400 | 187,514 | 14,947,779 |
| Bob reveal | 4,973,800 | 49,738 | 263,929 |
| Charlie terminal reveal | 4,963,200 | 49,632 | 173,874 |

Each actual fee equals supplied inputs minus actual outputs, its Full result
and metrics, and100 times mining mass. The single external 4B source leaves
four native returns totaling 3,962,975,200; the difference is exactly 37,024,800.
Both original Alice notes, 60M and1,958,751,400, are genuinely consumed to create
two 1B recipient notes with no payer tail. Bob receives 995,026,200 and Charlie
995,036,800 after their own revealing-exit fees. Shared prefix fees 27,087,800
allocate 13,543,900 to each; complete individual burdens are 18,517,700 and
18,507,100. The favorable two-useful-payment context is explicit; this does not
qualify a recipient-plus-change route or unpriced service/retry costs.

All four historical positioned NFs were independently recomputed from original
backup seed material, raw Note168 commitments and positions. They exactly match
the final five-entry NF set including its sentinel. Historical CMs remain;
all four positive liabilities are spent, all three owners report zero remaining
owned value, and terminal reserve is zero. Both revealing payouts use the exact
note-committed native key. This is a complete finite supplied-context artifact
review, not an independent replay of the implementation.

The actual execution wrappers isolate network, PID and mount namespaces and
check PK/prover paths absent before any reveal authorization. Only lifecycle
data, frozen assembler/receiver, native emitter and crypto bridge are mounted.
This independently checked filesystem boundary is narrower than stopping or
removing the complete public history/current-state oracles.

Canonical accepted founding/source UTXOs, current head and complete public
archive remain external oracles. No testnet broadcast/payout, durable network
recovery, cryptographic audit or financial-privacy qualification follows.
The genuine private proof's cold process was measured separately at 198.12s wall,
646.28 CPU seconds and 5.41 GiB peak including PK loading: the 4 GiB wallet target
was missed and no R8 qualification is claimed.

The separate native control run has seven positive accepts and 56 negative
rejects. Its original typed expectation score is 60/63 and exit 1 is retained:
three invalid-signature cases returned EvalFalse rather than predicted NullFail.
See the [adversarial review](../ADVERSARIAL-GATES.md) for source diagnosis and
the exact current-spent/capacity controls. This is not a retuned all-pass score.

## Genuine competing spend: separate frozen evaluation 03

Two fresh proofs under the same selected key bind distinct alternative Auths:
A privately consumes the original Bob note before revealing; B proves private
ownership after the actual main Bob reveal. The reviewed prover's exact fixture,
Auth484, returned proof128, VK328 and native-vector bytes close for both. B's
ownership proof is genuinely host-verified even though the current native NF
update is intentionally invalid. These are hypothetical branches separate from
the six-operation primary trace and its economics.

The [separate native result](../native/fork-runtime-01/evaluation/RESULTS.json),
SHA256 `b878ee34ef075b67b9ec23834962c06324c7874d2fd3ffdfaeda531eaa5ea54a`,
matches all three typed outcomes: A accepts; an old-Bob reveal against A's actual
output rejects VerifyError; B's genuine private proof against the main Bob-reveal
output rejects VerifyError. Their CURRENT NF paths and the losing reveal's
current CM path were independently recomputed before that run. Each loser
authenticates the same original positioned NF as an occupied current leaf.
All 112 native freeze members were rehashed afterward, with raw reports equal
to their result rows. No native or proof run was repeated by this reviewer.

The new A case SHA256 is
`1bbc856a75e32a130747b5ddce0c2c57d83e019d83a5bbddbcf31880dea5cd62`.
The [third freeze](PRE-RUN-FREEZE-03.json), SHA256
`fb20e1feba54b5d5c55d3de9aa2098c2c0577c7cb8d679c104586ea92460270a`,
pins 13 source members and the new case before evaluation. The
[third result](RESULT-03.json), SHA256
`2fc6372f477476f0c08f340d46418b8dcbf35f4372d55b937f76d1f2e9e729cc`,
passes real authority, canonical dummy derivation, all 3,344 public update bytes,
conservation, actual native metadata and immutable P2SH. Body SHA256 is
`ab29c68e439d07835fdefc103a530c096b0081963257fbc91c570714646904a2`;
context SHA256 is
`874e9e2f39d90755df54043f78326b3e9f6dd71472ab8d63219e36b88da2083d`.
Auth SHA256 is
`673c8340ef3f765ee35408d9433922c2b474c638406cbb269c11c9a414c92746`.

The producer case refers to retained constructor01 copies. Their complete bytes
were checked identical to the actual frozen and validated02 body/context, and
both path aliases are pinned explicitly. All source, case and alias pins still
match after the single evaluation. Code-body wall was 0.000990s with the same
one-thread/1 GiB cap and unqualified inherited resource-counter limitation.
No genuine proof or native verification is performed by this oracle.

The two genuine alternative proof processes still peak above 4 GiB. Their
approximately 24s prove-plus-library-check phases follow approximately 159s
loading; different fixtures/concurrency prevent a matched speedup inference.
No R8, accepted chain, network recovery or financial-privacy qualification
follows from these additional branches.
