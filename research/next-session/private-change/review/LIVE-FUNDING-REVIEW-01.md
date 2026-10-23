# Live funding review01

Status: **final exact-body/release ACK for root's single authorized merge04 submission**.
The preflight notes below preceded the completed final review.
No signing, native execution, RPC, submission or private input reads by reviewer.

Reviewed worktree: `research/shielded-kas-feasibility` at `a8392f1127e656da59709e0b6f93ece7cf5eb9c2`.
The parent has authorized the new ordinary TN10 merge04; only the root may submit.

## Public preflight

The selected3 distinct ordinary P2PK inputs total exactly286604800 sompi:
98987400 +98987400 +88630000. All specify noncoinbase/no covenant, exact public
SPKs/outpoints and accepted DAA scores. This is review of the root's public
selection, not a new independent network observation or control-of-key claim.

The existing builder enforces TN10/genesis, decimal integer positive/range/sum
checks, unique inputs, source-key→SPK equality, valid destination x-only point,
exact sole output and zero gas/native subnet. Signatures are canonical65-byte
SIG_HASH_ALL frames and every sequence disables relative locks. Secrets enter
through stdin; result projection excludes the private-key field.

Final review must bind selected source rows to exact body and native contexts,
fresh independently supplied destination, integer fee/storage fixed point, all
3 native engines+Full, SDK ID/body identity, durable once-intent namespace and
release/source/helper pins. That initial preflight did not issue an ACK; the completed final ACK follows below.

## Public source pins

- `selected-source-UTXOs.json`: `23419149d02fb021df8e86f7ea157015f9313c64a8eefb42d8a42b95a9bfebc4`
- `poc/recovery-trial/merge.mjs`: `fe598f5958c2b3f6aee3ad1e92d2085a82e73862f45c268ef706dce0e1f3194e`
- `poc/future-native-chain/adapter.mjs`: `b4f98db493f86fbb69c81e814b4516f8868a211cdf53b7180fa2d293ef05dabf`
- `poc/future-native-chain/native_safe.py`: `c4b7c3353ba4c83b758daa24f967c922acd1abe2aad2909010924fba9fb7f736`

## Final exact-body/release ACK

**ACK: root may submit this exact ordinary fundingprep transaction once.**
No substantive source/body/release blocker found. This is not a pool spend or
financial privacy qualification; root alone performs the authorized RPC action.

Transaction `15cf578776faff6ae4da8d7030e917f4ee5bbcdb64875c10fdab85dd79814fe1`
spends exactly286604800 sompi and creates one286218200-sompi output, paying
386600 sompi. Destination exactly equals the independently pinned public bd9a
identity's ordinary funding SPK. All3 source rows, actual executed native-case
entries, public/local-check contexts and transaction outpoints match. All inputs
use canonical SIG_HASH_ALL and sequenceMAX with budget10; the body is v1/native
subnet/empty payload/zero gas-lock/storage/covenant.

The existing generic077585 native report has isolation PASS, Full accepted and
all3 exact input engines accepted. Compute/mining/relay mass3866 and storage0
reconcile to the exact fee at rate100. The lossless pinned-SDK roundtrip equals
the same native body after canonical integer conversion. No VM was repeated.

Release authorization binds only fundingprep, the exact body/local-check,
profile, source adapters/native and Vector TN10 endpoint. Submit/observe
requests bind the same release/start checkpoint/canonical fresh0700 directory.
Both durable stage/tx intent markers were absent at reviewer inspection. The
adapter rechecks actual source UTXOs, SDK body, source/release pins and identity
before creating exclusive durable markers and its sole submission.

The root's network observations remain selected-node evidence. The unchanged
legacy observation adapter does not independently prove header consensus or
atomic current-output freshness after its second delta; subsequent pool funding
must still use the actual unspent source/context check. No such qualification
is inferred from this pre-submit review. No private keys, backups, operator
profiles, witness files, PKs or signing inputs were read.

Final public input pins (raw file SHA256):

- `selected-source-UTXOs.json`: `23419149d02fb021df8e86f7ea157015f9313c64a8eefb42d8a42b95a9bfebc4`
- `public-merge.json`: `bf3aefbb65bcbc69bd742e3648b11674abf8a20acb21d25b3c85bd6e51d00dc3`
- `transaction.json`: `3dc3b4fd778274ba5ba2f48facb8259d9c4ab19d8f86bd8d05c535e8a04939f9`
- `validation-case.json`: `8ea4349c85ec769a3e4639ff6b9bf3d14aac9c24bf5a3ae22b6482c3af1b6477`
- `supplied-context.json`: `23419149d02fb021df8e86f7ea157015f9313c64a8eefb42d8a42b95a9bfebc4`
- `local-check.json`: `599c9a4a5cb99055d4a0ca2d63238fac6bd3559c816af1de799ee81c64581c7b`
- `native-01/native-validation.json`: `673463a0b857674cdc61a452d8b98a46f7bbea56c8f977de38fb5992888d9607`
- `native-01/metrics.json`: `5bff13d85b0e911ec069a203e90cab928ab9c3b75197498cb24a0b52fce3001f`
- `release.json`: `ab5623f593372b25fd461c770f9d440a2d49ef49ed64667569c613074b0897a0`
- `submit-request.json`: `d49c74a43d496fbd84d7945c9d071217906b9275551c42226621588ddc625117`
- `observe-request.json`: `183749e3c8ce7298972bd7ab6f9f1daa0257ba561bfad760b21adbdd341cd0ea`
- `roundtrip.json`: `0b73706244748086b2197902b0cc8ec4ebbe00900b0b63fa403e7fd7cebd76c4`
- `checkpoint.json`: `b0ae3743f94f155c84e41a77daa605654e1240ba65f0f0acd1e40a79d3e7103c`
- `PUBLIC-IDENTITY.json`: `3669f0aab7d6cd4db661d848d26ed2c741523b7e1fbe7955cf9a0192f73bf37d`
