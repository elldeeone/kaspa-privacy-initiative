# Public parent-field join: scope correction and completed add-on

**Both retained recipient spends now have an explicit, separately executed public parent-field join.** Their input IDs, commitments and authorization keys match the actual corresponding outputs of the retained aggregate. Ten calibrated mismatched public-field copies reject. This add-on creates no new signatures, proofs, keys or random draws and reruns no cryptographic transaction/signature/range-proof validator.

The original103-path packet is frozen: manifest SHA`80d08a185e6590e761f814d4bfcc271bf731f8b3ab0041a48b35fce7c49e4d9f`; list SHA`a12e3ded7e70afdac97638778b71fe135eeb4bc3eb177323daba62f40ddd9b39`. All101 payloads remain byte-identical. The original recipient DESIGN stated a combined parent ID/commitment/key check, but the original fresh public verifier only called standalone Transaction::Validate and the controller compared IDs/counts. Its raw results were not an independently performed commitment/key parent join. This addendum corrects that overbroad interpretation without changing the original source, design or observations.

## What the separate run checked

Run identity: `MWEB-READ-ONLY-PUBLIC-PARENT-JOIN-01`.

The existing source-pinned inspector reads three authenticated public transactions: the aggregate and the two recipient spends. It deserializes/recomputes public object hashes and checks canonical roundtrips, without invoking owner construction, signing, proving or validation. The inspector binary SHA is`39c15d3ff27486d49f8847111493be345e13ee91e8a9b955b553dc9b10e03069`; its source remains the unchanged file already selected by the original packet. This is a local artifact identity/trusted-host premise, not executable authority supplied by a remote capsule.

For each one-input spend, the new Python join independently performs:

1. Unique lookup of the aggregate output by its computed public output ID.
2. Exact equality of input commitment with parent output commitment.
3. Exact equality of input output-authorization public key with parent receiver public key (`Ko`). The input's own ephemeral key is a different field and is not substituted for `Ko`.
4. Equality of that parent ID with the retained recipient's observed received-output ID. The two recipients consume distinct parent IDs.
5. Equality of publicly serialized total kernel fee1 with the retained fee observation.

R1 joins parent`ec7911b3ae224ca5ba5ce7fa8dec160736d82d3fa798e8de6f991d5ddce17704`.

R2 joins parent`8ffed90397fc629e9c615414696851af8534c23aa3b50a9d69cc3684a6a6124d`.

The retained amount equations10=9+1 and20=19+1 are checked as observations. Plaintext input/output amounts are hidden by the public commitments; the add-on does **not** independently derive those values from wire data or claim a new amount-opening proof.

## Calibrated negative copies

For each recipient, pure copies of the inspected fields reject when they contain:

- The original ID with the other parent's commitment.
- The original ID/commitment with the other parent's authorization key.
- The other parent ID while retaining the original commitment/key.
- All three fields from the other parent while retaining the original recipient observation.
- An ID absent from the aggregate.

These ten controls exercise the actual field-join checks. They are not signed/serialized transactions, do not invoke signature/range-proof validation, and are not presented as chain-valid attacks. The full other-parent case is rejected against the retained actor observation; that observation is supplied test evidence rather than proof of a human identity.

## Supported conclusion and limits

The correct combined claim is now: **retained standalone cryptographic transaction validation plus a separately executed explicit local public parent-field join**. The latter verifies these exact supplied parent/spend relationships; it is not the full chain UTXO validator and is not an independent cryptographic implementation.

There is still no accepted-chain backing, global current unspentness, absence of a competing spend, finalized ordering, reorg recovery, full DB-backed wallet, native KAS settlement or financial-privacy qualification. Public spent IDs and all pre-aggregation observer mappings remain visible. No original privacy thresholds or old result bytes were changed.

See [run-01/RESULTS.json](run-01/RESULTS.json), [source freeze](SOURCE-FREEZE.json), [preservation record](ORIGINAL-PACKET-PRESERVED.json) and the separate finite publication list/manifest for exact public bytes.
