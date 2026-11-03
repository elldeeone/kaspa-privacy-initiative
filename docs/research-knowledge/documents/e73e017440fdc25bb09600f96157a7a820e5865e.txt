# Genuine competing paths: actual native result

**3/3 exact typed expectations matched in one frozen native run.**
Freeze `dde66f751aa383057a186f7fb659f4c440467246b615c5ca7e6e50f7be9a53c0`
closed112 source/proof/context/body members before execution. Both new private
proofs were genuinely host-verified for their exact Auth under the same new VK.

| Case | Official Full | Input engine | Units |
| --- | --- | --- | ---: |
| A: Bob privately consumes original note, one real plus one dummy | ACCEPT, fee18,751,400 | ACCEPT | 14,947,907 |
| Original Bob reveal after A, with current CM membership/current authenticated occupied NF | REJECT | `VerifyError` | 58,313 |
| B: genuinely verified private proof after the actual main Bob reveal | REJECT | `VerifyError` | 51,483 |

Both rejects returned Full `SignatureInvalid(VerifyError)`. They fail at current
spentness before native signature/Groth16 verification. Independent pre-run
review recomputed all three current NF predecessor authentications: A has an
absent interval, while both losing paths contain the exact original positioned
Bob NF as a current occupied equality. The losing reveal has the correct
original native signer and current CM path; B's proof genuinely verifies this
changed Auth. These controls therefore exercise the common native spentness
guard rather than an old root, a different marker, invalid proof or wrong key.

Actual machine results are in
[`fork-runtime-01/evaluation/RESULTS.json`](fork-runtime-01/evaluation/RESULTS.json).
Accepted A's exact frozen body/context are in
[`fork-prepared-02/bodies/genuine-A-private-before-reveal`](fork-prepared-02/bodies/genuine-A-private-before-reveal/transaction.json).
They are available for the lifecycle owner's separate positive independent
oracle packet. The original primary sequence and its fee denominator are
unchanged; these are alternate synthetic branches.

The run used0.085s wall,0.079CPU-seconds,23.3MiB peak, swap0. Unit
`kpi-future-native-genuine-forks-01.service` is inactive/dead/MainPID0.
No setup/proof was repeated here; no network, funding or broadcast occurred.

Authorization followed the existing root instruction to run the three paired
native controls after the successful loader/proof gates and independent exact
fixture review. Root was temporarily at model capacity when the final review
arrived; no new exact-root-freeze ACK is invented. The independent reviewer and
lifecycle owner independently confirmed that existing authorization explicitly
covered this stage. All source/fixture and actual verdict bytes are retained.

These are supplied-context native results. Accepted genesis/backing, canonical
chain history, data availability, privacy and production security remain
separate obligations. The earlier63-case run retains its original60/63 typed
score and three signature-error prediction mistakes; these three successful
cases do not replace or repair that result.
