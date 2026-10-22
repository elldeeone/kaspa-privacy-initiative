# Independent saved-pair receipt verification and cleanup

Result: the saved genuine succinct receipt passes an independent invocation of
the existing frozen software verifier against the previously selected image,
exact 42-byte journal and JOIN control. Native settlement is not authorized.

| Artifact | Checked identity |
|---|---|
| Receipt | 223,310 bytes; SHA-256 `51a2f69e9986179696141ef106401109a3c7bf58fe87c8b0a645e29c49c4a3ec` |
| Frozen verifier | SHA-256 `cc0ecde6994f8a4f48b9a3d2177c61476acd24ddff0d37ba8bca8c0e592da0d9` |
| Expected image | `50ceec8ebb91edd01028c4aec9b495e7d77eb9e3b39e065910c0600f7693d832` |
| Expected JOIN | `7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e` |
| P / J SHA-256 | `9ac720aa55e7bd6eaec674788d418aa3314bc7af1010b7c9f09a493d9aa76ce9` / `5d667b709f35191c6fc98e6aa0b79bd934e39a40ef4edfea582fcef3b06d4ac7` |

The receipt is
`/home/luke/projects/kpi-intensive-2026-10-22/proof-target/two-v6-proof/receipt.bin`.
The verifier is
`/home/luke/projects/kpi-intensive-2026-10-22/proof-target/release/kpi-two-v6-binding-proof-host`.
Both were independently hashed before and after execution and remained unchanged.
The saved P/J output hashes match the earlier independent full-byte recount.

The verifier uses SDK 3.0.3 successful-claim/image/journal checks with development
mode disabled, then the official recursion STARK callback to authenticate actual
decoded seal control equality with both receipt metadata and independently
expected JOIN, plus official allowed-root inclusion. It rejects unresolved
assumptions and checks complete public P against J. Six cryptographic negative
calls passed: wrong image, two journal offsets, corrupted seal, damaged control
inclusion and wrong expected control through the actual seal verifier.

No proof was generated or binary rebuilt by this reviewer. Output is retained in
`receipt-independent-verification-01/verified.json`, with its invocation log in
`receipt-independent-verification-01.log`. The 34 frozen source/output identities
from build manifest SHA-256
`6f29772c10dbe480c988fb6cba4d14ddd4782ce319f621a11908cfda40350fce`
were independently rehashed; all matched. Details are in
`receipt-independent-verification-01/frozen-identities-rechecked.json`.

## Live cleanup check

After reviewing producer monitor artifacts, this reviewer independently queried
the live owned unit and process identities. Unit
`kpi-two-v6-gpu-proof-20261022.service` was inactive/dead, successful, MainPID 0,
with empty ControlGroup. All four monitored PID/start-time identities were gone.
At the read-only check, GPU compute-app output was empty and the instantaneous
sample was 1 MiB allocated / 0% utilization.

Evidence is retained in
`receipt-independent-verification-01/cleanup-independent.json`. No process was
terminated by this reviewer. The GPU sample is instantaneous; owned identity
and empty-cgroup checks establish cleanup of this workload independently.

This is evidence for the separately generated public development instance's
nonsettling receipt. It does not supply the missing original-instance pair,
accepted anchors/current spentness, reserve/covenant composition, native payout,
recoverability, privacy benefit or production assurance. The native opcode
predicate result remains a separate artifact produced by its owner.
