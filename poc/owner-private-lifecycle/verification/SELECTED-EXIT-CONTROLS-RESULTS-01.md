# Selected native Exit financial controls

The actual selected lifecycle tail accepted both retained genuine LOCAL direct
withdrawals (continuing Exit01 and terminal Exit09) and rejected eight financial
mutations. Every case ran through native validator `077585b8…` with Native Full
and every input script, using budget 1800. These are LOCAL supplied contexts;
they do not establish accepted backing, chain confirmation, privacy or an audit.

| Same original genuine proof, altered candidate | Native result |
| --- | --- |
| Payout destination and matching body | Groth16 verification failed |
| Payout +1 and successor reserve -1, body and outputs consistent | Groth16 verification failed |
| Fee +1 and successor reserve -1, body and outputs consistent | Groth16 verification failed |
| Current outpoint and matching body | Groth16 verification failed |
| Old NF root, matching mutable input redeem and supplied input SPK | VerifyError |
| NF predecessor sibling bit | VerifyError |
| Original Exit01 proof replayed against later Exit09 point/state/payout/NF transition | Groth16 verification failed |
| Terminal extra successor, preserving the total output value and actual fee | VerifyError |

The existing test codec recomputed upstream transaction IDs and mass before
validation. The continuing and terminal positive CASEs remained byte-identical
after normalization. All eight negatives preserved the exact original proof128
from their identified source case and the selected immutable tail. The replay
uses the earlier original proof unchanged inside the later original terminal
case; its transaction ID remains the terminal ID because the witness is excluded
from that ID. No new proof was generated.

This closes the distinction between the earlier 38 Exit negatives on synthetic
image/component identities and this exact selected tail. It adds eight bounded
financial controls; it does not broaden the privacy experiment or claim
exhaustive coverage. No financial source, profile, keys, private wallet files,
funding or broadcast changed.

Evidence: `native/selected-exit-controls-result-01/MANIFEST.json`, SHA256
`9014d03b6451478295508c876faff742568a6a24b1e5d3b14781f1f6beeffe40`
(42 payloads, 295,855 bytes). Result SHA256:
`acb90328277940d315308b09e2ae26d19420d5669db70932aa5a7a2074fb3efb`.
Additive source freeze: `native/SELECTED-EXIT-CONTROLS-SOURCE-01.json`, SHA256
`794c675fb7e32abee37181cb5407737179fdd255b1766543d4fb1d9096fb2f17`.
