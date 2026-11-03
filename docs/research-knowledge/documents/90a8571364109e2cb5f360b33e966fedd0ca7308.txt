# Uncompressed selected development parameters: closed

The new cache-backed prover completed a genuine proof and full fixed-VK
verification in **30.87 seconds**, including **5.88 seconds loading** and
**24.60 seconds proving plus the original library's verification**. It used
a six-CPU quota alongside the trial suite build. The payment circuit,
relation, domain, original parameters and native-compatible VK did not change.

| Stage | Result | Wall | Maximum process RSS |
| --- | --- | ---: | ---: |
| One compressed-to-uncompressed conversion | Pass | 161.40s | 2,951,752 KiB |
| Selected uncompressed loader only, 14-CPU quota | Pass | 6.07s | 3,935,908 KiB |
| One genuine cache-backed proof, 6-CPU quota | Pass | 30.87s | 5,648,204 KiB |

All stages used zero swap, finished successfully and retained inactive/dead,
MainPID0 and empty/absent owned-cgroup cleanup. The source-reviewed exception
guard stops the owned unit if monitoring fails. No native transaction or
setup was generated in this packet.

The one loader-only measurement separated 1.589s reading, 0.899s complete
SHA256, 3.263s official uncompressed decoding and 0.140s encoded-buffer
release, totaling 5.894s. The prior selected compressed loader took 156.376s,
including 155.266s decoding. This recent-cache comparison supports the
source-predicted removal of compressed-point reconstruction. Cache state
was not controlled and only one observation of each was collected; it is
not a cold-cache benchmark, p95 or universal speedup claim.

The prior fully checked baseline took 198.12s including loading and proving
under a different CPU cap. Its timer did not split those phases. Comparing
that total directly with 30.87s does not isolate a single causal speedup.
The cache-backed proof's 24.60s proof phase includes its internal checked
verification, followed by a separately timed 0.00374s checked fixed-VK
verification. The original strict proof/VK decoding remains unchanged.

The six-CPU genuine run peaked at approximately **5.39 GiB RSS**, exceeding
the 4 GiB wallet target; warm proving also exceeded the 10s target. No R8,
four-core laptop, p95 or whole-wallet qualification is claimed. The parent
deferred another four-core proof to prioritize the actual testnet trial.

The cache is exactly 2,012,802,352 bytes, SHA256
`0b8111335d56a0b14c66f263e081fae3f5453f69ae7764edc903b7e4af972ae8`.
Root independently hashed the complete artifact and its provenance before
[selecting it](ROOT-CACHE-SELECTION.json). Only the compiled cache-identity
data changed between preserved build01 and selected build02. Two independent
source reviewers ACKed conversion and the private same-owned-buffer full-hash
boundary; the selected-identity delta was separately ACKed. Nine unique tiny
test functions passed, with five common tests also run in the converter.

The [genuine proof report](proof-01/report.json) has SHA256
`d95e7b2221e79810d66942a852602a258bc895c2d246fae8d943c8f69994605e`.
The [proof128](proof-01/proof128.bin) SHA256 is
`6f34ce32919e2118dd43a9db8f0d20951d126c974167634dbbd886854fe61b8a`.
It binds the same primary Authorization484 and fixed VK as the completed
synthetic lifecycle. This packet's checks are host cryptographic verification;
they do not rerun the native engine, authenticate chain backing or establish
privacy or parameter-ceremony safety.

For a fresh trial, the setup owner can use the official uncompressed
serializer directly while its newly generated PK remains resident. That
avoids this development experiment's one-time 156.83s original compressed
decode. The old development key/cache must not be reused for a new domain.
