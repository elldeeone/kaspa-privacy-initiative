# Selected compressed loader: closed result

The source-reviewed trusted loader accepted exactly the selected new
development PK and matched the fully checked fixed native-compatible VK.
It took **156.38 seconds to load**, of which **155.27 seconds were compressed
decoding**. Skipping repeated validity checks did not remove the source-
predicted sequential square-root/decompression bottleneck.

| Measured phase | Wall seconds |
| --- | ---: |
| Read owned 1,006,401,200-byte PK | 0.619318 |
| Authenticate entire owned buffer with compiled SHA256 | 0.424887 |
| Official compressed unchecked decode | 155.266061 |
| Drop encoded buffer | 0.063561 |
| Original checked VK extraction and exact comparison | 0.000586 |
| Entire selected PK load | 156.376393 |
| Whole loader process | 156.50 |

External accounting recorded 155.01 user CPU seconds, 1.46 system CPU
seconds, 2,953,192 KiB maximum RSS (2.82 GiB), and zero swaps. The 0.5-second
cgroup sampler observed a 3,041,153,024-byte memory high-water mark. This
cgroup measurement and process RSS are different accounting quantities.
The unit finished successfully, became inactive/dead with MainPID0, and
its owned cgroup was absent/empty. No proof or setup was run in this stage.

This was one loader-only measurement on a recently used key, with
uncontrolled OS page-cache state. The 198.12-second checked baseline
includes proving and has no load/prove phase split. These are not matched
end-to-end timings; a total speedup, cold-cache performance, p95 or R8 pass
cannot be inferred. No four-core or 4 GiB whole-wallet qualification was
attempted. An uncompressed cache remains an unselected later option.

The exact result is [report.json](loader-01/report.json), SHA256
`dc4bd9e384c79a41f0721cb59785fd6f77d4b682fc8974b5bd6dc0dfa739dd2a`.
[Cleanup](loader-01/cleanup.json) SHA256 is
`5f2bd69e2a2b4af288c2cef8298809e29948b61ee20664ee461be9f703b6ed63`.
See also [external time](loader-01/resources.log),
[samples](loader-01/cgroup-samples.jsonl),
[start](loader-01/start.json) and
[runtime freeze](loader-01/runtime-freeze.json).

The separate CLI built offline and passed all six tiny authentication and
fixture-format tests before any full-key load. Source review checked the
private owned-buffer constructor, complete SHA before the only unchecked
decoder, full consumption, buffer drop, and unchanged checked VK/proof
boundary. A second source review checked read-only mounts, resource
accounting and cleanup. The prelaunch controller was revised to stop its
owned unit on monitor error/interruption; the unused earlier controller and
freeze remain byte-identically archived in
[prelaunch-runner-01](loader-01/prelaunch-runner-01/ARCHIVE.json).

Production payment library/circuit and baseline were not changed. The
frozen selected prover was handed to the lifecycle owner, who owns any
subsequent fork proofs and their artifacts. Those outcomes are outside this
loader-only packet.
