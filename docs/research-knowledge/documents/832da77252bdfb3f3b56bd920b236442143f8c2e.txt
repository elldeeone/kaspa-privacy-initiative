# Two v6 proofs: measured nonsettling result

**Two genuine v6 wallet proofs were verified in one RISC Zero guest, proved on
an RTX 3070, compressed without re-execution, and accepted by both relevant
pinned Kaspa native proof opcodes.** The inner proofs use the unchanged v6
relation under a separately identified public, single-party test setup.

This establishes a practical proof-compatibility path. It supplies no accepted
anchor, current nullifier-state transition, native backing, reserve movement,
independent exit, live transaction admission, or privacy result. The original
rehearsal still has no retained compatible pair; this fresh instance does not
replace it.

| Boundary | Measured result |
| --- | --- |
| Public statement | Exactly two proofs; input 2,846 B, public P 1,088 B, journal J 42 B |
| Guest image | `50ceec8ebb91edd01028c4aec9b495e7d77eb9e3b39e065910c0600f7693d832` |
| Guest execution | 77,129,798 user cycles; 169 segments; 1.5425 s executor |
| Guest rejection controls | All nine precise expected rejections passed |
| Genuine Succinct proving | 299.604 s; 88,211,456 total cycles |
| Succinct receipt | 223,310 B; SHA-256 `51a2f69e9986179696141ef106401109a3c7bf58fe87c8b0a645e29c49c4a3ec` |
| Same-receipt Groth16 compression | 4.448 s; no guest re-execution |
| Groth16 receipt | 581 B; SHA-256 `7ace0642e77fadacf9bc704e7500a97f2c8ea6a0b81a043ae5049eefbd1b97ff` |
| Source and compressed claim | Identical digest `7e5bed968ae55ede2c88edb1021b5bb718d8785061d8df761050badd2210b2e3` |
| Actual native 0x21 predicate | 222,668 B seal; 223,075 B script; 25,000,001 units; eight controls passed |
| Actual native 0x20 predicate | Standard canonical 128 B proof; 728 B script; 15,500,001 units; seven controls passed |

Native predicate results came from a separate harness executing the pinned
Kaspa script engine, not from relabeling SDK verification. They are bare
predicate measurements, not complete transaction mass/fees or admission. The
pinned engine's compute-budget rule includes its explicit free remainder;
rounded script grams and committed transaction budgets remain separate units.

The SDK Groth16 seal is 256 bytes. The native harness uses the established
canonical conversion to 128 bytes, never truncation. The fixed native wrapper
VK is 424 bytes, SHA-256
`78886245c5d55b850f2ac26af823802cd128eb4a43d6c52c8a62af46d54306a4`.
Its setup is the existing authenticated RISC Zero component, separate from
the fresh test-only inner wallet setup.

## Verification and resource evidence

The ordinary fully checked gate and optimized compiled gate produced identical
P/J on the genuine pair. Altered authorizations reached actual pairing rejection
in both paths; malformed and identity proofs failed. Fourteen shared-core tests
and three host tests passed under the host's pinned dependency graph. A separate
agent reran the focused equivalence test and independently reconstructed P/J.

The selected image, source, locks, exact static key and successful host key
preflight were frozen before guest execution. The optimized guest avoids
repeating subgroup validation of its immutable prevalidated key; submitted
proofs retain checked canonical/subgroup/nonidentity verification. No generic
caller-supplied key path became unchecked.

Independent CPU verification checked the saved Succinct receipt, successful
claim, selected image, exact J, no assumptions, decoded official join control
and allowed-root inclusion, plus wrong image/journal/seal/control/inclusion
controls. The compressed verification-only CLI checks the identical source
claim and matching complete P, plus its own corruption/fake controls. Actual
native 0x21 and 0x20 results are retained by the separate native checker.

| GPU phase | Host cgroup peak | Sampled matching-process VRAM peak | Swap |
| --- | --- | --- | --- |
| Succinct proving | 481,013,760 B | 6,096 MiB | 0 |
| Groth16 compression | 1,783,631,872 B | 5,332 MiB | 0 |

GPU sampling was nominally every 0.5 s and can miss brief peaks. GPU memory was
attributed to matching owned unit PID/start identities. Cgroup RAM is charged
memory, not a general cold-cache machine-memory requirement. External caps were
8 CPU equivalents / 10 GiB for proving and 8 CPU equivalents / 14 GiB for
compression, with no swap and a 60-minute wall deadline. Both units stopped;
all observed process identities disappeared and the GPU returned to idle.

The first compression attempt stopped after 1.17 s because the clean environment
omitted HOME, which Rzup requires before reading RISC0_HOME. It returned no
candidate and was not an OOM or a cryptographic rejection. Its logs and cleanup
remain preserved. A fresh attempt forwarded the unchanged user HOME and kept
the same receipt, claim checks and authenticated read-only parameters.

See [build freeze](evidence/build-freeze.json),
[guest qualification](evidence/execution-qualification.json),
[host equivalence](evidence/host-equivalence.json),
[Succinct packet](evidence/succinct-receipt/manifest.json), and
[compressed packet](evidence/groth16-receipt/manifest.json).
