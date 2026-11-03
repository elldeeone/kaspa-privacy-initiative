# Run 01 stopped before the 29 witness checks

**The first run produced no witness and performed zero R1CS checks.** Its
symbol-file audit exceeded Node's maximum single-string length. This is a
retained harness failure, not an accepted/rejected cryptographic test result.
The original sources, selectors and tmpfs run remain unchanged.

Both ordinary and official assertion-disabled C++ compilations succeeded with
1,163,533 constraints, 1,146,261 wires, 2,091 public inputs and zero public
outputs. Standard `make -j2` succeeded without generated-code patches or
`NDEBUG`. Their complete R1CS files were byte-identical: 258,572,020 bytes,
SHA256 `aa806976b76b1417613d56010f41710ba735203e18cad7c04c0a15e1503131d6`.
This establishes compilation and relation identity, not witness satisfaction.

The actual `.sym` was 645,386,729 bytes. Before witness generation, Root
prospectively selected a separate driver changing only the subprocess read cap
from 512 MiB to 1 GiB; the original frozen driver was preserved. The larger
buffer admitted the file, but `raw.toString().split(...)` then exceeded Node's
`0x1fffffe8` character limit. The run stopped and retained
[STOP-RECORD.json](run-01-public/STOP-RECORD.json), SHA256
`77ce5f28a44e4db21e98e70d790e6f97c4715978b1ed52661bc335eef150a01b`.
No negative expectation was reclassified as passing.

The generated 29 case inputs remain selected by
`da00ccd3471b15f3531aafb8069f3d5164ff673adfd94a37e88d418871974d57`;
the five compiled artifacts by
`99d1079afb8bc9b2344a41b67d8afdd1a794594514b839c499f427592d7f8413`.
Small exact evidence copies are pinned in
[the run01 evidence closure](run-01-public/EVIDENCE-CLOSURE-01.json), SHA256
`24046590d69a49c40e81ab4278a91eef6913e7914c9910fbd79c70352230c699`.
Large builds, symbols and original logs remain in volatile tmpfs.

Recorded executable phases consumed 244.01 CPU seconds. The highest GNUtime
process RSS was 5,409,440 KiB during ordinary compilation; observed scratch
was about 1.219 GB. The per-phase sampler inspected children of every process
thread; sampled summed RSS can double-count shared pages and miss short-lived
processes. GNUtime completed-child CPU and process RSS are separate metrics,
not a hard physical-memory sandbox.

The proposed next run changes the symbol reader to decode one LF-delimited
row at a time, preserving every audit condition. Its small parser controls
passed 23/23, including old/new equivalence and the whole-buffer-conversion
failure control. A separately selected fresh run02 may reuse exact copies of
the same cases, handoff and compiled artifacts. No reprepare, recompilation,
rekey or changed 29-case criterion is needed. No run02 witness/check result is
asserted here.

The public fixture and plaintext constructor reveal the full owner/NF/tuple
map. No setup, proving key, Groth16 proof, MPC, native transaction/profile/state,
recovery operation or actual Original was used. Current native 1NF→2CM grouping,
active-retry failures and the frozen 2% fee failure remain unchanged.
