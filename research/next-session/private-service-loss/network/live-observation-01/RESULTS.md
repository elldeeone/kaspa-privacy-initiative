# First fresh Auth528 network observation

The reviewed public-only client independently discovered the live pool prefix
from the authenticated descriptor and birth anchor. It received no operator
archive/tree/profile, rehearsal body/proof, owner backup, parameter blob, prover
or precomputed exit. Only the dedicated initially empty `client-output` subtree
was writable/mounted; controller confirmation metadata remained outside it.

The unchanged bundle is
[`client-output/network-data/fetch.json`](client-output/network-data/fetch.json),
SHA256 `72174443cf578042340d279eccc31dd8049796f1f65216c2d64aae042c50edc3`.
Descriptor canonical SHA256:
`7d8f74edc7cffc813201af8c932fb4196adffa4a2ccb5593910bc5cd82bf1a57`.
Public manifest SHA256:
`008689b84cd171187cc75d32402dbf13d6d4e3ed149d3349ecfbc418bfcaad54`.

The client scanned 31,672 accepted transaction IDs and discovered two pool bodies
through exact outpoint links. Both selected IDs were recomputed by the pinned
SDK using populated input contexts. Full expanded headers were hash-checked.
It reached the exact finite confirmed frontier
`b07edb9464f2f32ef8b3d0bbd25d69c62100c3052b3a827de34e1cdb283a7868`
(blue score 592590094), then reconciled through post-query frontier
`453dfdef514a8e626d0b10eaa76140ecaacebf3db5151e5aeb4a80e03299ebc0`
(blue score 592590211). No gap, pruning, removal or related-spend flag occurred.

Four exact current queries observed the private-payment output0 unspent at
120,000,000 sompi and ordinary founding change output1 at 88,630,000 sompi.
The selected consumed input/reserve were queried spent. Both live points were
watched during post-query catch-up. This is an observed public reserve candidate;
the cold client's fresh public semantic/SDK/native replay must authenticate it
before any backup access or ownership/spendability claim.

Vector was the only contacted endpoint. The ordinary execution selected the
SHA-pinned 0500 Node release with a fixed clean environment, a read-only mount
and explicit system-CA option. Source freeze19dffcaa remains unchanged. The
host/release owner is trusted not to mutate selected files; no malicious-inode
writer protection or independent consensus is claimed.

The acquisition took 30.44 controller seconds with a sampled cgroup peak of
664,588,288 bytes and zero swap. The manager explicitly reported the unit
unloaded/PID0. Kernel `cgroup.procs` was unavailable after teardown, so the receipt
honestly records that process observation as null rather than verified empty.

All four raw gzip/decoded page pairs were rehashed locally. Their totals are
117,554,876 decoded JSON bytes and 15,306,252 local gzip bytes, **not wire bytes**.
Bulk unrelated Full pages remain locally retained and ignored; only selected
complete bodies/contexts/headers/current queries plus their page hash index are
in the public export. The original bundle and raw captures were not rewritten.

The wallet performs the required fresh generic native checks itself before its
parameter-ready/one-backup flow. This lane does not duplicate those VM checks.
RPC calls remain non-atomic, and replaying retained observations cannot establish
that they are current indefinitely. Selected-node acceptance/history availability,
development setup and fresh caller acquisition remain explicit assumptions.
General privacy, sustained activity, independent providers/consensus, durable
availability and 10k-operation/20Mbit/s/15-minute performance remain unqualified.
