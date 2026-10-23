# Cold software and recognition result review

Reviewed the actual three build outcomes, final command and provenance receipt,
final software inventory `d8f96ce9f133d846b94ad5219f45d8664acba8972355fccd2d27b3315a06b808`,
recognition source/command/result and current reconciliation delta.

The third build reproduces the selected ELF exactly:
`1662fcd9a5b90b8658e07aed2250a4c9c11d2390e80d7addae717090d63fb94d`.
Actual build31.02s, cgroup peak1,207,611,392 bytes, zero swap. Authenticated
restored sources/vendor only are available; original source/cache/target absent,
Cargo offline and empty home/target, network unshared. Installed toolchain/OS
remain trusted. This is same-host reproduction, not independent-machine or
general cross-platform reproducibility.

Both previous mismatches remain recorded. Matching original logical dependency
paths changed42e72... to c587e...; masking optional installed rust-src then
restored canonical standard-library paths and produced1662.... Rust source,
dependency versions and compiler flags were not changed to bless a replacement.
The final launcher `b0208145...` reconstructs vendor bytes at the old logical
path, rather than mounting the old registry/cache. New software authority was
never granted by either mismatch.

Final inventory03 explicitly includes pinned owner8d6a... and launcher c620...
modules. An initial review concern compared the new canary launcher with an
earlier five-module inventory; checking final inventory03 resolved it without
another package version. The proving target is in the authenticated set.

Actual recognition01 replays SDK/native Full public history, then opens its
single known-unsafe original backup and decrypts/rederives one unspent receipt,
CM and positioned NF. Neither PK nor owner prover is mounted. This does not
prove spend readiness, accepted backing or currentness; all remain false.
Prospective proving mode mounts only the explicit selected PK/prover, one own
backup and authenticated runtime files, with original paths absent. Actual
HTTPS retrieval and root-scheduled genuine owner proof remain separate gates.

Current reconciliation source `dbd99cde...` additionally binds locally selected
founding point and birth frontier, complete ordered history/current queries and
postquery sweep. Selected-adapter/validating-node trust is explicit and there
is still no live KPX4 adapter. Contract fixture positives cannot activate spend.
Actual source ACK covers that seam and public recognition; it grants no live
currentness, provider independence, retention, setup soundness or production
qualification. The17-asset parameter release excludes the full cold software
payload, whose distribution remains a separately evidenced requirement.
