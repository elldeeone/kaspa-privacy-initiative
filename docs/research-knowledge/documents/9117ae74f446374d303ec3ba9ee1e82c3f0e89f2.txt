# Confirmed terminal public evidence snapshot

This is the exact **prepublication** public metadata/native-case snapshot after
GN3, both genuine mixed rounds, nine confirmed native payouts and three further
fresh original-seed terminal recovery scans. Reserve and outstanding owned
claims reconcile to zero. [SOURCE-TO-COPY.json](SOURCE-TO-COPY.json) authenticates
every explicit copy; no protocol bytes were rewritten.

The snapshot contains twelve chain-ordered [case packets](cases/00/case.json),
each with actual native Full/per-input validation and fee metrics. Index00 is
GN3, 01–02 are mixed batches, 03–11 are direct exits. These are public chain
ordinals, never owner/client ordinals. Proof witnesses, compute budgets, gas and
populated input contexts are the actual accepted values.

- [INDEX.json](INDEX.json) lists exact whole-file hashes, lengths, public URLs
  and placements for all terminal verification objects.
- [REPLAY-PACKET.json](REPLAY-PACKET.json) gives the existing closed-replay six
  input paths, complete main/post-query page list and exact terminal H/C pins.
- [PAYOUTS.json](PAYOUTS.json) preserves nine public outpoint/value/script/birth-DAA
  observations; [TERMINAL-AGGREGATE.json](TERMINAL-AGGREGATE.json) contains only
  aggregate seed/cohort/claims/payout-key booleans/counts.
- [metadata](metadata/SDK-VERIFICATION.json) retains the actual SDK/native replay,
  final history/checkpoint and explicit null current entry.
- [Terminal transport selection](transport/SELECTION.json) includes the one
  whole-hashed INDEX object plus its exact references. The unchanged initial
  recovery [selection](bootstrap/INITIAL-RECOVERY-SELECTION.json) and
  [closure](bootstrap/INITIAL-RECOVERY-CLOSURE.json) remain separate snapshots.

Raw compressed pages and decoded gigabytes stay outside Git. Their exact hashes,
lengths and public placement remain in the metadata; the new-page decoded
[audit map](GZIP-AUDIT-MAP.json) is not a payload archive. The
[operator candidate](CANDIDATE-OBJECTS.json) records the truthful pending-audit/
publication state at assembly. It is not proof of URL availability. Actual new
public CI HTTPS/native replay receipts must be assessed separately.

`owner_client_associations_selected=False` means no **additional private
recovery-client-to-note/NF/exit/payout association artifacts** were selected.
It does not mean public protocol participant IDs, input labels, amounts or
source-established funding/session linkage are absent. No individual recovery/
READY/scan outputs, client scan selectors/hashes, private schedule/order,
configuration, HEAD, raw logs, Root inode baseline or four raw acquisition
artifacts are included. The Root input selection is identified by its hash;
its machine-specific source pointers are not a new Git payload.

All-in fees are **2.156935 KAS / frozen 21 KAS = 10.2711190476%**, failing 2%.
See the [neutral final accounting](../accounting/PUBLIC-LIVE-TERMINAL-01.json)
and [lifecycle results](../RESULTS.md). This snapshot is selected validating-node
research evidence, not independent consensus, anonymity, separate
administration, durable retention or production-safety qualification.
