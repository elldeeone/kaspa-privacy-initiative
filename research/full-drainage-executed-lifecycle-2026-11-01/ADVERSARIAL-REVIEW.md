# Adversarial second pass

## Inflation or value creation

Each world registered exactly 200,000,000 sompi of fixture reserve, credited that
amount once, preserved private liability through three transfers, converted each
spent exit note into an equal unpaid exit and discharged it only through an
equal destination-bound payout record. Final reserve, private, pending and unpaid
principal were all zero. Underpayment and diversion rejected without successor
state.

Limit: native UTXOs did not back these fixture records. This is application
accounting evidence, not native conservation proof.

## Double spend and duplicate input

Every transfer/exit used one input and one economic nullifier. All eight
nullifiers per world were distinct. Replaying an accepted exit against final
state rejected as `current economic nullifier spent`. Five exits prepared from
one historical root applied only while their individual nullifiers remained
current. No multi-input/merge path exists, so duplicate-input safety for merge is
outside this milestone.

## Unauthorized payout or exit

Wallet S could not discover or exit A's 60,000,000-sompi note from the same public
state. Exit proofs bound their public amount/destination; underpaid and different-
destination fixture payouts rejected. Same-host orchestration still knew the
requested payment schedule and controlled process launch; it did not possess the
wallet store bytes through the public protocol.

## Wrong, stale or cross-domain state

A changed domain rejected during public checks. A changed root invalidated the
proof. All genuine recovery exits used the same previously accepted membership
anchor and were checked against the evolving current nullifier set. The run did
not exercise a chain reorg, pruned history or another lane. The old archived
default-domain proof suite failing under the depth-four feature is retained as
profile incompatibility evidence, not counted as a passed new-profile test.

## Reorg and concurrency

Concurrent intent was approximated by proving all exits against one common state
before applying any. Sequential application succeeded because membership anchors
remain accepted and nullifiers do not conflict. There was no selected-chain
acceptance, finality window, native conflicting UTXO or reorg. Those controls
remain mandatory in RFC-0003 before a funded trial.

## Dependency loss and recovery

Default relay and original wallet processes stopped after payment. Replacement
processes restored four owner backups and public state, then proved all exits.
This demonstrates backup/process recovery only. Proving parameters, public state,
wallet stores and replacement processes remained on one host; loss of that host,
parameters or authenticated history was not tested. Missing infrastructure would
halt liveness but did not add spending authority in the executed path.

## Metadata leakage

The ledger exposes operation kind/order, fixed wire arity, anchors, commitments,
nullifiers, ciphertext hashes/sizes, deposit owner/value fields, exit amount/
destination, zero fees and all state transitions. The relay additionally exposes
arrival order/time, request representation size and fresh tokens. It saw no
wallet label. Network/IP, RPC provider and native fee funding were absent, so no
network-anonymity claim is available.

Known payout owners and the four-edge graph leave two gross histories; the fact
that M paid S collapses them to one. This negative strong-observer result is
retained. Unmapped ownership is a sensitivity view, not the headline.

## Hidden trust assumptions

- fresh experimental Groth16 setup without an independently destroyed toxic
  waste ceremony;
- assumed commitment/ciphertext/nullifier opacity and proof soundness;
- one host, one orchestrator and local filesystem permissions;
- complete public state supplied by the experiment;
- authenticated native facts simulated by fixtures;
- no adversarial operating system, compromised wallet process or global network
  observer; and
- exact current source/toolchain dependencies rather than independent audit.

## Fresh TN10 profile

The local/TN10 mismatch was closed with a separate domain, fresh setup/VK,
fresh wallet proofs and a fresh guest image. Both cross-profile verifier
directions rejected. Seven linked local native batches consumed 39 distinct
inputs, ended with zero principal accounting and rejected exit replay plus 13
payout mutations. This extends local implementation evidence; it does not make
the original local domain fundable or validate the new setup cryptographically.

Exact CPU execution of all seven targets stayed below 160M user cycles and
matched each journal. All seven batches produced genuine Succinct receipts and
passed independent receipt and mutation checks. The original po2-20 batch-1
attempt failed with CUDA out of memory after guest execution and remains retained.
The successful po2-19 resource profile for batches 1-6 is explicitly recorded;
it did not change the guest, witness, journal, program image, verifier, JOIN
control or native checks. The original resource failure is not counted as an
invalid-proof control.

## Native stop decision

Funding remains correctly halted for a different reason: the complete
receipt-backed local rehearsal and isolated seven-stage TN10 builder now pass,
but this checkout cannot authenticate the gateway's current SSH host key. A
fresh unfunded identity exists. Host-key bypass is rejected because it could
hand the sponsor/source-signing workflow to an impersonated endpoint. After
independent key authentication, fresh-chain receipts, broadcasts,
selected-chain confirmation, reorg/freshness handling, service-loss recovery
and all five payout confirmations must execute before readiness can be claimed.
Reusing local receipts for different chain inputs or weakening any check remains
rejected.
