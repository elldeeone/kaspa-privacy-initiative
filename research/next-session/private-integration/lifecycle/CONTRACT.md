# Actual-body lifecycle experiment

This lane implements the bounded new-format integration authorized by ADR0041
and receive-V2 ADR0042. It owns only `poc/future-lifecycle` and this evidence
directory. Native/proof/recipient packages retain their separate owners and
frozen evidence. All keys and source funding contexts are public synthetic
DO_NOT_FUND material; no network, node, broadcast, wallet funding or old key is
used.

The primary exact accounting is:

```text
Alice G0 = 60M
Alice admitted G1 = 2B + actual_private_fee − 60M
after ADMIT: R = L = G0 + G1 = 2B + actual_private_fee
private consumes G0/G1, creates Bob1B and Charlie1B
after PRIVATE: R = L = 2B
Bob reveal: R = L = 1B; Bob receives1B − actual_Bob_fee
Charlie reveal: R = L = 0; Charlie receives1B − actual_Charlie_fee
```

Both input notes belong to one Alice backup. Bob/Charlie output construction
uses their public invoices; the sender's actual private witness contains
neither recipient s nor recipient k. Their backups are persisted before any
invoice/receipt. Restore constructs a new receiver from that seed and the
authenticated profile, checks each ciphertext and rederives authority. The
complete current archive and canonical head are explicitly supplied oracles.
No later note, witness, invoice log or precomputed withdrawal is in the backup.

For each transition compare the actual previous `transaction.json` output to
the next actual input outpoint and its supplied amount/SPK. Check all payloads,
successor states, cipher hashes and every positive liability independently.
Native `Full.fee_sompi`, actual contextual mass arithmetic and the frozen
authorized fee must agree exactly. Actual fees solve monotone integer fixed
points at100 sompi/mass;100/200/500 quotes remain separate observations.

Count ordinary preparation/founding/admission/private/revealing fees and all
ordinary funding change. Allocate shared fees by exact quotient/remainder,
then add each recipient's own reveal fee; report the maximum actual individual
burden rather than averaging away a costly recipient. Two distinct1B recipient
payments are the favorable case, never recipient-plus-change relabeled as two
payments. Other fee-rate, amount, tail, privacy and service-loss failures remain.

Root and an independent reviewer inspect exact source/shape before setup and
exact actual native-linked Auth/witness/fee before proving/execution. Operational
resource limits are generous and failure retains its identity. Each expensive
run has an isolated network-free unit, source/binary identity, CPU/wall/memory
record and cleanup. None of these checks proves accepted ancestry, complete
chain backing, cryptographic security, financial privacy or confirmed payout.
