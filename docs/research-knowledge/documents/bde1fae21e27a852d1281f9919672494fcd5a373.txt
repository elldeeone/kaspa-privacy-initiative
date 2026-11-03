# RFC-0004: Four-wallet full versus partial withdrawals

See [ADR-0016](../adr/0016-four-wallet-shared-pool-trial.md) for the bounded design.

Hypothesis: allowing private change at withdrawal increases the number of
marginal chain-consistent consumed-note candidates at the first-withdrawal horizon,
relative to whole-note withdrawal, under the same synthetic private workload.
Test again after complete drain; improvement need not persist.

The decision is whether partial withdrawals merit continued wallet/protocol
development, and whether a small direct pool can support repeat payments and
independent exits at measured L1/proving costs. More wallets alone are not a
privacy success criterion. A negative result is useful and must be reported.

State: version 2, commitment count, nullifier count, 24 commitments, 24 nullifiers
(1,539 bytes). Payload: `KPISP02\0`, mode, next state, two 185-byte ciphertext
slots (1,918 bytes). Modes: 0 deposit, 1 transfer, 2 full continuing exit,
3 terminal full exit, 4 partial exit. Deposit/partial create one note; transfer
creates two; full exit creates none. Unused ciphertext slots are zero.

Transcript: `KPIBN02\0`, domain, old state, reserve outpoint (txid + LE64 index),
reserve input/output/payout LE64 amounts, payout version+P2PK script (36 bytes),
external deposit outpoint (40 bytes), amount (8), script (36), SHA256(payload).
Deposit fields are zero for other modes; absent payout fields are zero.
Total 1,795 bytes. Both digest layers are constrained; the complete SHA256 digest
is exposed as two canonical 128-bit BN254 public inputs. Immutable script/VK
propagation follows ADR-0015 with offsets derived from the fixed state size.

Open after this bounded trial: larger state, contention/reproof costs, proof
parameter startup, adverse amount/timing distributions, wallet side information,
colluding participants, archive loss, setup ceremony and independent audit.
RPC/network observation is outside the chain-only attack input and not protected
by isolating the local prover. No real-world anonymity rate follows from this run.

Independent-exit evidence is restricted to this controlled, sequential workload
and retained public data. Wallets quarantine notes below the configured exit
floor, but the circuit permits smaller positive notes. A malicious tiny claim
could prevent a later exit that leaves an excessively small native reserve;
protocol-level dust handling and competing spend/reproof trials remain open.
The experiment does not resolve arbitrary reorg, pruning or adversarial liveness.

Bounded result, 2026-10-19: both funded arms completed with all four wallets
drained. The first-horizon candidate hypothesis held for all four selected
withdrawals; after complete drain, three retained larger candidate sets. Exact
input-amount inference was possible for all four full withdrawals and none of
the four partial withdrawals under the model. Equal 0.25 tKAS first payouts
were part of the partial-arm policy, so the result does not isolate that policy
from change support. No unique-source or deposit-origin advantage was measured
for these four exits. Continue researching private change, protocol-level dust
handling and independent recovery from competing reserve spends. See the
[measured results and evidence](../../poc/shared-pool/README.md).
