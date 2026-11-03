# Future-format offline lifecycle integration

Public synthetic **DO_NOT_FUND** fixtures only. This package composes only the
new `future-private-payment`, `future-native-union` and selected receive-V2
packages. It imports no previous wallet, owner CLI, replay engine or proof key.

The finite primary trace has one payer and two distinct useful recipients:

1. Ordinary funding creates a coherent Alice60M singleton reserve, plus ordinary
   owner change. First native public ADMIT establishes singleton coherence and
   adds an Alice note of `2B + private_fee − 60M` sompi.
2. Alice privately consumes **both** notes in one genuine two-input/two-output
   Groth16 action. Bob and Charlie each receive1B sompi; there is no private
   change. Reserve and complete positive liability both become2B.
3. Fresh receiver objects restore pre-payment seed-only backups using the exact
   complete ciphertext archive and current state. Preferred-service interfaces
   are absent before quote signing and withdrawal authorization.
4. Bob reveals against the actual private successor; Charlie reveals against
   Bob's actual successor. Both native payouts execute official Full validation,
   all physical nullifier updates are retained, and the final reserve/liability
   are zero.

`assemble.py prepare` creates the backup before invoices/receipts and a shape
fixture. `materialize` measures actual full native bodies with the selected VK,
solves integer fee fixed points before proof, and binds the final Auth484 to the
actual preceding ADMIT output. `execute` consumes the reviewed frozen artifacts
and genuine proof after `prefix` has validated actual preparation, founding and
admission before expensive key loading/proving. It checks every native Full fee
and independently compares each
consumed outpoint/amount/SPK to the actual previous transaction output.

The Rust binary has explicit `check`, `setup` and `prove` modes. Setup generates
one new local development key using OsRng. The serialized PK remains0600 outside
Git; only its hash/size, VK328 and resource evidence are published. A typed key
selection authenticates domain, circuit/library source, exact PK hash and VK
before any proof-time key load. Fresh outputs are required; no result is
overwritten. Local setup integrity and trapdoor erasure remain assumptions.

Reviewed source and exact input identities precede expensive execution. Frozen
snapshots remain unchanged after later assembly corrections. The circuit source
does not depend on the proof fixture's values; its fixed two-slot shape supports
both-real and real-plus-dummy cases with the same new key. Competing-path fork
controls need freshly rebound genuine proofs, current authenticated NF leaves
and explicit expected native rejection, never a stale-proof shortcut.

This is supplied-context evidence. The chosen canonical founding outpoint,
ordinary funding ancestry, ordered current lineage and complete available
archive are external oracles. Native Full validates supplied UTXOs; it does not
prove they were accepted by a chain or globally backed. Encryption correctness
is checked by the recipient, not proved by the circuit. A successful native
sequence does not establish production security, financial privacy, durable data
availability, network recovery, relay acceptance or a confirmed testnet payout.
Keep every actual fee, funding/change output and positive liability; use integer
per-user allocation and retain failing economics/privacy results.
