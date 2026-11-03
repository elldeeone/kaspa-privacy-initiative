# ADR-0020: Recover compact-pool wallets from backups and public history

Accepted for the owner-authorized Stage 1 offline experiment and conditional
TN10 rehearsal/trial, 2026-10-19. This changes recovery tooling, not the compact
proof relation, native covenant, setup or economic floors in ADR-0019.

## Decision

H7: after Alice sends to offline Bob and Carol, stop the original sender and
restore each of the three wallets using its own pre-payment backup. Each wallet
must discover its unspent notes, generate its own first exit authorization and
receive native test KAS without another wallet's secrets or experiment services.

The private backup contains the existing independent spending, viewing and
native-payout keys, a format version, and a hash identifying the public pool
descriptor. The initial depositor also retains the original note opening: it is
needed if recovery precedes the first accepted transfer. It is not recoverable
from the funding commitment alone. Bob and Carol have no note openings, Merkle
witnesses, proof or future transaction list in their backups.

The public descriptor fixes TN10/genesis, domain, canonical initial commitment,
reserve amount, funding outpoint/body identity, input context, parameter hashes
and a chain-discovery starting block. It contains no receiver/address book. The
backup's descriptor hash authenticates this choice; downloading an arbitrary
descriptor from a server does not authenticate a pool. Existing single-party
setup trust is unchanged by hashing the parameter files.

Recover by downloading public parameters and history from replaceable read-only
sources, validating funding and every reserve successor with the pinned native
engine, reconstructing all three trees, checking the current accepted chain
view, trial-decrypting ciphertexts locally and filtering spent notes. Bind every
exit to the wallet's derived native payout key. Public servers receive no keys
or plaintext notes. The original experiment manifest is never a recovery input.

Use static public copies and a normal node RPC; no privileged indexer, new token,
new cryptography, runtime, admin signer or consensus change. A fresh wallet
cannot invent missing ciphertexts/history: fail closed and try another source.
Loss of all required copies remains an availability failure, not a successful
exit. Correct synchronized node views and retained accepted history are explicit
assumptions; arbitrary reorg/pruning recovery is not established here.

## Alternatives and evidence boundary

- Reusing the experiment directory would not test minimum backups or independent
  discovery. Reject it.
- Prebuilding exits would repeat H6. H7 creates each exit after recovery.
- A hosted scanner given viewing keys reveals note ownership/value. Keep scanning
  local; network/RPC metadata remains observable and outside chain-only privacy.
- Seed-derived keys may simplify a future wallet, but changing derivation now
  would confound this test. Preserve the three existing keys explicitly.

Offline sandboxing precedes a complete funded rehearsal and fresh measured trial.
The live recovery runs away from the original experiment directory/processes.
Record actual host/node separation; do not claim three independent humans or an
audit. [RFC-0008](../rfc/0008-independent-wallet-recovery.md) defines the gates;
[source review](../../research/independent-recovery-source-review-2026-10-19.md)
records reuse and current upstream checks.

## Observed outcome

The offline gate, complete TN10 rehearsal and fresh measured trial passed.
Three restored clients independently discovered notes, generated their first
exit proofs and received exact native payouts on a separate host after the
original prover and public source stopped. All claims/reserves drained. The
first funded attempt hit an RPC disconnect before exit submission; a transport
fix and fresh ordinary wallet cleanup recovered that pool before the complete
rehearsal. No special recovery signer or covenant path was added.

Retain the declared backup and public-data model for further research. The
initial-note control confirms the depositor cannot recover that original claim
from keys alone. Cold parameter loading remains expensive, and public data must
remain available independently. This bounded result does not establish useful
privacy, arbitrary reorg/pruning recovery or production security.
[Measured evidence](../../poc/shared-pool/RECOVERY.md).
