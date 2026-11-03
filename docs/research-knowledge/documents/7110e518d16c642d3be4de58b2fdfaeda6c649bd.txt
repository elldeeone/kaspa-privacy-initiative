# Cold recovery of fresh unspent test-KAS claims

This is a separate old-KPX2 service-loss rehearsal. The previously closed
historical recovery packet and its software remain unchanged. Only free TN10
KAS and newly generated controlled research roles are used.

1. Root prepares and confirms the funding, genesis, admission and genuine private
   payment prefix, then stops the prover. Those preparation files, profiles,
   witness directories, expected payment maps and precomputed exits are excluded
   from the cold clients.
2. The owner separately pins the exact nine-field public descriptor. A network
   process mounts only that descriptor, the frozen public fetch software/SDK,
   system libraries and a fresh output directory. It discovers the current pool
   history and UTXOs from the founding outpoint. Charlie fetches again after
   Bob's exit; Bob's earlier current-head data are not reused.
3. A separate network-isolated public process replays each fresh raw fetch and
   runs native Full validation for every discovered pool transition. A changed
   transcript with the original curve proof must reach and fail Groth16. This
   validates supplied public contexts; selected-node acceptance remains explicit.
4. Each cold owner process mounts exactly one seed-only backup file, the pinned
   descriptor, that owner's fresh fetch, approved software and narrow helpers.
   It mounts no backup parent directory, other seed, operator archive/profile,
   proving key, prover or precomputed transaction. Host preflight checks backup
   permissions, symlinks and Git ancestry using metadata only.
5. The small `client.py` wrapper reuses unchanged wallet functions: software and
   descriptor checks, complete public replay before seed access, one backup read,
   one recognition, and current witness construction. The actionable position
   comes from recognized valid receipts. The first actionable position in
   ascending order is selected; the request cannot inject a position or amount.
6. Root explicitly authorizes revealing fallback for these two controlled roles
   before either seed is read. The unchanged wallet quotes the actual native
   mass at reference rate100, constructs a new current-head REVEAL, signs
   Schnorr ALL and checks its exact effects and native Full result. The generic
   helper uses the authenticated current redeem and preserves its immutable
   tail. It reads no proving key and does not use a compiled-domain factory.
7. Signed transactions remain in fresh0700 directories and0600 files outside
   Git. The cold client never broadcasts. Root rechecks the current head,
   submits each transaction once and verifies its confirmed native payout.

The sign process returns its recognized-claim summary as well as its signed
result, so no extra recover-only seed read is needed. Public orchestration
controls check ordering and position selection using mocks; they are explicitly
separate from the real network, native and one-backup evidence.

## Meaning and limits

Owned values are derived from locally decrypted, rederived, CM-valid receipts;
they are not compared against an operator's intended-payment table. Recognition
still assumes correct receiver encryption. The current relation binds ciphertext
bytes without proving correct encryption to the recipient, so foreign and
maliciously undeliverable ciphertexts cannot be distinguished from a seed alone.
An ongoing pool's recognized total is not a universal liability statement.
Validated terminal reserve0 is a separate public condition.

This proves operator/prover independence for the measured unspent claims under a
user-authenticated canonical descriptor, retained public data, selected validating
nodes and preinstalled pinned software. It does not prove independent consensus,
durable data availability, fresh-machine installation, recovery of off-chain
orphan disclosures/invoice issuance state, large-history performance or production
safety. The consented REVEAL publishes its note/value/CM, positioned NF credential
and key, and note-bound native payout key. These payouts do not establish
financial privacy or the complete-fee target. The new proof-private exit
prototype is a separate experiment.

Each launched unit records its actual cgroup `cpu.max`, `memory.max` and
`memory.swap.max` before entering bwrap, along with GNU-time, exit and cleanup
evidence. These operational observations are not reference-device qualification.
