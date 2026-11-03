> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Flat two-SPEND prerequisite: frozen toy contract

2026-10-22. Deterministic stdlib-only model, authored before the first run.
No native code, proofs, cryptographic setup, solver, sampled workload or field-removal audit.

## Exact question and separate verdicts

1. **Witness gate:** after a stipulated valid, accepted batch, can a recipient reconstruct its note position, commitment membership, historical-root membership and two current indexed-nullifier insertion paths from complete flat public data and its own key, without either operation grouping?
2. **Ambiguity gate:** can two distinct authorized/conserving internal assignments produce byte-identical projected public data with the same fixed note openings, ciphertext tokens, old state and native reserve movement? Different randomness or relabeling operations alone does not count.

A pass is an existence result for this data model, not measured privacy or native/proof feasibility. Either gate can fail independently.

## Public projection and client information

An authenticated starting checkpoint contains the ordered commitment/ciphertext pairs, complete indexed-nullifier leaves, all historical commitment roots/counts and native reserve. Authentication, completeness and accepted-chain selection are assumptions.

Each batch has exactly: `schema`, `before`, `outputs`, `nullifiers`, `fee`, `reserve_after`, `after`. `before/after` contain sequence, commitment/nullifier counts, their roots, history root, reserve and a digest of all ordered commitment/ciphertext pairs. `outputs` is four pairs sorted by commitment bytes; the four nullifiers are sorted as little-endian integers. The old list is never globally resorted. `fee` is the sum of the two individually authorized fees, and the native payout is zero. There are no individual authorization digests, inner proofs, operation IDs, owners, inputs, per-operation output grouping, per-operation anchor or arrival time in this projection.

After every two entries of the sorted append, record the deterministic commitment-prefix root. These prefixes are derived from flat order, not operation order. They become allowable historical membership anchors only after atomic batch acceptance. This is an explicit proposed rule, not an assertion that current v6 accepts four-entry updates.

The recipient receives checkpoint, batch records and its own secret. Note delivery uses an **ideal sealed-box functionality**: the public ciphertext is an opaque token, and `open(own_secret, token)` returns only that key's opening. A restricted key-bound capability simulates this primitive. No encryption is implemented or claimed secure. The client API does not receive private operations, other keys, note values or the producer's note table. Same-process object boundaries are not sandbox isolation.

SHA-256 Merkle hashing and HMAC-positioned nullifiers are real stdlib computations, with small fixed depth 5 for this fixture, rather than native depths 16/17. Owner derivation and note serialization are simplified and are not native byte parity. Indexed nullifier leaves use value, next index and next value, with a zero sentinel. Exit witnesses include both the real nullifier and a distinct dummy, inserted sequentially.

## Hidden assignments and validity

Two independently controlled senders A/B each own two old notes totaling 10.4 tKAS; their exact fee is 0.4 tKAS. Four fixed output notes are R:3, A:7, S:3, B:7 tKAS. Assignment X is A -> (R:3,A:7), B -> (S:3,B:7); assignment Y exchanges R/S while retaining each sender's own 7-tKAS change. The actual note openings, owners, commitment/ciphertext pairs and spent inputs remain identical. X/Y change sender-recipient relationships and output grouping, not amounts.

The bounded enumeration checks all six two-output allocations to A and the complementary allocation to B. It reports both protocol-valid allocations and the stricter client subset requiring each sender to keep its own change. Equal payment values are deliberate; no general or low-activity privacy claim follows.

The reference validity checker sees toy private openings/keys to check ownership, one/two distinct prior inputs, allowed historical anchor, padded arity, individual and aggregate conservation, exact fees, positive-note floors and cross-operation uniqueness. It stands in for the proof obligations. Public replay cannot establish hidden conservation by itself. A required negative control constructs a self-consistent inflated flat state which public replay alone cannot reject, while the private checker rejects it: this must remain a recorded dependence on a real sound proof.

## Required checks and stopping conditions

- Discover R's output using only its key-bound ideal-decryption capability; verify all membership/history/current-nullifier paths and derive an individual full exit's amount. The unrelated checkpoint holder must also do so.
- After a second unrelated batch, preserve R's position and historical authorization while rebuilding its public exit paths. Reject reversed batch sequence, wrong state and noncanonical ordering.
- Exercise two-real-input/payment/change and later one-real-input/dummy-nullifier operations. Reject reused inputs, wrong ownership, zero/duplicate/previously spent nullifiers, duplicate commitments, wrong fee/conservation, insufficient data and mismatched ciphertext/commitment delivery.
- Projection equality must hold for at least X and Y. Transparent per-operation authorization digests and an ideal separately verifiable inner-proof interface must distinguish X/Y, preserving this as a failed privacy design for those exposure variants. They are not silently removed from a native format we claim to have implemented.
- An injected per-operation field must fail the projection schema. A collector or colluder given its own complete operation can subtract it from a two-operation batch; the compatible allocation count is recorded.
- An omitted/malformed recipient ciphertext must not yield an invented opening or witness. Loss of published data fails recovery; no private grouping is used as a repair path.

Stop after this bounded fixture and negative controls. No parameter sweep, statistical estimate, native validation, proof generation, install or further infrastructure work. Expected runtime below one second and peak RSS below 100 MiB; record actual measurements.

## Source mapping (read-only Forge)

Repository `/home/luke/projects/kaspa-privacy-shared-pool`, HEAD `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`.

- `poc/shared-pool/src/two_input/mod.rs:24-118,153-239`: current public auth, ciphertext pairs and native reserve changes. SHA-256 `255f8e908fcb1c4a76dcc8ebe0ca5f4e9ddbadc8ba46f63036cb413298bc8150`.
- [poc/shared-pool/src/two_input/circuit.rs:109-278](../../../../../poc/shared-pool/src/two_input/circuit.rs): one/two real inputs, ownership, position-bound real NFs, dummy NFs, padded outputs, fee/conservation and authorization binding. SHA-256 `59071901c3abc25daab68c982ef065f8755c09abbb2ce30e6010d821813dd2a7`.
- [poc/shared-pool/src/two_input/tree.rs:152-287](../../../../../poc/shared-pool/src/two_input/tree.rs): retained roots, indexed-NF insertion, append paths and current fixed two-output history convention. SHA-256 `9fc004721ae2a22c6faa26f2a046eefd7bb707e3c83077be01a7913b464891ed`.
- [poc/shared-pool/src/compact/tree.rs:7-47](../../../../../poc/shared-pool/src/compact/tree.rs) and `compact/mod.rs:54-58`: hash domains, indexed leaves and positioned HMAC NF.
- [poc/shared-pool/src/two_input/wallet.rs:299-353](../../../../../poc/shared-pool/src/two_input/wallet.rs): decryption, commitment/position checks and spentness. SHA-256 `3039fe885379aeec3b2378ee4b881a46e01b5bc1d3e6e68d706852c6a39070e5`.
- `poc/shared-pool/src/protocol.rs:65-106,175-204`: existing sealed-box delivery and plaintext validation, which this toy treats ideally. SHA-256 `5243cab1b36e0d9cae8bf13e81b7fcdb033c8dc1bc7405daa401c69334cc4ec4`.

The previous architecture report is [/home/luke/projects/kpi-orchestration/2026-10-22/architecture-options/REPORT.md](../archive/INITIAL-BATCHING-PROPOSAL.md). This check narrows that proposal; it does not alter Forge sources or the frozen evaluation.
