# ADR-0020: Full offline wallet relation and receipt-backed restore harness

Status: Accepted for owner-authorized unfunded offline implementation, 2026-10-18.

Implement the relation and exact bytes reviewed in RFC-0003/RFC-0004 and
ADR-0019. Reuse pinned Orchard V2 key/note/nullifier/tree/encryption APIs and
the already vector-tested strict Ed25519 profile. No replacement primitive,
new asset, native registration, admin exit or mainnet code is introduced.
The existing same-day [source comparison](../../research/private-payment-source-review-2026-10-18.md)
records Kaspa/Toccata/vProgs, Orchard, Aztec, RAILGUN, Monero and MWEB reuse and
rejections. It remains the source baseline; this implementation does not track
unpinned upstream changes.

Use a shared pure Rust relation compiled into both a native adversarial harness
and a RISC Zero 3.0.3 guest. A successful guest commits exactly the reviewed
229-byte wallet journal. Generic guest context is bound, not admission authority.
Generate actual image only after building the guest; no self-image hash is
embedded. Require genuine succinct receipts, pinned default verifier parameters,
successful halt, empty assumptions and disabled development mode. Use the
qualified local RTX3070 sm86 prover with po2=19. CPU re-verification reads saved
receipt bytes in a separate process and is not an independent verifier audit.

A separate offline state adapter verifies receipts, every immutable policy
field, anchors, current nullifiers, pending-credit consumption, conservation
and claims atomically. Its policy/deposits/ordered history are explicitly
synthetic and locally trusted. It is host code, not a proved outer classifier;
no real-private R13, canonical Kaspa acceptance, native payout or native R16
claim follows. Preserve native recognition/bootstrap/ordering/payout gates.

Recovery starts from a backup containing Orchard spending keys (both scopes
are scanned) and every independently sampled pending-deposit Ed25519 seed and
reference, plus the exact synthetic context/checkpoint identity. These local
research backups are plaintext files with restrictive permissions, not a
production encrypted backup format. Never publish fresh secrets or witness
inputs with evidence. Rebuild current state from complete pinned synthetic
history and re-verify saved receipts before scanning/decrypting. Missing,
truncated, changed or wrong-context history is unavailable; an old root does
not reset spentness. OS entropy must fail closed. Entropy quality and local
machine confidentiality are assumptions, not properties established by proofs.

Receipt timing and workload may disclose real/dummy execution differences.
No constant-time, network anonymity, externally audited security or production
privacy claim is made. The [implementation plan](../../poc/private-payment/WALLET-PLAN.md)
defines failure modes before code and records the acceptance scope.

Implementation review additionally requires one canonical bincode 1.3.3 receipt
envelope before host admission: serialize(deserialize(raw)) must equal raw.
The upstream default decoder permits trailing bytes; the shared offline host
decoder rejects that aliasing explicitly. Existing genuine succinct receipts
are unchanged, and the frozen wallet guest image is unaffected. This strengthens
profile/evidence identity; it is not a total native R13 classifier.
