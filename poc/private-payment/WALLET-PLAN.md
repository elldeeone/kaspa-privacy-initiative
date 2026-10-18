# Full offline wallet acceptance plan

Owner instruction: full offline prototype with real RTX3070 proofs, review
findings, double spends and restore cases. No mainnet or real funds.

Before implementation, challenge these failure modes:

| Layer | Positive path and failure controls |
| --- | --- |
| Canonical decoding | Original intent corpus; complete witness; truncation, trailing bytes, unknown flags/kinds, wrong lengths/scopes, noncanonical field encodings |
| Ownership/membership | External/internal notes, one real plus dummy and two real inputs; wrong SK/scope/rho/seed/path/position/root; a positive input cannot skip membership |
| Monetary relation | CREDIT -> TRANSFER with change -> EXIT; zero/one/u64 maximum, u128 sums, changed principal/fee/output, irrelevant fields; exit_only requires both zero outputs |
| Delivery | Both exact ciphertexts/ephemeral keys/commitments; wrong recipient/rseed/memo/rho or any delivered field rejects |
| C1/C2 | Exact verified public signature in journal, altered signature/envelope/journal; all eight policy fields and actual receipt image checked at admission |
| C3/C4 | Genesis empty allowed root; initial CREDIT; pending principal consumed once without reserve duplication; exit remains unpaid liability |
| Current state | Duplicate nf within/across operations, valid stale-anchor double spend, cross-domain/lane/context replay, expiry including rejected entries, atomic rejection, capacity/no-wrap |
| Restore | Complete pinned history and own backup only, both scopes, decrypt/reconstruct witnesses, current spentness; old/truncated/changed/foreign history fails; no selected-note/key sent elsewhere |
| Real receipts | Genuine succinct GPU proof(s), exact expected journal and image, no assumptions/dev mode, seal/image/journal mutations rejected, saved receipt reverified on CPU |

Native host checks and VM execution failures are not invalid-operation proofs.
The adapter is not a proved outer verifier. No synthetic deposit or payout is
native evidence. Record actual counts and workload costs; do not substitute a
primitive receipt for the full relation. Perform a separate adversarial pass
before reporting implementation completion.
