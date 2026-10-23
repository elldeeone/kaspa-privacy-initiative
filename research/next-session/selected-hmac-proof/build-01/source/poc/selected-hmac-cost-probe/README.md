# Selected-HMAC circuit cost probe

Separate public **DO_NOT_FUND** adaptation of `../exact-sha-cost-probe`.
It chooses the original real or dummy HMAC inputs before hashing, so each input
slot executes one HMAC instead of both candidates. It preserves the private
transfer relation, SHA-256/HMAC formulas, domain and native wire bytes.

The inner hash compresses exactly three fully padded blocks from the standard
SHA-256 IV. All padding/length bytes are constants or selections by the existing
Boolean flag; no padding witness is accepted. Real message length is76bytes,
dummy length73bytes, and their full inner bit lengths are1120/1096 respectively.
The outer SHA-256 uses ordinary finalization. The independent review and checks
are under `../../research/next-session/selected-hmac-cost/`.

The R1CS matrices change. **Fresh setup and matching verification key are
required; previous parameters cannot be used.** Existing production sources,
closed experimental packets and the current testnet trial remain unchanged.
Proving time and wallet RAM require a separately frozen experiment.
