# Private action with proof-backed native payout

Separate unfunded ADR-0050 experiment. The root-selected public development
domain is `aa39ad5d2da85dfd1695cc74ce3e0f23e713f315d6e5341bccc8a060111354c2`.
Never fund these deliberately public fixtures. Existing/funded source and keys
are unchanged. The exact contract is
[Auth528](../../research/next-session/privacy-recovery/PRIVATE-EXIT-CONTRACT.md).

The fixed two-input/two-output relation supports ordinary private payment,
native payout with private change and terminal payout. Ownership is still s+k;
the same positioned original NF is used by proof and revealing fallback. Public
payout/fee/state/destination are bound to SHA256(Auth528). Terminal mode creates
no dummy CM/delivery, while keeping both NF updates. Per-real-input destination
key inequality blocks exact emergency-key reuse; global freshness/curve validity
are not proved. Native current-state/update/transaction validation remains
separate. No ciphertext encryption or accepted ancestry is proved here.

`fixture KIND NEW_FILE` exports deterministic public relation fixtures;
`positive KIND NEW_DIR` and `negative CASE NEW_DIR` perform full R1CS synthesis.
Negative runs bypass host validation and record actual complete constraint
satisfaction. `list` prints the frozen case names. Counts/roots in these sizing
fixtures do not assert an accepted historical ledger.

`session SHAPE NEW_SETUP_DIR NEW_EXTERNAL_PK` creates one fresh development setup
with OS randomness, writes the official uncompressed PK0600 outside Git and
retains it in memory. Only after its fsynced `ready` event may stdin JSON
`{"fixture":"/public/frozen.json","output":"/new/proof-dir"}` request a proof.
Each proof gets checked host verification. `quit` or EOF ends the process. There
is no old PK/matrix loading mode. `verify SELECTED_VK FIXTURE PROOF` uses checked
untrusted proof/VK decoding; caller/root selection remains the key authority.

The selected SHA/HMAC gadget source is reused from the separately reviewed
cost candidate. New Auth/mode/terminal/ownership constraints require a new VK.
Gadget KATs alone do not replace full-relation negatives or an adversarial
review. Passing tests does not prove cryptographic correctness. Native proof
cost floors, privacy under traffic/disclosure and independent recovery remain
separate obligations.
