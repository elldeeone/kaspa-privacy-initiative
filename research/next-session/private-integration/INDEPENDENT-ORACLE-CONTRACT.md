# Independent private authorization oracle

Prospective: source prepared after bounded core design ACK, no artifact
evaluation performed. Root authorized one compact stdlib oracle, at most1CPU
and1GiB; no duplicated financial graph, proof verifier or native runtime.

[`verify-private-auth.py`](verify-private-auth.py) imports only Python standard
library code. It independently parses exact State112/Auth484, recomputes
raw-CM/O/K/HMAC relations, current membership, private value conservation,
dummy rules, cipher binding, all3,344 public-update witness bytes and the two
little-endian128-bit transcript limbs. It reads source-pinned actual native
serde body/UTXO exports, compares metadata/outpoint/amount/fee/payload, parses
the actual common scriptSig, verifies the input's standard BLAKE2b-256 P2SH,
and reconstructs the successor P2SH from that executing policy with only the
new State112 substituted. V1 transaction IDs use BLAKE3, absent from hashlib;
no independent transaction-ID rehash is claimed or replacement invented.
No invocation of this oracle establishes accepted initialization/backing,
Groth16 soundness, native validation, recipient encryption or privacy.

Freeze exact oracle source, approved contract, producer source and actual public
synthetic artifacts before evaluation. Each artifact is DO_NOT_FUND. Retain
any failure unchanged; source corrections require a new pre-execution identity.
Do not overwrite outputs or mutate already evaluated source/inputs.

Input schema `independent-private-auth-cases-v1` contains a nonempty `cases`
list. Each case contains `case_id`, classification
`PUBLIC_SYNTHETIC_DO_NOT_FUND`, auth_hex484, actual_previous_outpoint_hex36,
actual_reserve_sompi, actual_fee_sompi, actual_successor_reserve_sompi,
actual_successor_state_hex112, two inputs, two outputs, two ciphertexts_hex264,
public_witness_hex3344, public_limbs_decimal (two decimal strings), payload_hex4356,
transaction_path, transaction_sha256, supplied_context_path and
supplied_context_sha256. Paths identify actual official native serde transaction
and supplied-context artifacts; their bytes are hashed before parsing.
All hex is canonical lowercase and all amount/count fields
are strict integers. Inputs contain real(bool), note_hex168, s_hex32, k_hex32,
position(u32), cm_path_hex(16 hashes), dummy_key_hex32 and dummy_seed_hex32.
Outputs contain note_hex168; positive public descriptor fields need no
recipient-secret witness. Source pointer/file identity for every native context
field is retained by the producer/export manifest.

The widths above are literal suffixes in the producer's JSON keys: auth_hex484,
actual_previous_outpoint_hex36, actual_successor_state_hex112, note_hex168,
s_hex32, k_hex32, dummy_key_hex32, dummy_seed_hex32, ciphertexts_hex264,
public_witness_hex3344 and payload_hex4356. A separate proof_stage is exactly
PLACEHOLDER_NOT_VERIFIED for the materialized pre-proof body (all128 proof bytes
zero), or GENUINE_NATIVE_VALIDATED for a later source-pinned proof-bearing
native-validated body (proof bytes nonzero). The oracle reports this stage and
does not itself validate a Groth16 proof. A pre-proof pass releases only the
relation/byte binding gate and never counts as native acceptance.

The freeze JSON contains runtime_authorized=true, oracle_sha256, source_pins
(path→SHA256), cases_path and cases_sha256. Runtime authorization is root's
existing engineering authorization, not a new user permission request.

Only exact valid-case conformance is reported PASS. Genuine circuit malformed
input rejection and native competing-spend controls remain separate evidence;
this oracle must not be used to replace either. It verifies every public update
path itself and never imports the implementation under test.
