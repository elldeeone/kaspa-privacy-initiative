# Public native action helper API, ADR0053 + execution amendment0054

Selected under frozen ADR0053 and the common integration contract. The implementation is
a small Rust ELF. ADR0054 supersedes the earlier executable-FD plan: trusted
callers use a dedicated0700 release directory and ordinary0500 binary,
read-only mounted and SHA-checked before every launch, with a clean environment.
Host/release immutability during an operation is an explicit assumption; this
does not resist a malicious host/inode writer. It reuses source-approved
program construction and official native mass/Full APIs; it accepts no owner seed, native signing secret or PK.

## Strict requests

One JSON object on stdin. Duplicate keys, unknown fields, noncanonical lowercase
hex, noncanonical unsigned decimal strings and integer overflow reject. Network
is always `testnet-10`; `genesis_hash_hex` is always
`f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370`.

The following fields are exhaustive for `quote`:

| Field | Type / rule |
| --- | --- |
| schema | exact `kpx3-public-native-action/v1` |
| mode | exact `quote` |
| network_id | exact `testnet-10` |
| genesis_hash_hex | exact TN10 genesis above |
| domain_hex32 | lowercase hex, 32 bytes |
| current_redeem_hex | lowercase hex, exact approved 24,417-byte program |
| previous_outpoint | exactly `{transactionId: hex32, index: JSON u32}` |
| supplied_utxo | exactly the five fields below |
| auth_hex528 | lowercase hex, 528 bytes, `KPX3AU01` |
| cipher_hex528 | lowercase hex, 528 bytes |
| public_witness_hex3344 | lowercase hex, 3,344 bytes |
| vk_hex328 | lowercase hex, 328 bytes, exact embedded operand |
| proof_hex128 | exactly 128 zero bytes in quote mode |
| fee_rate_sompi_per_mass | canonical positive u64 decimal string |

`supplied_utxo` has exactly `amount_sompi` (canonical positive decimal string,
at most MAX), `script_public_key` (complete version-prefixed lowercase hex),
`block_daa_score` (canonical u64 decimal string), `is_coinbase:false`, and
`covenant_id:null`. The outpoint is separate and is bound by the transaction.

`verify` has the same fields, with `mode:verify`, a nonzero `proof_hex128`, and
the required extra field `expected_quote_id` (lowercase SHA256 hex32). Quote
mode rejects that extra field. No software path, executable, report, callback,
fee sponsor or alternate output can be selected through a request.

The separate public `genesis` constructor has exactly `schema`, `mode:genesis`,
`network_id`, `genesis_hash_hex`, `domain_hex32`, `vk_hex328`, `note_hex168`, and
`cipher_hex264`. It returns the source-approved singleton State112, complete
redeem/SPK, public GN536 payload and reserve amount. It does not construct or
sign an ordinary funding spend; the trial's funder signs that separately.

## Binding and responses

Approve the entire new union with only State112, ten parsed canonical domain32
operands and one parsed VK328 operand variable. Current input SPK must hash the
actual supplied redeem. State/domain/outpoint/R must match Auth528 exactly.
Use the unchanged private budget1600 and exact zero signature65. Outputs follow
P0 continuing, P>0 continuing, or P>0 terminal topology from ADR0050, including
the byte-exact full SPK36 and immutable successor tail. Destination ownership,
curve parsing/freshness and hidden consumed-note key inequality remain wallet
and circuit responsibilities; the public helper does not invent those claims.

Quote constructs the body with zero proof, obtains official mass/actual fee,
then requires isolation PASS and the intended Groth16 proof-decode failure:
engine `ZkIntegrity("ARK serialization error: the input buffer contained invalid
data")`, corresponding Full `SignatureInvalid(...)`, and the two-input Groth16
charge reached. An arbitrary `EvalFalse` or earlier public failure is rejected.
Quote is not an accepted transaction or valid proof.

Response schema is `kpx3-public-native-result/v1`. Quote returns `quote_id`,
official native `transaction`, complete `supplied_context`, `metrics`,
`native_validation`, `transaction_id`, `fee_sompi`, `required_fee_sompi`,
`fee_rate_sompi_per_mass`, `mining_mass`, and nullable
`successor_state_hex112`. Top-level monetary amounts/rates are canonical decimal
strings. Context rows retain all five UTXO fields above. It labels
`verified:false` and `public_checks_reached_G16:true`.

`quote_id` binds the entire canonical native case (all transaction fields,
signature/frame/redeem/Auth/cipher/update bytes and every populated UTXO field),
plus the fee rate. Normalize **only** the 128 active proof bytes to zero.
Version1 transaction IDs omit witness bytes and are insufficient. The digest is SHA256 of exact tag bytes `KPX3/PUBLIC-NATIVE-QUOTE/v1\0`,
then the compact UTF8 official `native::ValidationCase` serde byte length as
u64LE, then those serde bytes (struct field order, not recursively sorted JSON),
then the fee rate as u64LE. The native case normalizes only proof bytes68..196
of the single common input script. Source and public component vectors pin this
serialization before execution.

The owner wallet repeats integer quotes until its authorized fee covers checked
`mining_mass * fee_rate_sompi_per_mass`, updating its Auth-bound fee, reserve and
payout/private-change values before proving. The helper never silently changes
an authorization. Verify reconstructs the body from fresh proof bytes, requires
the expected full-case quote ID, exact fee coverage and actual Full/all-engine
acceptance, and returns `verified:true` only on success.

Both modes report `accepted_chain_backing_proved_here:false` and no network
contact. Honest current-chain authentication and UTXO freshness are caller
responsibilities; the root-only transport rechecks actual UTXOs immediately
before submission. The helper cannot turn a supplied context into chain backing.

## Trial transport proposal

Fork the existing finite TN10 adapter only into this new package. Preserve
exclusive stage+transaction-ID intent files, file/directory fsync before the one
RPC submission, and read-only reconciliation after ambiguity. Never reuse an
old identity/marker directory. Proposed stages are `founding`,
`private-payment`, `bob-private-exit`, and `charlie-private-exit`; private stages
use `KPX3AU01` with exact P/R' distinctions. Root retains broadcast authority.

The frozen public profile schema is `kpx3-tn10-private-trial/v1`, program label
`AUTH528_PRIVATE_CASHOUT/v1`, with domain
SHA256(`KPX3/TN10/PRIVATE-RECOVERY/v1\0` || TN10-genesis32 || fresh-nonce32). Never fund the
public AA development domain or its deliberately public fixture identities.
