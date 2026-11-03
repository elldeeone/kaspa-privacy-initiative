# Public replay boundary

Implemented interface for the current KPX2 profile. This module consumes public
data only and does not scan keys, sign, prove, submit transactions or select funds.
The measured results and their limits are in [RESULTS.md](RESULTS.md).

## Input

`replay(descriptor, fetched, native_validator=None, *, context="NETWORK_FETCH")`
takes a user-selected public descriptor and fresh data obtained by the separate
network fetcher. The selected
founding outpoint is an explicit instance-identity assumption: domain/policy
coherence does not select a canonical instance among separately funded copies.

Descriptor schema `kpx2-recovery-descriptor/v1`:

- `schema: "kpx2-recovery-descriptor/v1"`;
- `network_id: "testnet-10"`, `genesis_hash_hex`, `domain_hex32`;
- `founding_outpoint: {transactionId,index}`; index is zero for this profile;
- `birth_start_hash`: accepted-chain scan anchor before founding;
- `initial_redeem_hex`: complete singleton State112 + immutable policy bytes;
- `immutable_policy_sha256`: SHA256 of redeem bytes after offset114;
- `vk_hex328`: the selected native Groth16 VK, present in the immutable policy.

These nine fields are exhaustive; additional fields reject. The descriptor's
complete canonical JSON digest is retained by replay: SHA256 of recursively
sorted-key, compact UTF8 JSON, with `ensure_ascii=False`. The
receiver/user must authenticate the descriptor; an arbitrary supplied hash is
not a trust root. A descriptor contains no operation list, payments, actor labels,
snapshots, notes or secrets.

The explicit benchmark-only keyword `context="UNPROVED_SYNTHETIC"` accepts a
different `kpx2-unproved-synthetic/v1` schema with declared input/current contexts
and **no fake accepting headers, confirmations or SDK-ID attestations**. It keeps
all public state, witness, policy, lineage and value checks, but returns
`completeness.complete:false`, `public_replay_complete:true`, and unchecked
crypto/acceptance status. Default network replay and the live wallet reject that
schema. No benchmark result is accepted state, funds, note usability or a full
fresh-recovery qualification.

Fetcher schema `kpx2-network-fetch/v1` has:

- matching `network_id`, `genesis_hash_hex`, `descriptor_sha256`;
- `transactions`: rows with canonical SDK `transaction`, actual
  `accepted_input_contexts`, `accepting_block_header`, and
  `confirmation_policy` (strict sink blue-score distance > min>=20);
- `coverage`: full start-anchor, finite frontier and frozen initial-sink headers;
  the exact frontier must be reached. Per-row sink/depth metadata must match that
  frozen sink and depth, and accepting score must lie after the anchor and at or
  before the frontier. Missing/pruned/removed records prevent completion;
- `current_view`: a checkpoint, exact consumed-input/head/payout queries, and a
  completed finite post-query delta from the scan frontier. Queries bind
  outpoint, amount and full script, with `queried:true` and an actual `entry` or
  null. Consumed input entries must be absent. A related new successor or removal
  in the post-query delta requires a fresh scan.

Actual input entries contain exact outpoint, integer sompi (canonical decimal
string), full version-prefixed SPK, block DAA score, noncoinbase status and null
covenant ID. The public replay never substitutes an operator's local-check
receipt, declared snapshot or intended amount for these records.

## Replay

Start at the selected founding transaction, derive singleton note commitment,
delivery, sentinel and exact reserve. Follow spends of its output0 by actual
outpoint graph, not operation positions or known successor IDs. Dispatch only
supported payload magics. Verify exact input/output conservation, current State112,
immutable P2SH body, sequential CM/NF witnesses, framing, domains, widths,
integer/count/floor bounds, public note/ciphertext binding and native payouts.

Maintain sparse CM and NF trees incrementally. Physical indexed-NF append order
is retained; logical ordering is unsigned LE256. An already observed occupied NF,
duplicate accepted transaction/spend, competing successor, missing middle record,
truncated terminal transition, incomplete scan, stale/missing head or corrupted
payload rejects/incompletes. Lack of an address balance is never terminal zero.

Without a local native validator, proof validity and signatures retain the
explicit selected validating-node acceptance premise. Public hash replay alone
does not validate Groth16/Schnorr or establish independent consensus. A separately
selected generic public native validator may execute actual script/Full checks
without any PK; its source/binary identity and reports must be recorded.

## Output

`kpx2-independent-replay/v1` exposes:

- descriptor digest and network/genesis/domain;
- `deliveries:[{position,cm,ciphertext}]` reconstructed from actual bound payloads;
- `nullifiers:[{value,next_value,next_index}]` in physical append order;
- `head:{outpoint|null,state_hex112,reserve_sompi,current_redeem_hex|null,
  current_utxo|null,observation_checkpoint,accepting_block_header}`;
- inferred `operations` with public previous/current state and amounts;
- `payouts:[{transaction_id,outpoint,amount_sompi,script_public_key,cm,position,
  note_hex168,queried,current_utxo|null}]` from validated native reveals;
- `completeness:{complete,public_replay_complete,terminal,acceptance_trust,
  scan_anchor,frontier,view_is_atomic:false,independent_consensus:false,
  durable_data_availability_proved:false,
  orphan_disclosure_history_complete:false}`;
- `local_native_validation`, `groth16_and_signatures`,
  `sdk_transaction_id_validation` and `context` state the verification scope.

There is no owner label or expected-payment map. The separate wallet derives
ownership from its one seed-only backup and checks the derived current snapshot
before creating a witness. Historical spent receipts remain discoverable from
the final state and can be matched to their public reveal payout by CM/position.
A historical payout is allowed to have a null current UTXO after a legitimate
later native spend. Query observations are finite and non-atomic; they are not a
durable promise about future unspent status.

## Reuse and limits

Reuse the exact published KPX2 SHA/HMAC/Merkle encodings and immutable V2
receiver arithmetic; preserve the old finite checker and its manifests. This
adapts Orchard/RAILGUN-style local reconstruction from retained public ciphertexts
and Aztec-style indexed spent-state witness updates, without importing their
cryptography, tokens, governance or chain guarantees. Source references are in
the new workstream's SOURCES and the prior pinned PRIMARY-SOURCES comparison.
The actual positive is the already completed TN10 lineage, fetched anew, with
local Full/script validation of every discovered pool body and one genuine
wrong-transcript Groth16 rejection. It contains no new spendable pool note.
A 10,000-operation synthetic cost run is explicitly unproved and cannot establish
chain acceptance, actual packet availability, privacy, or reference-device p95.
