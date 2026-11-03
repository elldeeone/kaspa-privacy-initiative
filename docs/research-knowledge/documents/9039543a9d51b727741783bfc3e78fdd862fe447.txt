# Independent network fetch contract

Status: prospective source/API contract. No replay, signing or payout result is
claimed here. Read-only TN10 RPC access is authorized; no submission API exists.

## Bootstrap

`fetch.mjs DESCRIPTOR NEW_OUTPUT [--rpc URL ...]` reads one public
`kpx2-recovery-descriptor/v1` object containing:

- `network_id: "testnet-10"`, pinned `genesis_hash_hex`, `domain_hex32`;
- `founding_outpoint: {transactionId,index}` and `birth_start_hash`, a retained
  accepted-chain anchor preceding founding;
- `initial_redeem_hex`, the expected public singleton script preimage, and
  `vk_hex328`, plus redundant `immutable_policy_sha256`. The exact nine fields
  include the schema. The script commits its State112/domain/immutable policy/VK.

The bootstrap is a user-selected public pool identity, not a supplied current
state. It contains no stage list, other operation IDs, payment values, actor
labels, snapshots, paths to bodies, local-check receipts or private material.
The new client accepts only these fields, verifies their encoding, State112/domain,
version-zero P2SH and fixed official SDK identities. The app-bundled approved
stateless policy template is authenticated before parsing/patching. Only its ten
canonical D32 pushes and one VK328 push are replaced; the complete resulting
bytecode must match. A caller-selected hash cannot select arbitrary new semantics.
The node's claimed network/version/sync/index status remains a trusted assertion.
Multiple endpoints provide availability/corroboration, not independent consensus.

## Discovery

Freeze an actual initial sink/header and walk its selected parents to the nearest
frontier with strictly greater than20 blue-score depth. Traverse
`getVirtualChainFromBlockV2` from the pinned birth anchor using explicit Full data
and minimum confirmation count20, stopping only at that exact finite frontier.
Persist every decoded page compressed with its exact uncompressed SHA256,
request cursor and source. Expand SDK `CompressedParents` explicitly before
JSON persistence; normalize blue work to native fixed48-hex digits and u64 values
to decimal strings. These retain decoded RPC semantics, not wire Borsh bytes.
Recompute every header hash with the pinned SDK. Verify returned hash/header
correspondence, integer score depth and cursor
progress. Do not jump to a newly fetched sink and thereby skip unseen data.
Reorg/removal or retention/pruning gaps return `INCOMPLETE`; they never fabricate
an empty recovered balance. A fresh scan may restart at the original retained
anchor against another endpoint. No stale partial scan is spliced across sources.

Select the descriptor's founding transaction and possible subsequent reserve
spends from actual accepted bodies. Candidate matching uses input outpoints and
the public KPX2 domain/script framing, never expected six operation IDs or names.
Replay follows the exact reserve graph and independently checks all state updates.

Actual founding payload is536 bytes: `KPX2GN01 || D || Note168 || CM32 ||
cipher264 || SHA256(cipher)`. This corrects an earlier finite-adapter narrative;
the original accepted body and native source are authoritative and unchanged.

## Output

`fetch.json` (`kpx2-network-fetch/v1`) contains descriptor/hash, selected source,
SDK pins, start/end cursor, scan/confirmation coverage, removal status and pages.
Each transaction row has:

```text
transaction: canonical SDK body (u64 fields are decimal strings),
accepted_input_contexts:[{outpoint,amount_sompi,script_public_key,
 is_coinbase,covenant_id,block_daa_score}],
accepting_block_header,
confirmation_policy:{min_confirmation_count,accepting_blue_score,
 sink_blue_score,actual_blue_score_distance,passes},
network_id,genesis_hash_hex
```

The current view queries exact discovered candidate heads and payout scripts,
with `{outpoint,script_public_key,queried:true,entry:<canonical UTXO>|null}`,
observation sink and an independently fetched post-query chain delta. Missing
current head without a verified terminal transition is incomplete. RPC views are
not atomic. No permanent finality or durable archival availability is claimed.
The post-query delta is itself paginated to a second fixed confirmed frontier;
removals or a newly confirmed related head spend invalidate this reconstruction.
This first bounded client restarts rather than incrementally retaining a verified
prefix on an active pool; sustained-activity liveness is not qualified.

No private seed, invoice, owner label or decrypted receipt is sent to RPC. The
fetcher queries the shared pool/candidate public outputs; ownership discovery
happens separately in a network-isolated recipient process.

## Decisive checks

Before the live scan, freeze code/descriptor/source/stop classifications and
test truncated pages, changed network/script versions, conflicting duplicate
transactions, omitted founding/links, removals and endpoint failure. An absent or
pruned archive must remain `INCOMPLETE`. Successful read-only live replay of the
known completed trial demonstrates network reconstruction of that trace, not
recovery of an unspent liability or a new independently generated exit.
