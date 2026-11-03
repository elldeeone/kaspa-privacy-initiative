# ADR 0069: Separate read-only RPC client

Date: 2026-10-26

Status: Accepted for bounded research/testnet acquisition. Financial confirmation
and complete trial readiness require their own execution evidence.

## Decision

Run network RPC in a dedicated worker, separate from synchronous acquisition,
source guards and the original financial SDK. The worker permits exactly five
read-only methods: `getServerInfo`, `getBlockDagInfo`, header-only `getBlock`,
`getUtxosByAddresses` and Full `getVirtualChainFromBlockV2`. It receives no owner
key, Original, private plan/state or signing/submission request. Typed IPC is
single-flight; malformed fields, reply IDs or early EOF fail acquisition.

Build its network-only SDK from rusty-kaspa
`01b532e8b553523216471682649693af92f0fd16`, with the sole request-timeout source
change **60,000 → 900,000 milliseconds**. The separate Tor/TLS bridge and SDK
worker keep their event loops runnable during parent-side work. Fixed TN10
peers, loopback-only worker URLs and no resolver/direct fallback remain required.
Opaque SDK fields are materialized explicitly. BigInt/uint64 values cross IPC
as exact decimal strings; booleans and legitimate finite Number fields retain
their types before the existing validation rules.

The new outer acquisition profile (profile8) and acquisition-source sidecars
record this network dependency separately. They introduce no financial
authority. The original financial/header/transaction SDK, financial runtime
`30da3b8e5573248f20753173654723cf683e3e44066ee1b6e6b0f64bbf2e1be1`,
admission `fd47c3f8c6ae75d03be3eb335782bd68ac88e53ddbc7f6650929d6470d3db514`
and submit source `47c695afc9dc229b65fcb9dd0f3d7988a240e40209103436da0aff739656fab1`
remain unchanged. Preserve proof/native Full replay, value/range and current-state
checks, local-cache admission and consumed-submission gates. Network responses
and sidecars cannot authorize spending or grant an external cache admission.
Raw local profiles/routes remain unpublished.

## Qualification and limits

The retained-response offline qualification is
`26bf0bd394c3042d234efd8d7288eeb411048de32f19249846d68db88d7a68e5`.
It recomputed **1,991 headers** with the original SDK and scanned **33,616
transactions**, including version-range checks. It fully checked the known
CASE10 body, populated input contexts and transaction ID, and observed CASE11's
exact payout UTXO. This is nonvacuous acquisition/compatibility evidence;
it is not complete history/native financial replay or payout confirmation.

The two full-page calls took approximately **22.50 and 52.07 seconds end to
end**, including IPC/materialization/parsing. Neither exceeded the old 60-second
deadline. The 900-second setting is source/build-bound; this evidence does not
empirically demonstrate a longer request or prove the cause of earlier
WebSocket disconnects. The corrected offline pass made no new network calls;
it reused the captured responses and their recorded call timings.

Original capture failure
`ef70d742ea149aba5f4cece2ae489ed378500ac98eb957feec283dbb0baddeab`
remains `FAIL_PRESERVED`. The offline correction retains original unsigned
integer decimal lexemes when loading Native CASE JSON expectations, avoiding
unsafe Number rounding. It changes none of the existing whole-body, SDK,
range, header or input-context checks. Raw decoded-byte identity is not claimed.
The alternate JSON-RPC fallback remains source-only, held and unqualified.

Profile8's full financial confirmation remains a separate execution gate.
This component qualification establishes no final payout count, zero reserve,
fee target, independent recovery, privacy, production safety or security audit.
Missing/malformed acquisition must halt safely; it must never relax financial
checks or trigger rebroadcast of an already consumed submission.

## Source identities

- [Selected network SDK](../../poc/local-private-payment/ingress/BORSH-RPC-SDK-01.json),
  `4bb8ca2f39859b9b9809ccc34f4981e985bb2141624cf65f846c37f0e430dc62`.
- [Worker](../../poc/local-private-payment/ingress/readonly_borsh_worker.mjs),
  `224c869304f91dfbef68275cc68e8031535c02d4a46078fecd46a042bb7a7530`;
  [parent facade](../../poc/local-private-payment/chain/readonly_borsh_rpc.mjs),
  `73293b497d617169db86f94716f18b20efce336fddf3e2af18eb6e718e645da2`.
- [Independent source review](../../research/next-session/local-private-payment/review/READONLY-BORSH900-INDEPENDENT-SOURCE-REVIEW-01.json),
  `10761086ca229ef873c7b38e0b67a4e18bac8286adef0f134d92482915913e94`.

This decision changes acquisition strategy, not the native protocol, keys,
profile/KDF/Spend/Exit rules, fees or permissionless exit authority.
