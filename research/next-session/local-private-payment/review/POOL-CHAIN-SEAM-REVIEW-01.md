# Pool chain seams: independent source review

Verdict: no remaining confirmed source blocker at the final pins below. Genuine cached replay and historical CASE3 preflight qualification remain separate evidence; this review performs no network, submission, owner-worker, or financial execution.

| New source | SHA256 |
| --- | --- |
| chain/pool_bridge.py | 9d22f554eb686c9df189ee6375c4c04ed261ee30be74dd33fce3ca9f7c4360e9 |
| chain/preflight_pool.py | 57f6ea1a1f1e5a7f4764ac07610fe5fae11ac570be1545e336aa5b5412eafe1c |
| chain/confirm_pool.py | e56ecffb1df9c88312b600e538d8823a137ff308b4e9ff1c60b5125962d661d8 |
| chain/submit_pool.mjs | 47c695afc9dc229b65fcb9dd0f3d7988a240e40209103436da0aff739656fab1 |

Every explicit source/evidence content read used unchanged helper09. No Original, private STATE, plan, log, event, truth, proving-key, or private content was read or hashed.

## Financial and submission boundary

Whole-byte guarded diffs against frozen `submit_cached.mjs` (`1eb94270…70c50`) show only the added closed pool selectors and the fixed preflight child/output path. Candidate scope/hash checks, canonical official-SDK reconstruction, selected live Node check, TLS/Tor connection, input-context equality and coinbase maturity checks remain unchanged.

The first fresh query still precedes both global immutable reservations. Stage and transaction reservations retain `O_EXCL|O_NOFOLLOW`, file fsync, and directory fsync. The second fresh query remains after durable reservation and immediately before the sole `submitTransaction` call. Unknown/failed replies retain read-only reconciliation status and no automatic resubmission. No signer, private intent path, RPC, or execute flag enters the offline role.

The new preflight wrapper invokes the old cached preflight entry through the selected fixed-role client. The old entry retains native normalization, exact fee `100 * mining_mass`, Native Full/all-input verification, official SDK lossless roundtrip, accepted-prefix replay, exact reserve outpoint/state/value binding, and final native projection equality. The new bridge does not replace these checks with a host success marker.

## Confirmation and cache boundary

The confirmation diff preserves host Tor acquisition. It hashes the newly fetched public evidence, requires one matching accepted transaction, and compares the entire reconstructed native CASE with the selected expected CASE before calling offline replay. Witness, compute budget, input contexts, ID, and storage fields remain included in this comparison.

After genuine replay, the unchanged payout loop checks each observed direct exit against its actual native output and fresh retained UTXO value/script. HISTORY, CONTEXT, CURRENT-ENTRY and RESULTS selectors are collected before the unchanged cache receipt is created. CACHE remains a local controller receipt, explicitly not external attestation. HANDOFF is written only after those checks and selector additions. Output paths change to a fresh pool-only `parent/result`; financial schemas and arithmetic do not change.

## Finding fixed in the new confirmation source

The initial new confirmation retained one HostPolicy instance across host acquisition and the long pool child. The bridge's fresh guard was local to that function, leaving the outer selector reader vulnerable to the already qualified historical-inode false positive.

The author added two phase-local instances of the unchanged HostPolicy: after host fetch returns, before reading its newly created fetch; and after successful pool replay, before reading new export selectors. Independently removing exactly these two lines from final `e56ecf…61d8` reconstructs exact prior `70be014f…5195`. No guard is cleared, no read is skipped, and no financial ordering changes.

## Executed-source and provenance correspondence

Guarded profile `/var/tmp/kpi-local-private-payment-01/campaign/trial-02/pool-seam-01/POOL-SELECTION-02.json`, SHA `8d757fcf000f6270620a62cd4b29fb64076bfe4ff3ad029db4b9606563ba582a`, preserves all 596 static rows and both old role configurations from Profile01. The sole outer source change is the new confirmation pin above.

Independent correspondence checking maps every one of the frozen 68 runtime members to an exact namespace target, identical source path, and expected SHA. Both entries are the unchanged cached replay (`d39b2647…8b1a`) and preflight (`5e1201aa…7285`), with old runtime `30da3b8e…e1be1` and admission `fd47c3f8…db514`. No `.pyc`, `.pyo`, `.pth`, sitecustomize, or usercustomize override is selected.

Server `233ce480…ca7b8` fixes those entry paths/hashes, validates closed role options, fixed financial arguments, admitted path/pin selectors and runtime overrides, then launches the literal old CLI. Client `532a4a88…7535c` binds the selected owned local socket, pool selector, role, request selector and output; successful stdout remains exactly the old program's stdout. The bridge additionally requires zero exit/clean stderr, matching export provenance, stdout/result equality for replay, and candidate SHA/case/trial/stage/mode binding for preflight. The public-only pool has no cache or chain authority of its own.

## Evidence limits

The author's six seam controls and ten perturbations were inspected through report `e82bf999fa3213cf7b8c41e2890e0167500e5ea5c9e9fb2de9f30e633e9d42d4` and test source `3dfbc0f5…6af36`; they were not independently rerun here. They qualify bridge formatting/provenance and the fresh-guard model, not native financial correctness. The separate independent SnapshotStore suite passed 28 public fixture controls (`3425ebdc…fea52`).

Historical CASE3 qualification, actual wrapper/caller selection, fresh live-state checks, and any release remain outside this source-only verdict. No mainnet, privacy, cryptographic correctness, or independent consensus claim follows from it.
