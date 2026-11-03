# Private matched21 caller

`campaign.py` is the concrete caller for accepted native genesis → six local
payments → nine downloaded-software exits → confirmed zero reserve. It performs
no mining or genesis funding. Root releases actual execution separately.

Prepare with `python3 campaign.py prepare --selection PUBLIC.json
--selection-sha256 HEX32 --private-directory NEW_PRIVATE_DIRECTORY --output
NEW_PUBLIC_DIRECTORY --owner-backup ORIGINAL_BACKUP` (repeat the final argument
three times). Backups must be distinct original files under the authorized new
local-payment private root. Only metadata is inspected. `prepare` creates a
private plan and current-head state and performs no network or financial action.

Run with the same selected inputs and directories using `run --execute` after
Root release. The initial standalone qualification must have released the GPU.
The caller uses exactly one sequential GPU pipeline. It durably consumes an
action before the once-submit call. Unknown RPC responses enter fresh read-only
whole-CASE confirmation; restarting a consumed action never retransmits it.
An incomplete action before submission is retained, and a fresh trial is used
if it cannot be resumed. Resource failures never become privacy/fee passes.

The private plan fixes one 5-KAS payment per owner, then one 2-KAS payment per
owner: useful demand is exactly21KAS. `SystemRandom` independently shuffles each
round and the nine exits. Recipients form one privately chosen cycle. Round two
restores original seeds; owners zero/two prefer received notes, owner one spends
change. Convenience labels are recovered from authenticated history and own NFs,
without a private receipt/index map. Each completed owner stage starts from a
fresh runtime and mounts only its single original backup leaf. Exact invoice
authentication uses one read-only private leaf created by the selected recipient
worker; all six invoice leaves are prepared before any payment and the recipient
workers then terminate. The caller never reads/hashes them. Public diagnostics contain generic
action ordinals and confirmed txids, never payer maps, roles, scan indices,
private plans or schedule hashes. Canonical protocol CASE/projection bytes
necessarily contain their normal public NFs and transaction grouping.

The selected JSON has exactly these fields:

- `schema`: `kpxa-matched21-campaign-selection/v1`; `domain_hex32`; `trial_id`.
- `activation`: path/sha256 row for chain's actual `ACTIVATE-HANDOFF.json`.
  It carries confirmed genesis selectors and chain selection/descriptor/assets/
  parameters/codec rows. Ordinary pre-genesis fees are separate from retained
  prefix fees, which already include the genesis transaction.
- `wallet_assets`, `native_fee_policy`, `node`: path/sha256 rows.
- `scripts`: path/sha256 rows `worker`, `outer`, `native`, `submit`, `confirm`.
- `wallet_source_sha256`: exact hashes keyed by `wallet/worker.py`,
  `wallet/payment.py`, `wallet/support.py`, `recovery/history.py`,
  `integration/native_fees.py`. These source leaves are copied into each stage.
- `native`: path/sha256 rows `host`, `program`, `engine`, `codec`, `component`,
  `selection`, matching the selected new image/profile/keys.
- `fee_cap_sompi`: explicit positive integer owner-approved payment/exit cap.
- `cold`: the downloaded finite release interface below.

Every path/sha256 row has exactly `path`, `sha256`. Public input reads use the
root's guarded reader. No old trial or whole unauthenticated directory is
mounted. Trusted system runtime mounts are inherited from the root's reviewed
offline bubblewrap helper. Private logs/plans/state remain under the protected
caller directory and are never read or hashed by the supervisor.

The `cold` interface selects **actual downloaded bytes**, rather than a local
unpacked build. It has `download_receipt` (path/sha256), `files` (finite owner
closure), `worker_target`, `wallet_assets_target`, `wallet_assets_sha256`,
`native_fee_policy_target`, `native_fee_policy_sha256`, `native_files`,
`native_targets`, `native_selectors`. Each file row has exactly `target`, `path`,
`sha256`, boolean `executable`; every target is under `/public`. Owner closure is
downloaded software + the exact public ExitPK, three manifests and public
history/context. Spend/Output PKs, original services and other backups are absent.
The root-selected download receipt is an explicit acquisition/retention trust
boundary; actual off-host recovery and independent retention remain separate.

Receipt schema is exactly `kpxa-downloaded-recovery-receipt/v1`, classification
`ACTUAL_TOR_TLS_DOWNLOAD_AND_INVENTORY_VERIFIED`, transport `TOR_SOCKS5H_TLS`,
`inventory` (path/sha256 row), `artifacts` (exactly two rows, software archive and
ExitPK, each `path`, `sha256`, integer `bytes`, HTTPS `origin_url`), and `files`
(each `path`, `sha256`, integer `bytes`). Every retained artifact is independently
hashed and sized through the guarded reader. Files must equal the inventory's
22 payloads under the downloaded unpacked root, its exact `INVENTORY.json`, and
the downloaded ExitPK with hash/size from the selected role manifest. Every
mounted cold leaf must appear in that exact map. A flag or a local unpack alone
cannot qualify the acquisition.

`native_targets` has exactly `validator`, `engine`, `codec`, `component`,
`selection` logical paths under `/public`; `native_selectors` supplies their
public path/sha256 rows for the latter four. `native_files` is exactly seven
leaves: those five targets, `/public/verification/native_case.py`, and adjacent
`wire.py`. This native stage mounts no prover, PK or network. It uses only the
downloaded verifier/engine, the completed direct proof and public CASE/journal.

Every action is qualified as a whole CASE before submission and confirmed
against the accepted whole CASE including witness, budget and entry contexts.
Nine native payout UTXOs and the final zero reserve must be observed. Final
accounting is ordinary pre-genesis paid fees plus final accepted-prefix fees;
the useful denominator stays21KAS. Old frozen privacy/fee results are unchanged.

Public controls: `python3 -m unittest -v test_campaign.py`; real component
matched control `campaign_fixture.py`; actual finite owner IPC control
`caller_control.py`. Their supplied-context/known-public-seed results do not
establish private seed handling, testnet confirmation or global anonymity.
