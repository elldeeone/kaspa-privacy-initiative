# Live four-wallet stage and resume recipe

This is a reviewable source execution map, not a completed rehearsal. It connects
the existing fresh LIVE66 identity to two payments and four independently
recovered native test-KAS payouts. Commands below have not been executed by this
recipe's author. Use testnet-10 only. Existing LOCAL evidence, histories, trials,
projection/journal files and proofs are never substituted for LIVE inputs.

## Remaining joins

| Join | Current source / required result |
|---|---|
| Accepted quote and outer preparation | New `four-wallet-live/outer_accepted.py` is implemented, source `c1f82574…`, source freeze `7d6eb36f…`. It replays the actual accepted GN2/W prefix, derives the real head/DAA, quotes payments, and prepares the two-child LIVE body. Its review/control scope is separate from live execution. No LOCAL-history bridge. |
| Public request and prefix assembly | New `four-wallet-live/stages.py` implements `request`, `prefix`, and finite `copy-public`; three synthetic schema/alias controls pass. It grants no proof or accepted-state authority. |
| Generic genuine-body finalization | New `four-wallet-lifecycle/accepted_public.py finalize` is implemented, source `d8b5673f…`, freeze `7f140f92…`, with parent source review pending. Existing `finalize_outer.py` remains LOCAL-pinned and must not be used here. |
| Complete accepted fee/recovery ledger | New `accepted_public.py ledger` is implemented under that same pending review. It freshly replays FINAL accepted history and joins four genuine exit results plus four final original-backup scans. Existing live `arithmetic` is only a structural cross-check. |
| Funding descriptor | New separate `four-wallet-live/funding_descriptor.py` is forthcoming with the fixed CLI below. It must derive the descriptor from pinned LIVE funding/anchor bytes and run the complete selected descriptor parser; it confers no Native/currentness authority. |
| All-eight public ingress | `stages.py copy-public` provides all-eight metadata-guarded read-only input copies alongside the separately staged combined55 read-only software. Every public member must actually be staged before invoking frozen c14 helpers. Unstaged retained pages or the signer's internally opened original public record still require an explicit closed wrapper; this is not a finished all-eight execution claim. |

The last row includes constructor public owner records, selected software/SDK,
profile, source contexts, approvals, descriptors, retained pages, sizing,
requests, components, receipts and final summaries. The signer receives the
public constructor export staged outside original owner directories; it must
not reopen `owner-init.json` under an excluded original directory on the host.
Only its own original backup enters its closed signing worker. The accepted
adapters stage all retained pages themselves; `run_owner.py` receives all eight
`--exclude-private-file` and eight `--exclude-private-dir` selectors. Frozen
runner/submit calls must receive only all-eight-staged public inputs, including
**every page referenced by fetch metadata**, or execute inside an explicit
reviewed all-eight wrapper. Copying only `fetch.json` is insufficient.

The finite staging form is `stages.py copy-public --file PUBLIC --file-sha256
PIN`, repeated for every selected public member, plus both `EXCLUDE` roots and
a fresh output. Results are indexed mode0400 files; keep the index-to-input
mapping private. Preserve the relative retained-page layout when constructing
the owned bundle passed to a frozen helper. No caller JSON supplies commands.

New adapters need a finite source freeze and the parent's execution release.
This document changes neither frozen c14/runtime packets nor prior evidence.

## Controller variables and common arguments

All variable values and owner-to-stage mappings belong to a private controller,
outside Git. Use `umask 077`; disable shell tracing/history for private paths;
never publish raw subprocess argv, controller plans or private stdout/stderr.
Each `$*_SHA` is an externally selected whole-file digest obtained through the
all-eight guarded public ingress, not a blind hash of an arbitrary supplied path.

```sh
PROFILE=(--financial-profile "$FP" --financial-sha256 "$FP_SHA")
SOFTWARE=(--software-root "$TREE" --inventory "$INV" --inventory-sha256 "$INV_SHA")
CHAIN=(--descriptor "$DESC" --descriptor-sha256 "$DESC_SHA")
OBS=(--fetch "$FETCH" --fetch-sha256 "$FETCH_SHA" --bundle-directory "$BUNDLE")
EXCLUDE=(--exclude-trial-directory "$LOCAL_ROOT" --exclude-trial-directory "$LIVE_ROOT")
OWNER_EXCLUDE=()
for trial_root in "$LOCAL_ROOT" "$LIVE_ROOT"; do
  for owner in A B C D; do
    OWNER_EXCLUDE+=(--exclude-private-file "$trial_root/owners/$owner/backup.json")
    OWNER_EXCLUDE+=(--exclude-private-dir "$trial_root/owners/$owner")
  done
done
```

These arrays are private command-line conveniences. Public JSON never selects
a callback, executable, script, shell command or software authority. `$TREE`
is the separately prepared read-only combined runtime, not a mutable repo.
Financial profile41c is
`41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a`.
The selected SDK/runtime/profile joins remain required; system libraries and
the host remain trusted premises.

## 1. Fresh identity, source KAS and ordinary GN2 funding

For the current LIVE66 attempt, retain its existing original identity and
backups. A failed used trial gets a new identity with the one constructor:

```sh
python3 -B poc/four-wallet-bootstrap/new_trial.py \
  --identity "$IDENTITY" --identity-sha256 "$IDENTITY_SHA" --destination "$FRESH_TRIAL"
```

The constructor exports only public A/B/C/D records; each original compound
backup stays inside its owner's namespace. Ordinary funding is only to the
fresh LIVE A/C addresses exported by that identity. Never fund an older LOCAL
control identity. Parent arranges the free test-KAS funding resource separately.

1. Capture a fresh confirmed birth anchor with `runner.py anchor`, using the
   selected software/profile and `--trial-directory "$LIVE_ROOT" --output
   "$ANCHOR_OUT"`. Use the all-eight ingress/closed wrapper described above.
2. Collect exactly the fresh A/C ordinary source outpoints and actual UTXO
   contexts into `sources.json`: integer sompi amounts and actual integer DAA;
   no fabricated DAA0 or copied LOCAL source.
3. Prepare, independently sign once per original A/C owner, then combine:

```sh
python3 -B poc/four-wallet-bootstrap/entry_cli.py prepare \
  --profile "$FP" --profile-sha256 "$FP_SHA" --trial-id "$TRIAL_ID" \
  --owners "$PUBLIC_A" "$PUBLIC_C" --sources "$SOURCES" \
  --assets "$GENERIC_RUNTIME" --fee-rate 100 --output "$GN2_PROPOSAL"
python3 -B poc/four-wallet-bootstrap/run_signer.py \
  --owner "$ONE_ORIGINAL_OWNER" --profile "$FP" --profile-sha256 "$FP_SHA" \
  --case "$GN2_PROPOSAL/proposed-case.json" --trial-id "$TRIAL_ID" \
  --assets "$GENERIC_RUNTIME" --fee-rate 100 --output "$ONE_SIGNER_OUT"
python3 -B poc/four-wallet-bootstrap/entry_cli.py combine \
  --profile "$FP" --profile-sha256 "$FP_SHA" --trial-id "$TRIAL_ID" \
  --case "$GN2_PROPOSAL/proposed-case.json" --approvals "$APPROVAL_A" "$APPROVAL_C" \
  --assets "$GENERIC_RUNTIME" --fee-rate 100 --output "$GN2_COMBINED"
```

Run the signer separately for A and C inside the reviewed closed one-backup
wrapper. Its outputs are `client/run/APPROVAL.json`; combine emits
`selected-case.json`. Its local NativeFull result is still not chain acceptance.
The forthcoming separate descriptor builder constructs the exact
`kpx5-gn2-network-descriptor/v1` from the new birth hash, LIVE trial, final
financial SHA, combined founding outpoint and derived initial redeem bytes/hash,
then runs the complete selected descriptor parser:

```sh
python3 -B poc/four-wallet-live/funding_descriptor.py \
  "${PROFILE[@]}" "${SOFTWARE[@]}" "${EXCLUDE[@]}" --trial-id "$TRIAL_ID" \
  --case "$GN2_CASE" --case-sha256 "$GN2_CASE_SHA" \
  --anchor "$ANCHOR" --anchor-sha256 "$ANCHOR_SHA" --output "$DESCRIPTOR_OUT"
```

Select its `descriptor.json` and digest as `$DESC/$DESC_SHA`. False Native,
accepted/currentness and spend-authority flags remain explicit. This new
source still needs its source/control review before execution.

Submit funding exactly once with the fixed selected Node:

```sh
"$NODE" --use-openssl-ca poc/four-wallet-live/submit.mjs \
  --stage funding --trial-directory "$LIVE_ROOT" --trial-id "$TRIAL_ID" \
  "${PROFILE[@]}" "${SOFTWARE[@]}" "${CHAIN[@]}" \
  --case "$GN2_CASE" --case-sha256 "$GN2_CASE_SHA" \
  --journal "$CAMPAIGN_JOURNAL" --output "$GN2_SEND_OUT" --execute
```

The fixed submitter performs actual public preflight, immediately requeries
both exact sources with actual DAA, commits the immutable intent and makes one
RPC request. `RPC_ACK_ONLY` is not confirmation. Fresh fetch plus complete
reconciliation must succeed before a funded claim is used.

## 2. Accepted funding, fresh requests and genuine private children

Acquire and reconcile the funding transaction:

```sh
python3 -B poc/four-wallet-live/runner.py fetch \
  --trial-directory "$LIVE_ROOT" "${PROFILE[@]}" "${SOFTWARE[@]}" "${CHAIN[@]}" \
  --output "$FETCH_OUT"
python3 -B poc/four-wallet-live/runner.py reconcile \
  --trial-directory "$LIVE_ROOT" --trial-id "$TRIAL_ID" \
  "${PROFILE[@]}" "${SOFTWARE[@]}" "${CHAIN[@]}" "${OBS[@]}" \
  --stage funding --journal "$CAMPAIGN_JOURNAL" --output "$FUNDING_RECONCILE_OUT"
```

Set `$FETCH/$FETCH_SHA/$BUNDLE` to the fresh acquisition's exact fetch file,
digest and directory. `FETCHED_PENDING_REPLAY` alone is never balance/currentness
evidence. Reconciliation reruns complete retained Full-page/SDK/native/financial
checks under the remote validating-node, non-atomic checkpoint premise.

The implemented accepted adapter's `quote-payment` operation uses the same
selected profile/software/descriptor/fetch inputs:

```sh
python3 -B poc/four-wallet-live/outer_accepted.py quote-payment \
  "${PROFILE[@]}" "${SOFTWARE[@]}" "${CHAIN[@]}" "${OBS[@]}" "${EXCLUDE[@]}" \
  --trial-id "$TRIAL_ID" --net-principal-sompi 1000000000 --output "$SIZING_OUT"
```

The `SOFTWARE` array includes the required `--inventory` file and external
`--inventory-sha256`. The adapter writes `SIZING.json` by applying `pricing.evaluate` to
the actual accepted snapshot/point/reserve/DAA, net1,000,000,000 and rate100.
Its schema remains explicitly provisional and grants no spend authority.

Create separate B/D requests and proposed prefixes:

```sh
python3 -B poc/four-wallet-live/stages.py request "${PROFILE[@]}" "${EXCLUDE[@]}" \
  --trial-id "$TRIAL_ID" --sizing "$SIZING" --sizing-sha256 "$SIZING_SHA" \
  --recipient "$PUBLIC_RECIPIENT" --recipient-sha256 "$PUBLIC_RECIPIENT_SHA" \
  --invoice-index 1 --output "$REQUEST_OUT"
python3 -B poc/four-wallet-live/stages.py prefix "${PROFILE[@]}" "${EXCLUDE[@]}" \
  --output "$PREFIX0_OUT"
```

Request credit comes only from that LIVE accepted sizing. Do not copy the
LOCAL trial's exit credit. Each owner preparation independently recomputes
sizing and rejects a mismatched credit; the builder itself establishes no
timely-chain or quote authority.

The fixed owner launch form is:

```sh
python3 -B poc/four-wallet-lifecycle/run_owner.py "$OWNER_CONTROLLER" \
  --op prepare-payment --source-kind accepted \
  "${PROFILE[@]}" "${SOFTWARE[@]}" "${CHAIN[@]}" "${OBS[@]}" \
  --backup "$ONE_ORIGINAL_BACKUP" "${OWNER_EXCLUDE[@]}" \
  --request "$REQUEST" --request-sha256 "$REQUEST_SHA" \
  --virtual-prefix "$PREFIX" --virtual-prefix-sha256 "$PREFIX_SHA" \
  --ordinal "$ORDINAL" --manifest "$MANIFEST" --pk "$PK" \
  --workers 14 --fee-rate 100 --execute
```

1. A prepares ordinal0 from prefix0 for B. After successful whole-PK/VK READY
   and genuine child verification, retain only its public `COMPONENT.json` and
   `SUCCESSOR.json` exports from `client-output/run`.
2. Assemble prefix1 with `stages.py prefix --component "$A_COMPONENT"
   --component-sha256 "$A_COMPONENT_SHA"` plus profile/exclusions/output.
3. C prepares ordinal1 from prefix1 for D, using only C's original backup.
4. Assemble prefix2 with the two pinned components, in A-then-C virtual order.
   Each record is exactly `payload_hex3920 || proof_hex128`; its Auth/domain,
   public body and proof-slot structure must join. Prefixes/successors remain
   proposed virtual state, never accepted native heads.

Launch B and D independently with the same accepted source and prefix2, their
own request and original backup, `--op preflight-pending --execute`, and no PK,
manifest or ordinal. Both must produce exactly one decrypted/rederived pending
receipt in `PENDING-RECEIPT-CHECK.json`. No outer GPU work starts before both
checks pass. A pending ACK grants no on-chain authority.

## 3. Fresh LIVE outer proof and genuine NativeFull body

The implemented accepted preparer has this fixed contract:

```sh
python3 -B poc/four-wallet-live/outer_accepted.py prepare \
  "${PROFILE[@]}" "${SOFTWARE[@]}" "${CHAIN[@]}" "${OBS[@]}" "${EXCLUDE[@]}" \
  --trial-id "$TRIAL_ID" --prefix "$PREFIX2" --prefix-sha256 "$PREFIX2_SHA" \
  --w-codec "$CODEC" --w-codec-sha256 "$CODEC_SHA" \
  --r0-host "$R0_HOST" --r0-host-sha256 "$R0_HOST_SHA" --output "$OUTER_PREP"
```

It must require current accepted GN2 with no previous W operations, independently
replay both genuine children, bind the actual W/DAA, and emit new
`validation-case.json`, `contexts.json`, `projection.bin`8301, `journal.bin`424,
metrics/native-codec agreement and accepted-observation-only `PREPARATION.json`.
The case still has the explicit zero outer-proof slot and is not submittable.

Use unchanged reviewed `outer_run.py` source
`da559335c0e071d15b7daee5cd4d256776295c934d5db569c1e13c3d2bf83195`.
Its generic operations accept the fresh pinned LIVE projection/journal. Root's
approved scheduler serializes heavy private-prover/GPU work and records owned
CPU/GPU/resource/cleanup observations; do not run competing heavy jobs.

```sh
python3 -B poc/four-wallet-profile/outer_run.py execute \
  --projection "$P" --projection-sha256 "$P_SHA" --journal "$J" --journal-sha256 "$J_SHA" \
  --exclude-private-root "$LOCAL_ROOT" --exclude-private-root "$LIVE_ROOT" --output "$R0_EXEC"
python3 -B poc/four-wallet-profile/outer_run.py prove \
  --projection "$P" --projection-sha256 "$P_SHA" --journal "$J" --journal-sha256 "$J_SHA" \
  --exclude-private-root "$LOCAL_ROOT" --exclude-private-root "$LIVE_ROOT" --output "$R0_PROVE"
```

Execute must halt0 with the exact new journal. Prove must produce a genuine
succinct receipt at `$R0_PROVE/public-output/result/receipt.bin`. Run the same
fixed CLI's `verify`, then `compress`, each with `--receipt/--receipt-sha256`,
the same `--journal/--journal-sha256`, both exclusions and fresh output. Compress
emits `public-output/result/groth16-receipt.bin` without changing the claim.
Verify that compressed receipt, then run `native-proof` on it; output is
`public-output/result/native-proof.bin`128 plus `report.json`. Pin each actual
new output; never reuse a LOCAL receipt or proof because the image matches.

The implemented fixed accepted finalizer command, pending source review, is:

```sh
python3 -B poc/four-wallet-lifecycle/accepted_public.py finalize \
  --software-root "$OWNER_TREE" --inventory-sha256 "$OWNER_INV_SHA" \
  "${PROFILE[@]}" "${CHAIN[@]}" "${OBS[@]}" --trial-id "$TRIAL_ID" \
  --case "$ZERO_CASE" --case-sha256 "$ZERO_CASE_SHA" \
  --proof "$NATIVE_PROOF" --proof-sha256 "$NATIVE_PROOF_SHA" \
  --projection "$P" --projection-sha256 "$P_SHA" --journal "$J" --journal-sha256 "$J_SHA" \
  --preparation "$PREPARATION" --preparation-sha256 "$PREPARATION_SHA" --codec "$CODEC" \
  --program-sha256 "$ACCEPTED_PUBLIC_SOURCE_SHA" \
  --exclude-private-root "$LOCAL_ROOT" --exclude-private-root "$LIVE_ROOT" \
  --output "$FINALIZE_OUT" --execute
```

For this exact source, `$ACCEPTED_PUBLIC_SOURCE_SHA` is
`d8b5673f95adfb68e8566ff7435dc9bac27ee1a8361388355acbcb667321a1a9`;
its source freeze is
`7f140f92176071b01bbfc55faf8e98bb9f71388bee3bb12688ae1fda5984e341`.
These pins establish source identity, not execution approval or live readiness.

It replays accepted evidence and both children, joins both independent codecs,
inserts only the genuine proof slot, requires unchanged financial bytes/context,
ID/mass/fee, performs fresh positive and five negative NativeFull controls, and
emits `public-output/validation-case.json`. This remains a valid proposal until
actual submission and accepted replay succeed.

Submit once as `--stage settlement`, with fresh `OBS` and the campaign journal;
then fresh fetch and `runner.py reconcile --stage settlement`. The submitter
requeries the exact physical head immediately before committing its intent.

## 4. Coordinator loss, four independent cold exits and final recovery

Remove the coordinator/operator/prover state from each cold owner's namespace.
Each owner gets only its one original backup, selected public software/parameters
and freshly acquired accepted public evidence. A missing backend may halt; it
never enables another owner or an administrator to withdraw.

For each of four privately scheduled owners, serially:

1. Fetch/replay the current accepted head. Launch fresh `run_owner.py` with
   `--op prepare-full-cashout --source-kind accepted`, current `PROFILE`,
   `SOFTWARE`, `CHAIN`, `OBS`, one `--backup`, all `OWNER_EXCLUDE` arguments,
   selected `--manifest/--pk --workers 14 --fee-rate 100 --execute` and a new
   controller. Set `--minimum-payout-sompi 1000000000` for B/D; A/C require at
   least10000000. No original operator path or another owner's path is mounted.
2. Require the one-claim exit, actual quote, genuine proof, NativeFull and
   minimum net payout checks. Retain only public `RESULTS.json` and
   `prepared/validation-case.json` from `client-output/run`.
3. Submit that exact case once using `--stage owner-exit --owner-attempt
   "$FRESH_OWN_ATTEMPT"` plus fresh accepted `OBS`; no campaign journal is
   required. Fresh fetch/reconcile with the same owner attempt must locate
   actual accepted complete bytes and payout. Unknown responses are query-only.
4. Only after this accepted spend, give the next owner the new accepted head.
   Reusing the prior physical head is a stale/double-spend refusal, not a reason
   to weaken the check. Keep the role-to-attempt mapping private.

After the fourth accepted exit, the actual public reserve/head must be0/null
and four distinct payout outputs must be confirmed and queried. Launch four
new no-PK `run_owner.py --op recover --source-kind accepted --execute` workers
from the original backups against the FINAL accepted evidence. A/C must each
recognize two historical spent receipts, B/D one each; all four report zero
unspent claims, one controlled payout-key match and zero unresolved records.

The new accepted rich-ledger driver uses the fixed `accepted_public.py ledger`
common arguments shown for finalization, FINAL `OBS`, and:

```sh
  --exit-receipts "$FOUR_EXIT_RESULTS" --exit-receipts-sha256 "$FOUR_EXIT_RESULTS_SHA" \
  --recovery-receipts "$FOUR_FINAL_SCANS" --recovery-receipts-sha256 "$FOUR_FINAL_SCANS_SHA" \
  --recipient-exit-index "$B_PRIVATE_INDEX" --recipient-exit-index "$D_PRIVATE_INDEX"
```

The two indices stay private. The driver must re-execute accepted replay, then
call the selected lifecycle `ledger.close` with fixed requested nets[1B,1B].
It emits `LEDGER.json` and neutral count-only recovery receipts, closing integer
source KAS = ordinary change + entry fee + outer fee + four exit fees + four
payouts, with reserve0. Change/refunds are not additional useful payments.
Only this completed LIVE join may report complete-workload fees/confirmed
payouts; it still does not qualify cryptographic soundness or financial privacy.

## Resume and abort rules

- No immutable intent yet: repair public staging/preflight, acquire fresh
  evidence and retry that read-only/preparation step. Do not weaken a failed
  financial, root, source or native check.
- Any intent exists, including a crash or unknown RPC response: never send it
  again, delete it, change it, or relabel it. Only fresh acquisition/replay and
  reconciliation may continue. A genuinely failed trial uses a new identity.
- Actual accepted same-ID budget/witness variants may reconcile after full
  actual-body/context/native/financial validation. Preserve the exact original
  intent and both public byte digests; do not impose a new-preparation fee quote
  on historical accepted variants.
- A reorg, conflicting spend or stale near-tip view requires fresh evidence;
  do not infer an empty balance or lack of acceptance from an unavailable page.
- If cooperation aborts before settlement, original A/C owners retain the
  protocol's two direct private-exit fallback path from actual accepted GN2.
  Establish the actual current head first, especially after an unknown
  settlement request. No administrator rescue exists; this two-exit abort is
  separate evidence and is not a completed four-wallet payment campaign.

Completion requires the real final broadcast, accepted confirmations, all four
payouts, four final backup recoveries and rich ledger in the same fresh trial.
LOCAL controls and LIVE accepted results remain separately classified throughout.
