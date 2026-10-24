# Integrated lifecycle phase API

This is the new ADR0064/KPX8 implementation. ADR0063/P0 and prior funded
profiles are unchanged. Public structural checks, genuine component proof
verification, outer receipt verification, native Full, accepted-chain replay and
confirmation are separate facts. No input JSON flag can establish any of them.

## Trusted scheduling and private boundaries

`runner.py` supplies `StageRunner` and a first `initialize` command. All fresh
wallets, MPC inputs and controller plans/logs stay below the predeclared
`/var/tmp/kpi-owner-private-lifecycle-01/private`. Public files stay in its sibling
`public`; public parameters/software stay in `assets`.

The owner launcher has separate `--private-run-directory` and public `--output`
directories. Its output contains only `PUBLIC.json`. `Ingress` registers each
fresh public output before launching its producer, accumulates metadata-only
private inode exclusions, rejects renamed/hardlinked private files before
opening them, validates the exact typed export and then copies the public bytes.
It never exempts a path inside the private parent. Raw argv, plans, owner maps,
MPC input/engine logs and seed contents/hashes are not public inputs.

Initialization accepts an externally selected source manifest:

```json
{"schema":"kpx8-lifecycle-source-selection/v1","files":[{"path":"/absolute/public/source.py","sha256":"...","bytes":123}]}
```

It authenticates that finite closure before creating owners and again before
every stage. Each stage runs under its own observed systemd cgroup. The
initializer runs three fresh isolated owner jobs in parallel; it returns only
their participant IDs, initial authenticated public GN3 rows and funding keys.

## Public driver

Every phase uses:

```text
python3 -B poc/owner-private-lifecycle/integration/driver.py PHASE
  --exclude-private-root OLD_LOCAL
  --exclude-private-root OLD_LIVE
  --exclude-private-directory WHOLE_CURRENT_PRIVATE_PARENT
  [--exclude-private-directory OTHER_RETAINED_PRIVATE_PARENT ...]
  --output FRESH_PUBLIC_DIRECTORY
```

All file selectors below are two arguments, `FILE SHA256`.

1. `genesis --case GN3_CASE --founding-selection GN3_SELECTION --trial-id UUID`
   calls the strict signed GN3 financial-history parser. It extracts the three
   exact 496-byte rows from that transaction and joins independently rebuilt
   initial roots, reserve and outpoint. It writes `HISTORY.json`,
   `CHECKPOINT.json` and `GN3-SEMANTICS.json`. **This still requires actual native
   Full plus accepted-chain replay before being called funded/current.** The
   local rehearsal remains supplied-context evidence.
2. `context --history HISTORY --component-profile-sha256 SHA --fee-sompi INTEGER
   --native-tail-hex HEX` creates a selected premix context. It contains current
   roots, physical head/reserve and exact fees, never the selected private input
   note's commitment or position. The fee split is `F//3,F//3,F-2*(F//3)`.
3. `session --history HISTORY --context CONTEXT --program-sha256 SHA
   --participant-id ID0 --participant-id ID1 --participant-id ID2` makes the
   canonical KPX8 session for the unchanged complete-row stock MPC program.
4. Isolated owner `invoice`/`prepare` operations use that session and complete
   history. READY exposes participant/session/NF/CVin and no input CM/position.
   Run the new construction adapter's public `prepare`, then actual `run` using
   three opaque private input-directory handles. All three genuine contributors
   must complete; a subset is never a successful mixed round.
5. `build --history HISTORY --context CONTEXT --session SESSION --mixed MIXED
   --ready READY0 --ready READY1 --ready READY2` reconstructs the full current
   CM/indexed-NF history, builds all sequential insertion/append paths and checks
   a separate networkless public-only assembler returns exactly the same body.
6. `native-project --body BODY --native-codec CODEC --exit-vk VK
   --outer-image-hex32 IMAGE --component-profile-sha256 SHA --compute-budget N`
   builds the canonical native case/projection/journal. Its default proof is
   zero and **never** establishes financial or native acceptance. Optional
   `--proof FILE SHA` attaches a genuine completed outer/Exit proof.
7. After each owner has independently checked its own MPC output, all public
   proofs, current history, whole pool, payment/change inclusion, balance and
   exact effects, `finalize --projection PROJECTION --spend-public AUTH0
   --spend-public AUTH1 --spend-public AUTH2` attaches the three exact-statement
   genuine Spend proofs. Run `native-project` again on the final body.
8. `verify --projection PROJECTION --verifier-host HOST --execute` requires the
   genuine nine-proof predicate and independent Arkworks pairing reference.
   Actual guest execution, GPU proving/compression, separate receipt
   verification and genuine native Full remain subsequent root-owned jobs.
9. `append --history HISTORY --case CANONICAL_CASE --projection PROJECTION
   [--session SESSION]` plus the native codec/image/profile/Exit-VK selections
   requires the codec to reproduce that exact projection from the canonical
   case. It appends the actual successor transaction's output-zero point. Live
   acquisition must independently confirm this exact case before the history is
   treated as accepted. No callback or `accepted:true` bypass exists.
10. Repeat the genuine mixed round from the actual successor. The selected
    workload is **two rounds**: at least one round-two participant spends a
    recovered incoming payment and another spends recovered private change.
    Three genuine spends create six outputs each time, leaving nine unspent
    notes after round two. No fake extra activity is an anonymity claim.

## Direct exits and cold recovery

Freeze the complete public history/checkpoint and authenticated recovery asset
closure immediately after round two, before original coordinator/shared-prover
loss. A final empty-wallet history alone cannot demonstrate cold recovery of
spendable funds. Fresh clients restore only their original seed backup and
acquire the public assets/history independently.

The wallet's `exit-ready` export discloses the chosen NF, gross full-note claim
and native recipient SPK, all of which the eventual native exit exposes. It
discloses no CM/position. `exit-body --history HISTORY --exit-ready READY
--fee-sompi INTEGER` constructs the single-NF/no-CM-append 1632-byte body.
The native codec's exact quote sets its fee before authorization. The restored
owner independently rescans the same history, checks `value=payout+fee`, all
native effects/current state/NF insertion/own recipient and produces Exit152.
The native policy verifies that proof directly, without MPC or shared RISC Zero
proving. After each confirmed exit, independently acquire and reconcile the
latest public head before preparing the next; do not reuse a stale checkpoint.

Nine genuine direct exits must consume all nine remaining notes, with all nine
native payouts confirmed and zero terminal reserve/user liability. Final fresh
seed-only scans must find no unresolved/spendable claims. `ledger.complete`
independently checks exact physical outpoint lineage and integer conservation
over the whole selected acquisition/founding/two-round/nine-exit DAG, including
all fees. Its declared useful-payment denominator is explicit and is not
derived from hidden payment values by that arithmetic function. The 2% fee
target is a separate verdict; financial completion cannot erase a fee failure.

## Existing construction reuse

`construction/kpx7_mix.mpc` is byte-identical to the executed ADR0063 Source04
program. The engine image/binary, prime, random-key sort, complete 520-byte rows,
fixed 2695-byte owner input and original caps remain unchanged. The additive
adapter selects the KPX8 domain and transport schemas; the program's literal
`KPX7_SESSION/ROW/DELTA` transcript tags remain unchanged. The session digest
binds the full new-domain descriptor. This is reuse of the same computation,
not an inherited proof that the new protocol composition is private.

The new finite controls run with:

```text
python3 -B -m unittest -v test_history.py test_state_ledger.py \
  test_ingress_construction.py test_coordinator.py test_exits_quote.py \
  test_live_context.py
```

These include an actual public-only bubblewrap assembler, independent retained
NF path consumption, two-round/nine-exit structural replay, stale/cross-session
roots, current outpoint and integer fee joins, missing payouts, private inode
rename/hardlink refusal and new/foreign-domain transport checks. They are not
genuine financial proofs, chain results or privacy qualification.

## Live current-entry and single-exit handoff

For an actual chain round, call `rounds.run(..., current_entry=selected_entry)`.
`selected_entry` has exactly `outpoint:{transactionId,index}` and
`entry:{amount,scriptPublicKey,blockDaaScore,isCoinbase,covenantId}`. Convert
canonical SDK decimal strings to Python integers at the acquisition boundary.
The adapter requires the exact history point/reserve/selected policy,
noncoinbase/null covenant and a canonical u64 birth DAA. It carries that real DAA
into both native case construction and exact quotes. The local default zero
does not establish an actual-chain context. Preflight must independently
reacquire and compare the entry; it must not silently rewrite a candidate.

`live_exit.prepare(runner, output, party, participant_id, history_selector,
assets_selector, native_selection, current_entry)` builds **one** genuine
full-note Exit candidate against that current head. Authenticated owner
emptiness is a separate result. A nonempty result has the actual owner proof,
exact selected DAA, unchanged approved fee and actual Native Full/all-input
verification. This function neither broadcasts nor appends accepted history.
The live controller must submit once, independently confirm/replay that exact
case, then select the next current checkpoint before calling it again. The
local nine-exit loop is not an accepted-chain controller.

For restored infrastructure, `validation.native_full(..., validator=PATH)` can
use the restored native binary; its fixed SHA remains
`077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061`.
All validation runs in a public-only networkless namespace. Restored wallet
ASSETS paths may change only to independently authenticated byte-identical
programs/parameters; the component/profile/image/Exit-VK identities do not.
