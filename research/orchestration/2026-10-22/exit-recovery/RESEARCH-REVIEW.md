> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Current-version exit and recovery evidence review

Date: 2026-10-22 Australia/Sydney. Inspection only: no build, test, proof, network trial, service change, checkout edit, private evaluation read, commit or push was performed.

Repository: `/home/luke/projects/kaspa-privacy-shared-pool`; branch `shielded-kas-research`; observed HEAD `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. The active price-leakage work leaves documentation and new experiment files dirty. This review did not read its private inputs or change its files. References below are repository-relative, with line numbers from the inspected working tree. The cited implementation and historical result files are tracked and unchanged. Applicable [AGENTS.md](../../../../AGENTS.md) and [SECURITY-INVARIANTS.md](../../../../SECURITY-INVARIANTS.md) were read.

## Decision

Do not repeat milestone 2. It already has real v6 proof, original-backup recovery, payment/change and terminal-drain evidence. Key separation has its own genuine v2/v1 regression experiment.

The highest-value missing bounded condition is:

> A current v2 wallet restored from its pre-receipt backup, with original service paths unavailable, can withdraw a minimum-sized v6 claim after another valid claimant wins the reserve-input race, using only its own newly generated authorization and reconstructed public state; both winner orders end in exact native-validated drainage.

A privacy improvement that strands this claimant after one ordinary race is unusable within that exit envelope. This is an evidence gap, not a finding that the relation necessarily fails. Old v3 contention does not close it: that loser had to reprove, whereas v6 deliberately separates historical private authorization from current public settlement. Conversely, v6 sequential saved-proof exits do not demonstrate the recovered client's losing-race flow.

Propose the four-proof, two-branch offline experiment below. It is a bounded preflight, not milestone 3 cryptographic work, a new live client or full recovery/settlement qualification.

## Evidence and version map

| Claim/path | Retained evidence | Established scope and limit |
|---|---|---|
| Current original backup discovers later notes and freshly exits | `poc/shared-pool/WALLET-LIFECYCLE.md:38-66,88-115,159-174`; result commit `bf4505c16bd3f55ee6e4b534b14fece4281c963a` | Six positive proofs: B created after bootstrap, own-key admission, offline receipt, original-backup restore, two-input payment/change, second restore and fresh terminal exit. 32 = 29.6 payout + 2.4 pool fees + zero reserve. Same-host namespaces, synthetic ancestry and expected head; not independent public-data survival or live acceptance. |
| Key-separation continuity | `poc/shared-pool/ADDRESS-KEY-SEPARATION.md:18-31,55-88`; [docs/adr/0030-separate-funding-and-exit-keys.md:27-65](../../../../docs/adr/0030-separate-funding-and-exit-keys.md); commit `52c209296184d880221432fcbf56bb20d3f64d10` | Ten genuine proofs across two fresh-v2 arms and genuine old-CLI v1 control. Original backups unchanged; scan/exit/native payout spend passed. Funding purpose changes; exit purpose, relation/covenant, encryption and parameters do not. Bounded continuity is evidenced, not every older recovery property. Payout index 3 was supplied. |
| Original services absent, first proof after restore, separate host/RPC | `poc/shared-pool/RECOVERY.md:11-35,54-80`; execution checkpoint `6fa1ea3` | H7 restored three compact-version wallets after original prover/HTTP source stopped, using independent public copies and another host/node. All paid; zero liabilities/reserve. Real older-version evidence, not v6 recovery. H7 PK was 478,600,432 bytes; current v6 PK is 962,197,520 bytes. |
| v6 native payout from a saved capability | `poc/shared-pool/TWO-INPUT-TN10.md:14-17,56-92,127-169,193-204`; relation/covenant baseline `bf64f3d17ef17d1bcc7cf368fa4a59e7c675506b` | Two TN10 runs accepted all 15 transactions, six unchanged saved exits for four wallets, full drainage. Clients rebuild public witnesses without keys/PK. One host/correct RPC, known funding roster, sequential launches. Not fresh original-backup recovery, arbitrary admission or competing-reserve liveness. Exact-fee capability cannot be silently repriced. |
| Competing exits and minimum claimant | `poc/shared-pool/CONTENTION.md:19-48,52-76,90-105` | Version 3 changed domain/transcript/VK and used a 26,713,000-sompi note floor. Loser discovers successor and makes a new proof after winner stops. Minimum claimant won both observed live runs; opposite minimum terminal behavior was local testing. Not v6, whose floor is 60,000,000 and current policy fee 40,000,000. |
| v6 minimum amount/native behavior | `poc/shared-pool/TWO-INPUT.md:109-118,135-172` | Constraint fixtures and a 36-case changed-amount mass/policy sweep exist; the sweep does not carry valid proofs. Report explicitly leaves genuine-proof minimum-value native exits open. Normal/fallback mutual exclusion has genuine checks, but is same-claim safety, not two different claimants progressing after a race. |
| Full drainage | `WALLET-LIFECYCLE.md:51-58`, `ADDRESS-KEY-SEPARATION.md:65-88`, `TWO-INPUT-TN10.md:143-169` under `poc/shared-pool/` | Already demonstrated in bounded current offline and older-adapter live traces. The missing composition is minimum claim + clean restore + losing reserve race, not ordinary serial drainage itself. |

A saved fallback is a private optional capability for an existing claim, not additional backing or a substitute when no capability was saved (`docs/rfc/0013-coherent-v6-lifecycle.md:109-114,192-212`). The proposed proof is first generated after restoration, then reused across one unrelated reserve change. Unused authorization/proof artifacts stay private.

## Current implementation map

All implementation references below are under `poc/shared-pool/`. Wallet's last modifying commit is `52c209296184d880221432fcbf56bb20d3f64d10`; circuit's is `bf64f3d17ef17d1bcc7cf368fa4a59e7c675506b`.

- **Backup/keys:** `src/two_input/wallet.rs:22-28,96-157,175-186` accepts exact v1/v2 pairs, pins descriptor/public parameters and stores three secrets. Founder additionally needs its initial note opening. Later notes/saved proofs are not prerequisites. V2 funding and exit purposes differ.
- **Replay:** `src/two_input/replay.rs:229-253,258-332` resolves actual funding parents and checks founding identity, contiguous reserve outpoints, canonical reconstructed bodies, native proofs/signatures and integer accounting. `wallet.rs:258-279` checks supplied endpoint count/full hash. A consistent stale prefix plus stale endpoint remains possible; currentness/acceptance are external trust inputs.
- **Admission:** `wallet.rs:426-465,726-749` requires bootstrap, supported actual parent, matching funding key/script, amount/floor checks and external input signature. It already has genuine offline evidence and is not the new proposed variable.
- **Discovery:** `wallet.rs:299-355` scans ADMIT/SPEND, advances both positions including padding, validates membership, records positioned spentness and rejects credit for individual unusable delivery without blocking unrelated valid notes. DRAIN adds no commitments. `382-404` selects owned unspent claims.
- **Fresh exit:** `wallet.rs:499-525` requires index = minimum selected position, pays selected value minus fixed harness fee, derives restored wallet destination. `560-568,667-711,726-764` check circuit, exact PK bytes/embedded VK, generate proof, settle and run native validation. Result records base head (`630-637`).
- **Rebasing:** `src/two_input/tree.rs:209-259` permits retained historical anchors while requiring current nullifiers unspent. `src/two_input/mod.rs:158-242` rebuilds public witnesses, spends current reserve, binds payout/fee and requires DRAIN for zero reserve. Exercise it only with state returned by actual replay, never deserialized claimed state.
- **Current client gap:** `two-input-client.mjs:23-40` builds a saved exit, asserts current reserve immediately before one submission, and aborts if it changed. It is not a retry/reconciliation loop. Wallet CLI exposes create/receive/funding/inspect/prepare/serve, not live race handling (`wallet.rs:810-864`).

Parameter identities recorded at `WALLET-LIFECYCLE.md:138-144`: PK 962,197,520 bytes, SHA-256 `6f95db952f84420717b3b677e1368bc85776791eb1ccf409cb390a4e4fb39593`; VK SHA-256 `9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef`. This review did not open/hash retained parameter or private directories. Future execution must verify exported public parameter bytes again. No replacement setup is proposed.

## Fee, availability and discovery limits

Current v6 note floor is 0.6 tKAS, payout floor 0.1 and wallet/harness fee 0.4 (`src/two_input/mod.rs:20-22`, `src/two_input/harness.rs:97`). A minimum claim therefore pays 0.2. The relation permits other authorized fees; the wrapper does not offer fee selection. Public witness rebuilding cannot alter an exact-fee proof.

The adopted 2x/5x fee envelope is not merely waiting for another recovery test. Retained terminal mining mass 330,497 costs 66,099,400 sompi at 200 sompi/mass, already above the entire 60,000,000-sompi minimum note; at 500 it costs 165,248,500. These are arithmetic consequences of that recorded shape, not newly measured transactions or market forecasts ([poc/shared-pool/TWO-INPUT.md:143-161](../../../../poc/shared-pool/TWO-INPUT.md); [docs/rfc/0012-useful-privacy-requirements.md:195-203](../../../../docs/rfc/0012-useful-privacy-requirements.md)). Measure the proposed shapes, but keep higher-rate exitability failed/unqualified. A baseline pass cannot waive it; do not assume subsidy or redefine the minimum after results.

Fresh recovery requires exact public PK/VK, descriptor, founding/admission parent bodies, ciphertext-bearing lineage, software and an authenticated current view. Roots do not replace missing bytes. Current lifecycle explicitly leaves missing older parents/ciphertexts and live head authentication open (`WALLET-LIFECYCLE.md:159-174`). H7 is one older independent-copy arrangement, not permanent availability. A same-Forge isolated copy tests input completeness and denied original paths; it cannot establish survival of Forge, all publishers, or a pruned live node.

Native payout spend tests supply a known index (`WALLET-LIFECYCLE.md:57-60`; `ADDRESS-KEY-SEPARATION.md:57-64`). The index is reconstructible from historical owned note positions in this model, but general native UTXO/index discovery is not implemented. Leave this separate gate open; do not add that subsystem to this test.

No new upstream architecture comparison is needed for this implementation gap. Existing source reviews separate retained public bytes, local discovery, current spentness and chain-view trust (`research/shielded-kas-admission-recovery-2026-10-20.md:20-34,44-59,89-113`). Those upstream observations are dated; this review does not assert remote heads remain current.

## Proposed minimal offline test — not executed

### Inputs and isolation

1. Pin current wallet/replay/circuit/covenant/native validator and existing setup. Any tiny test adapter belongs in a separate authorized workspace after frozen-evaluation resources are released; never alter active checkout/binaries/experiment paths.
2. Supply a public-only export of exact PK/VK, parameter pin and compatible software. Generate new synthetic funding, descriptor and wallets. Do not read an existing wallet/funding key, raw private run, fallback or private evaluation file.
3. Use existing synthetic 20-tKAS founder helper. Bootstrap 19.6 to A; initialize B afterwards and seal/hash its v2 backup before receipt. A pays B exactly 0.6, retaining 18.6 change. Two genuine proofs so far.
4. Make and hash-check a separate public file copy. Mount only it, public parameters/software and one original backup into each recovery namespace. No symlinks to original source/controller tree, host home mount or network. Preserve originals outside namespace. Reuse launcher pattern `two-input-lifecycle.py:59-75`, without host-security changes.
5. Stop only this test's original workers. Restore A and B independently, sequentially, and generate each first exit proof against identical reconstructed head H. A authorizes 18.2 payout; B 0.2. B receives no plaintext note, later request/index sidecar or precomputed exit. Each obtains selection/index from its own scan. A founder backup retains its documented initial opening. Total: four genuine proofs.

### Two deterministic branches from H

- **A wins, minimum B loses:** append native-valid A exit. B's original body must reject against the updated lineage. Reconstruct public prefix, call v6 `settle` using unchanged B proof/authorization and current replay state/reserve, validate and append rebased B. B is the minimum-sized terminal exit.
- **B wins, A loses:** start a separate counterfactual history from H. B is the minimum-sized continuing exit. Reconstruct/rebase A with unchanged authorization and drain.

Append must compare consumed outpoints with current lineage. Script validation using an old UTXO context does not prove current spendability. Use actual replay's `reserve lineage discontinuity` check (`replay.rs:266-274`) and complete native validation. These are mutually exclusive synthetic histories, not two accepted payouts on one network.

No new proof should be necessary to rebase an unrelated claim under v6. If unchanged-authorization rebasing fails, preserve that failed condition; do not silently replace the proof or alter fee. A fresh-reproof diagnostic would be separately named, outside the four-proof pass.

### Invariants and failures

| Obligation | Required outcome | Failure |
|---|---|---|
| I-10/I-14 restore | B's byte-identical pre-receipt v2 backup finds 60,000,000 sompi and makes first valid proof in isolation. | Original private paths, another user's secrets, saved proof or private note export needed; no discovered claim; indispensable public bytes unavailable. Safe halt is a recovery failure, not success. |
| I-1/I-2/I-7 accounting | Each branch: 2,000,000,000 = 1,840,000,000 payouts + 160,000,000 pool fees + 0 reserve. A gets 1,820,000,000; B 20,000,000. Ordinary synthetic funding/founding fees separate. Exact replay and native validation pass throughout. | Unpaid tail, underbacking, diversion, hidden subsidy/fee, invalid continuing reserve or unverified transaction. Padded commitment/NF counts must not stand in for liabilities. |
| I-3/I-4/I-6 race safety | Stale body fails for lineage/outpoint cause. Rebased loser preserves proof/auth/payout/fee/NFs. Winner cannot spend again, including before drainage. | Wrong rejection cause, double payout, changed authorization, another wallet's capability or stale body accepted against obsolete context. |
| Minimum boundaries | Genuine B proof passes as both continuing and terminal exit. Both branch results retained. | Works in one order only; placeholder proof or mass-only transaction substituted. |
| Input integrity | Wrong endpoint, omitted body/parent, wrong pool/VK/parameter pin and duplicate/spent-claim controls reject for intended cause. Declared public copy is the only repair source. | Guessed state/witness, original-private-path fallback or unrelated early errors passing for intended controls. No additional proofs required. |
| Evidence scope | Record `chain_acceptance_verified: false`, hashes, path-denial checks, worker stop order, times/RSS and actual native mass/fees per branch. | Presented as TN10 inclusion, live fee adequacy, separate-host durability, current-head authentication, sustained fairness, privacy or cryptographic assurance. |

Optional zero-proof check: derive known payout keys from restored backups and locally recovered historical selections, then validate ordinary spends with existing helper. An externally supplied index does not count as general discovery. Basic key-separation spending already passed, so this is not the main question.

### Estimated cost and scheduling

Four proofs, three cold loads if original A produces bootstrap/payment then stops and A/B each restore once. Serialize all prover processes. Existing component observations: 203–206 seconds/load; 59–60 seconds preparation + proof (`WALLET-LIFECYCLE.md:102-115`). Approximately 14–15 minutes of those components; plan 15–20 minutes on an otherwise idle machine plus artifact I/O. This is an estimate, not a measured result or operational kill timeout.

At most four Rayon threads, one prover. Same-v6 TN10 preparation peaked around 6.44 GiB RSS (`TWO-INPUT-TN10.md:42-49`); allow roughly 8 GiB headroom and record aggregate RSS. This does not satisfy the adopted 4-GiB wallet target by assertion. Each public PK copy costs about 0.96 GB disk. No setup generation or GPU. Queue after the twelve frozen privacy workers release resources; no experiment was run during this review.

## Inspected implementation SHA-256

All files under `poc/shared-pool/`:

| File | SHA-256 |
|---|---|
| `src/two_input/wallet.rs` | `3039fe885379aeec3b2378ee4b881a46e01b5bc1d3e6e68d706852c6a39070e5` |
| `src/two_input/circuit.rs` | `59071901c3abc25daab68c982ef065f8755c09abbb2ce30e6010d821813dd2a7` |
| `src/two_input/covenant.rs` | `3b6d73c1ebada11d156f3020b444c881160e2f4d8eb7ae629a23ac267bf0d96d` |
| `src/two_input/mod.rs` | `255f8e908fcb1c4a76dcc8ebe0ca5f4e9ddbadc8ba46f63036cb413298bc8150` |
| `src/two_input/replay.rs` | `9e2de9ae756e9af65fb3f7c75fff7170e3a06170a8eb85d0b0da05d758b1b66e` |
| `src/two_input/harness.rs` | `1bad02792f96632892487ec6af9aa94aa4fc2f14c6ecab28602f75174286583d` |
| `two-input-client.mjs` | `8a7d0029ce643a7a95609bb0c77fb9468371250c533c79e793b34c1d0793c34a` |

Saved only on Forge at [/home/luke/projects/kpi-orchestration/2026-10-22/exit-recovery-review/REPORT.md](RESEARCH-REVIEW.md). No proposed test is claimed as executed.
