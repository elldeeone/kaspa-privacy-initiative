# Next testnet package: two-owner bootstrap and accepted W history

Read-only investigation, 2026-10-24 UTC. Workspace HEAD
`ad18b65e1472d904d0528520104936592cda65b7` plus the explicitly identified
uncommitted W sources below. This document proposes work; it creates no profile,
key, setup, transaction, funding request or broadcast. Existing evidence packets
remain unchanged. No private key, backup, witness or PK was opened.

**Answer:** two independently held ordinary P2PK funding inputs can create an
initial two-note W output without adding an entry branch to W. The missing work
is a strict GN2 bootstrap/history profile, owner-local ordinary signing, and
accepted-chain reconciliation through every payout. The current public canary
is not ready to receive funds or run a live rehearsal.

## Why GN2 does not require a new W entry branch

The funding transaction executes its ordinary input scripts; its output script
executes only when that output is later spent. W's `OpTxInputCount == 1` rule
therefore constrains subsequent W spends, not the number of ordinary funding
inputs. `wrapper_redeem` accepts State112 with `1 <= n <= 65535`,
`1 <= m <= 131071`, and `m <= 2*n+1`. A correctly reconstructed n2/m1 state is
within those bounds. W does not recognize GN1, GN2, ADMIT or a funding key.
See [wrapper construction](../../../../poc/shared-settlement-native/src/policy.rs)
at lines950–1068, source SHA256
`4e79e161f8cc8f35abcc6ae93f995c51f5b1b9a0c82af307a7e715772594c6ec`.

For the **same selected child domain/VK and outer image**, replacing initial
State112 changes the redeem prefix and P2SH address, while the immutable W tail
can remain identical. This is a source-derived feasibility conclusion, not a
GN2 native execution or accepted funding result. The currently selected tail is
`5c9e15357f07f092e25f272ea40bb92f1c0335574e37e0e4e687297db4e56559`.

That does not authorize funding the current benchmark. Child profile
`492a0981ad04891ea68243f2c8221976f436501acf940e42211bb8773744fbdd`
explicitly says `PUBLIC_SYNTHETIC_DO_NOT_FUND_UNFUNDED_BENCHMARK_ONLY` and
`owner_witness_or_funding_authority:false`; outer selection
`0a288ee94e29503f8483310d13034d8c721870ac6bb49d6b2568b8fe1db0e740`
also denies funding/currentness authority. [ADR0059](../../../../docs/adr/0059-scheduled-private-actions-with-public-settlement-proofs.md)
requires a separately selected financial profile with fresh identities,
parameters and owners. Establishing that fundable profile is a prerequisite
once, not a new setup requirement after each failed trial. A fresh compiled
child domain changes related keys, guest identity and W constants;
byte-identical-tail reuse must not be claimed across that change. GN2 itself
needs no new private relation or primitive.

## Smallest legitimate route

1. **Create one fresh unfunded trial, with owner-local secrets.** Reuse the
   outside-Git, fresh destination, selected network/domain and
   secret-exclusion practices of `poc/private-cashout-trial/trial.py`, rather
   than relabelling its KPX3 profile. Each participant independently creates
   its ordinary funding key and shielded owner backup; the coordinator receives
   only public data. Distinct keys/processes demonstrate key separation, not
   independent people or infrastructure. The eventual constructor must remain
   one command taking minutes; it must not hide setup/proving inside identity
   creation. Once compatible financial proof/runtime assets are selected, a
   retry reuses that reviewed profile with a fresh trial identity, owner/funding
   keys and funding outpoints. Failure alone requires neither a new compiled
   domain nor another setup; exact profile/domain checks remain in force.
2. **Validate GN2 before either signature.** A new explicitly versioned entry
   record should contain exactly two ordered initial Note168/CM/cipher records
   and their selected domain/profile. Derive both commitments, cipher hashes,
   CM/CF roots, positions0/1, cursor2, and the exact one-row empty NF sentinel
   (`m=1`). Require distinct CMs and integer sompi satisfying
   `NOTE_FLOOR=60,000,000 <= vA,vB <= MAX=2,870,000,000,000,000,000`.
   Check the sum without overflow and require `R0=vA+vB <= MAX`; output0 must
   be exactly that reserve to the selected W(S0), with no covenant. Match both
   genuine ordinary source UTXOs, distinct funding-key scripts, their owners'
   chosen return scripts, explicit fee allocation and any ordinary change;
   every ordinary change output must also have no covenant:
   `inputA+inputB = R0+changeA+changeB+entryFee`, and independently
   `input_i = noteValue_i+change_i+entryFee_i`. Both owners must authorize the
   same checked entry/allocation. Funding does not execute W: the new strict
   GN2 validator must independently enforce all initial bounds, CM/CF content,
   liability allocation and recoverability checks, alongside both ordinary
   authorizations. A native-valid ordinary transfer alone proves none of those
   initial W-state properties.
   Each owner must locally decrypt/rederive its own initial receipt from its
   original backup before approving the entry; a ciphertext hash alone does not
   prove delivery or recoverability. Public Note168 entry records expose entry
   value/metadata; this does not establish deposit privacy. No seed, spending
   secret or backup belongs there.
3. **Sign locally, then reconcile the accepted funding head.** Freeze the
   canonical body, all populated input contexts, exact quote and each owner's
   accepted public GN2 transcript. Each owner signs only its own input with
   ordinary Schnorr `SIGHASH_ALL`, exporting a signature/partial transaction.
   Combine signatures without collecting keys, verify both inputs with official
   Native Full/all engines, and recheck exact body/quote before submission.
   After submission, require accepted transaction evidence and the exact live
   output0 (amount/script/outpoint); neither a submission response nor a local
   Full result is confirmation. Replace fake Q0 with this actual transaction
   ID:0 before preparing any child Auth or proof.
4. **Run the actual lifecycle to reserve zero.** Obtain a complete accepted
   public prefix and current W UTXO; quote the actual two-action settlement,
   allocate exact child fees, obtain owner-local proofs and the outer receipt,
   and submit once in this trial identity. Reconcile accepted actual Q1, then
   rescan original backups against complete public deliveries. Each owner
   independently prepares/quotes/proves its private no-append exit against the
   newly accepted head. Reconcile the first payout and remaining W before the
   next exit. Finish only after every recipient claim **and sender change** has
   been consumed, terminal reserve is zero, all payout outpoints have accepted
   confirmation evidence, and each destination matches its owner's derived
   key. Close `funding inputs = ordinary change + entry fee + settlement fee +
   all exit fees + all native payouts`, in integer sompi. Failure means a fresh
   trial identity, not rebroadcasting the used identity or weakening a check.

## Existing strict validators that need a separate profile

| Existing boundary | Why it cannot be reused unchanged |
| --- | --- |
| `poc/private-cashout-trial/sdk.mjs:45` | `sign-founding` requires exactly one input, compute budget10, GN01 and536-byte payload, and accepts one secret. Keep it strict. Add a separately selected owner-local GN2 signer around existing SDK APIs. |
| `poc/compact-batch-lifecycle/history.py:61,71` | `common` requires one input; `validate_genesis` requires GN01/536bytes, one note/reserve, its old two-role redeem and source-only change. Add an explicit GN2 entry validator; do not make ordinary Full substitute for it. |
| `poc/shared-settlement-wallet/recovery.py:45` | `initial` pins constructed-prestate SHA `82ae8087adf61fd65cf20a539d10f446ee31f0f224aec5fcd87b99f0d62a08be`, fake-Q0 kind and explicit non-GN/nonaccepted flags. Keep that study unchanged. New accepted-GN2 replay must derive its anchor from accepted funding bytes. |
| `poc/private-network-recovery/fetch.mjs:67,283` and `network_replay.py:56` | Descriptor/template pins are KPX3-specific (including24417-byte redeem); terminal recognition expects KPX3 Auth4400. They do not discover KPX5 settlement or KPX4 mode0 continuing/terminal W exits. New W profile must decode these bodies and replay their exact semantics. |
| `poc/shared-settlement-wallet/runtime.py:17`, `selected.py`, `poc/current-wrapper-runtime/prepare.py:16` | Exact installed domain/VK/image/PK/codec/software selections are for this benchmark. New financial selections need their own identities and whole-file pins, not relaxed hash checks or a caller-selectable runtime. |

The new accepted-head adapter should adapt the existing fetcher's finite
birth-anchor→fixed-frontier Full accepted-transaction scan, canonical ID/context
checks, unique successor graph, current-UTXO queries and post-query race/reorg
scan. Include both ordinary funding inputs in the founding record, follow
**actual** W transaction IDs rather than virtual child IDs, and reconstruct
every CM/CF/NF/reserve transition with the selected public replay. Reorg,
missing/pruned bodies/ciphers, conflicting accepted successors, stale head or
partial pages are INCOMPLETE. A later fresh accepted scan may recover liveness;
missing information must never become a fabricated empty balance or payout.
RPC observations are non-atomic and retain a trusted-node/transport premise.

## Official signing and current network evidence

Official release tag[v2.1.0](https://github.com/kaspanet/rusty-kaspa/releases/tag/v2.1.0)
resolved again to `01b532e8b553523216471682649693af92f0fd16` on this investigation.
The [SDK signer](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/wallet/core/src/wasm/signer.rs#L34-L90)
supports partial signing and explicit `createInputSignature(..., All)`.
[Per-input signing](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/client/src/sign.rs#L38-L75)
signs matching ordinary scripts and preserves unmatched inputs. Full verification
is required after both signatures; `verify_sig=true` during an incomplete first
signer pass would reject the unsigned other input. Sending two keys to one
`signTransaction` call is unnecessary. These are inspected API capabilities;
no two-key signing experiment was executed here.

[Sighash implementation](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/sighash.rs#L140-L279)
binds ordered outpoints, covered outputs, payload and each own source
amount/script. **V1 compute budgets are not committed by sighash or txid**;
keep independent exact-body/quote/budget checks. The official
[Toccata agent brief](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/agent-brief.mdx#L35-L47)
explicitly distinguishes txid, sighash and full transaction hash.

Read-only RPC observation, using the installed pinned SDK2.1.0; no wallet,
signer, submit API or private file was used:

| UTC observation | Endpoint | Reported state | Observed sink / blue score |
| --- | --- | --- | --- |
| 2026-10-24T00:15:13.036Z | `wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh` | TN10,2.1.0,synced,indexed; virtual DAA604673779 | `ee5197a4eb290c1699cc094d74caa18314adacbcfba3e487d77b599b2b972721` /593063672 |
| 2026-10-24T00:15:14.837Z | `wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh` | TN10,2.1.0,synced,indexed; virtual DAA604673802 | `c7216724d462402f51eb4dbb3ed6e1539aeccf100c8d70927f34ef0fbdb5ac22` /593063694 |

Both reported pruning point
`b4efe03f3c99bc5bbe31c6b6e7ef187513ac4191dea87adadb4f037de5e20c5e`.
At00:17:17.466Z and00:17:18.564Z respectively, both rejected a read of expected
genesis `f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370`
with `cannot find header`. Preserve that negative: these endpoints did not
independently authenticate genesis, and their historical coverage is not an
archive guarantee. The expected hash remains source-pinned in the official
[genesis definition](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/config/genesis.rs#L123-L149).
Use a retained recent accepted birth anchor before funding; long-term recovery
also needs retrievable accepted history beyond a public node's pruning window.
Different endpoint names do not establish independent operators. Availability,
reported version and selected-chain sink samples prove no W acceptance,
current pool, funding-key possession or confirmed payout.

Official[Full accepted-chain RPC fields](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/rpc/core/src/model/message.rs#L2855-L2918)
include removed/added chain blocks and accepted-transaction groups; the new
adapter must consume and retain them. Observed upstream heads are still
rusty-kaspa master `4edcbbccb449f84832afb1ca157904b35f37d006`, docs main
`0ac77d043a802fc8196abfd5812ac2afbd97a2b9`, and vprogs master
`f9b84a863a7c7c20586a9cf947550475e894f72e`. The matching signing blob is
unchanged on observed master. Execution remains selected release2.1.0; no
master substitution. The official[vprogs warning](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md#L1-L7)
still calls it a prototype; this bootstrap does not require adopting it.

## Concrete next package and stop condition

Build **a separately profiled two-owner GN2 and accepted-W rehearsal adapter**:
one-command unfunded identity, isolated ordinary input signing, strict GN2
validator, W accepted-prefix/current-head reconciliation, and a finite runner
through all confirmed payouts. Reuse current W transition semantics and
reviewed private fallback; preserve all old profiles/negative results. Record
the new entry/history contract under RFC0024 and its financial-profile decision
before implementation; this investigation selects neither.

First establish the unfunded two-input GN2/all-engine boundary, malformed entry
and signature controls, accepted-history/reorg fixtures, and compatibility of
the chosen financial artifacts. Then perform one fresh free-testnet rehearsal
under an explicitly selected financial profile. Do not call it ready before
that rehearsal actually confirms terminal payouts. Stop on lack of authentic
entry/history/current head, incomplete data, inconsistent reserve/fees,
unauthorized owner effects or unavailable financial proving assets. Retain
privacy/linkage and complete fee failures separately: confirmed backing and
exits will not repair the known invoice/change linkage.
