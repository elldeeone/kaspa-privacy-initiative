# Coverage of the original research histories

[Knowledge guide](README.md) · [Commit index](commits.md) · [Document index](sources.md)

Snapshot: **369 commits, 2341 distinct document versions, 24 local branches, 14 fork branches, one upstream branch, 42 merged upstream pull histories, two recovered commits and 15 unfinished research notes**. All text below is committed on the current research branch. The original historical audit covered 363 commits; six completed consolidation commits extend the source checkpoint.

## Original branch tips

These describe the pre-consolidation snapshot. Counts and audit notes are historical; in particular the old 11 tooling failures have since been repaired, and unmatched files have since been privately preserved. Same-tip aliases share documents; their uncommitted work was handled separately.

| Scope | Original branch | Exact tip | Historical role / unique knowledge |
| --- | --- | --- | --- |
| fork | `docs/kpi-orchestration-2026-10-22` | `6b4fc65d5e64a91a134e722ff88ebc429960abe9` | Local tip is nine commits ahead of its GitHub counterpart. Contains cross-reviews, controls and deferrals, not a separate payment implementation. Three untracked v2 scripts are not committed anywhere. |
| fork | `main` | `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1` | Matches both live GitHub main refs at 7ffe8353. Preserve all upstream features/CI when consolidating. |
| fork | `offline-wallet` | `b41141733ed04b3ef6086ab1a98e75b00372f424` | Unique offline wallet implementation and four real GPU receipts. Not merged into later research ancestry; preserve its exact source/evidence and explicit invariant clarification. |
| fork | `p10-recovery-research` | `e86e2a277ad53b28fc3bfc4aea40c24d858259fb` | Its committed work is contained in the broad feasibility line. Missing exact public proving parameters for the historical published instance remains an important source-bound lesson. |
| fork | `research/shielded-kas-feasibility` | `4d54dc026098506dd56dc568b20cab269be2b447` | 97 commits outside upstream main; broad direct-L1, recovery, fee and MPC work. Owner-paused; one rejected tracked patch remains modified. Extract findings, not the whole experimental tree. |
| fork | `shielded-kas-research` | `ec6aa15d586bcc8a90f7232b433fd48d8c73d509` | Committed history is contained in feasibility. Preserve the rejected working-balance policy and price-prior calibration. Two untracked evidence archives still need private archival treatment. |
| fork | `test/native-admission-adapter-proposal-20261022` | `fde0c288d42ff58482d8b05df85e033806b64ecb` | Independent side-branch tip; per-input admission controls. Not an ancestor of feasibility, so retain its exact commit even if similar files exist elsewhere. |
| fork | `test/native-continuation-admission-20261022` | `c430dd8a18d738a2d6ead9246d9650a4c1fe1933` | Native continuing payout/context checks; ancestor of admission-adapter branch. No reason to retain an active engineer lane. |
| fork | `test/native-guard-controls-20261022` | `dd00ceed35a95d10b6c79b80b744642244cb3226` | Native payout/successor guard controls; ancestor of continuation/admission test branches. Source/evidence are version-specific, not current protocol qualification. |
| fork | `test/relation-controls-20261022` | `2251864a7f89065a526641c3782506f27b39c59f` | Range/ownership/padding controls; ancestor of tree-capacity branch. Passing constraints are narrower than proof/native acceptance. |
| fork | `test/tree-capacity-controls-20261022` | `67793fa4b849e12555a13dfe10016cad7299d040` | Independent side-branch tip covering capacity and no-mutation refusal. Not an ancestor of feasibility. |
| fork | `upstream-reproduction` | `a0ef8fb82263fd6604d1a10a546ebd8ce2fc735f` | Unique RTX 3070 reproduction; four outer receipts in 10m27s, po2=19 adaptation, CPU/native controls. Valuable reproducibility reference, not a competing product branch. |
| fork | `work/intensive-research-20261022` | `85e39398fd97ff0299e07fad8899cd3f4cc454ac` | 85e39398 is an ancestor of feasibility. Preserves proof/compression/state/native component results; synthetic statements remain distinct from funded lifecycle evidence. |
| fork | `work/s7-owner-lifecycle-20261022` | `68d7b039f606bd42b39d8d1317c0bfd76c277ae0` | 68d7b039 is an ancestor of feasibility. Fresh supplied-context paired transition; not accepted chain ancestry or a completed user lifecycle. |
| upstream | `main` | `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1` | Matches both live GitHub main refs at 7ffe8353. Preserve all upstream features/CI when consolidating. |
| local | `docs/kpi-orchestration-2026-10-22` | `596d800706afb1c6a0a4aa116abe11f9da01e160` | Local tip is nine commits ahead of its GitHub counterpart. Contains cross-reviews, controls and deferrals, not a separate payment implementation. Three untracked v2 scripts are not committed anywhere. |
| local | `main` | `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1` | Matches both live GitHub main refs at 7ffe8353. Preserve all upstream features/CI when consolidating. |
| local | `offline-wallet` | `b41141733ed04b3ef6086ab1a98e75b00372f424` | Unique offline wallet implementation and four real GPU receipts. Not merged into later research ancestry; preserve its exact source/evidence and explicit invariant clarification. |
| local | `p10-recovery-research` | `e86e2a277ad53b28fc3bfc4aea40c24d858259fb` | Its committed work is contained in the broad feasibility line. Missing exact public proving parameters for the historical published instance remains an important source-bound lesson. |
| local | `research/native-kas-withdrawal-privacy` | `5f8c8957e1c8cd437516e30778ea92d63feb5b8c` | Two local-only commits hold the latest wallet-local studies, completed depth-four TN10 run, scorer corrections and open architecture boundary. Preserve before any cleanup; full fast CI is known red. |
| local | `research/shielded-kas-feasibility` | `4d54dc026098506dd56dc568b20cab269be2b447` | 97 commits outside upstream main; broad direct-L1, recovery, fee and MPC work. Owner-paused; one rejected tracked patch remains modified. Extract findings, not the whole experimental tree. |
| local | `self-funded-native-kas` | `e86e2a277ad53b28fc3bfc4aea40c24d858259fb` | Tip aliases p10-recovery-research, so branch name is misleading. All 62 untracked self-funded files match committed history elsewhere; keep ignored runtime/parameters separately. |
| local | `shielded-kas-research` | `ec6aa15d586bcc8a90f7232b433fd48d8c73d509` | Committed history is contained in feasibility. Preserve the rejected working-balance policy and price-prior calibration. Two untracked evidence archives still need private archival treatment. |
| local | `test/native-admission-adapter-proposal-20261022` | `fde0c288d42ff58482d8b05df85e033806b64ecb` | Independent side-branch tip; per-input admission controls. Not an ancestor of feasibility, so retain its exact commit even if similar files exist elsewhere. |
| local | `test/native-continuation-admission-20261022` | `c430dd8a18d738a2d6ead9246d9650a4c1fe1933` | Native continuing payout/context checks; ancestor of admission-adapter branch. No reason to retain an active engineer lane. |
| local | `test/native-guard-controls-20261022` | `dd00ceed35a95d10b6c79b80b744642244cb3226` | Native payout/successor guard controls; ancestor of continuation/admission test branches. Source/evidence are version-specific, not current protocol qualification. |
| local | `test/one-v6-input-binding-control-20261022` | `6fdc5fc61ddd9b33c254acbc47316348d7d84503` | 6fdc5fc6 has a real changed-public-input pairing rejection. Same tip as outer-proof and two-bundle work branches; no unique additional committed stream. |
| local | `test/one-v6-verifier-compatibility-20261022` | `acba8b04237e62a5bbc3eb93eb10faa1722a59ea` | One-bundle host/reference adapters; ancestor of 6fdc5fc6. Does not establish a paired state transition. |
| local | `test/relation-controls-20261022` | `2251864a7f89065a526641c3782506f27b39c59f` | Range/ownership/padding controls; ancestor of tree-capacity branch. Passing constraints are narrower than proof/native acceptance. |
| local | `test/tree-capacity-controls-20261022` | `67793fa4b849e12555a13dfe10016cad7299d040` | Independent side-branch tip covering capacity and no-mutation refusal. Not an ancestor of feasibility. |
| local | `upstream-reproduction` | `a0ef8fb82263fd6604d1a10a546ebd8ce2fc735f` | Unique RTX 3070 reproduction; four outer receipts in 10m27s, po2=19 adaptation, CPU/native controls. Valuable reproducibility reference, not a competing product branch. |
| local | `work/intensive-research-20261022` | `85e39398fd97ff0299e07fad8899cd3f4cc454ac` | 85e39398 is an ancestor of feasibility. Preserves proof/compression/state/native component results; synthetic statements remain distinct from funded lifecycle evidence. |
| local | `work/native-observation-20261022` | `ec6aa15d586bcc8a90f7232b433fd48d8c73d509` | Tip equals shielded-kas-research. Of 221 untracked files, 219 contents already appear in committed history; two replay-design/pin files remain unique. |
| local | `work/outer-proof-compatibility-20261022` | `6fdc5fc61ddd9b33c254acbc47316348d7d84503` | Tip equals 6fdc5fc6. 376 of 379 untracked file contents are committed elsewhere; three retained packet/program files remain unmatched. |
| local | `work/privacy-source-review-20261022` | `ec6aa15d586bcc8a90f7232b433fd48d8c73d509` | Tip equals shielded-kas-research. Native/extractor packets mostly committed elsewhere; two frozen binaries and one publication audit remain uncommitted. Binary notices are unresolved in retained audit. |
| local | `work/protocol-binding-review-20261022` | `ec6aa15d586bcc8a90f7232b433fd48d8c73d509` | Tip equals shielded-kas-research. 49 of 188 untracked files have no committed-content match, including review corrections and verification/provenance records. |
| local | `work/public-binding-fixtures-20261022` | `ec6aa15d586bcc8a90f7232b433fd48d8c73d509` | Tip equals shielded-kas-research. 3,041 unmatched untracked files include 2,962 build-output files and 79 other files. Do not equate that count to research results. |
| local | `work/s7-owner-lifecycle-20261022` | `68d7b039f606bd42b39d8d1317c0bfd76c277ae0` | 68d7b039 is an ancestor of feasibility. Fresh supplied-context paired transition; not accepted chain ancestry or a completed user lifecycle. |
| local | `work/two-bundle-binding-20261022` | `6fdc5fc61ddd9b33c254acbc47316348d7d84503` | Tip equals 6fdc5fc6. Eight of 14 untracked files are committed elsewhere; six variants/drafts/probe files remain unmatched. The older lib variant lacks the later compiled-instance feature. |

## Original upstream pull histories

Original and squashed histories remain separately identifiable. These are upstream contributions, not 42 new contributions by this fork. The merged state is the retained 3 November audit snapshot.

| PR | Head | Merge commit | Subject |
| --- | --- | --- | --- |
| 18 | `91e26acb46c97967c5e6b4076d1d99513862d010` | `2233993208440d59fa44012038e3c2dfcae20bd0` | Connect public research tasks and contribution entry points |
| 20 | `0c4dbaf1293c417c48a6f8301810c08a972d6199` | `3a1efa8db9672025f5282970703cb7256428c1be` | PoC A0/A0.5: live TN10 proof-gated reserve release |
| 21 | `7ea21ee59cee7b4490501dc4781feb896e724d06` | `0193d1847aa53468d6056a925ffb60f2d69e5b23` | A1 specification: authenticated successor reserve and independent exit |
| 22 | `52256d7ed48ac3ab5e835c338955d2ece89f7977` | `e4a10390fbbd3df523f5eb5871e4dc1d0eb1501d` | PoC A1: authenticated successor reserve and independent recovery |
| 24 | `4387e8da31e09a86a48fc71c2c116193abdd3223` | `98aa99fa8230f5eb490e0af4e3da0291260581d6` | Project maintenance: status sync, CI and reviewer entry points |
| 25 | `e5cae32ee71bfb1a515e2c4379245060a6bd1e6d` | `6fcfeed3d7890f83d416184591ee183988b90838` | research: evaluate Kaspa-native post-quantum experiments |
| 26 | `c1437a9d5cf4883cc5b90a33beb340ecc3454a0d` | `5435113d17a61a2bdf88b2d95b58bb5146ed906c` | docs(agents): testnet trial practice |
| 27 | `eb35be02169b7e8907f05f88cedbe36780680976` | `e9c8b1a4d76938d0059ccec38d3f6545fa20afe2` | docs: refresh roadmap and RFC-0001 evidence after A1 |
| 28 | `debb02b0e724cfb9e8722f4f02923046046a64b4` | `06f24918927e674b973ae7213e19ee8c5f538755` | research: Phase 1 source review (P01/P02, mature protocols) |
| 29 | `ca5e4e274549b31e287ec4dba16e3ec795ebb04a` | `ccbdfbc7b5d2f601089e9dc5254719c523a64010` | docs: RFC-0001 comparison after Phase 1 source review |
| 30 | `d96928f93b663d687a1a20ab565d4f8926aff378` | `e7c4dc133dabce25346e55499bc431132b0ca14a` | docs: record Michael Sutton feedback on Based Apps and KPI |
| 31 | `68100588133175442dab2b0a56ed6d784dc015ea` | `0167b04fd3598b30b470f92f458c3f1ffe19f404` | research: remote TN10 KPI input, real proofs and settlement |
| 32 | `d52ce08a10f78f0441a9a265fb0c4a427239296b` | `335fbca8103e28af9ba15aedfd56d22350b1cbd2` | research: public native-KAS deposit and exit through the based-app bridge |
| 33 | `eecfebb92a28b03f2bbf2528cbd18ba4392793e0` | `d79bb67ab5d5403cea0fd5fca5725c937c58f184` | research: validate recursive TN10 Based App flow and conclude feasibility |
| 34 | `bfb96263b54419ea7b08ddf2c929a60cc6c03008` | `f777e57674f11ce17366faae4b3dfb0cf5caef29` | docs: establish privacy-preserving protocol migration requirements |
| 35 | `a3e834da5267417dbfa1b5822570fd08ee6fb23d` | `42c98654d38c8e86c6b0d58837bb134752439bec` | research: specify shielded native-KAS payments and measure wallet proof composition |
| 36 | `b7972914d3300d319d59eb83059738cbc8c18175` | `eb9cdd99046faa53ae3c530e4cb064b050316459` | research: measure guest proof classification and native payload limits |
| 37 | `d4a4b58177f0173dacc1134512e742c90cd26cf5` | `a1d1b08dda867d9c0c8c47c16bddeece1d85dc76` | research: compare specialized Groth16 wallet proofs within a bounded classifier |
| 38 | `eee8173df1c2c679c15ce4a8ec47ce0ed7468866` | `99d35099d6640108db76a5ba6db8eff18d2b79d3` | research: qualify accelerated BN254 backend and measure full classification |
| 39 | `db264acf3e4902f159d82b55e6d870e5d912b2bb` | `ed7aa2b2a2d900315fe53ca0f25b9dde0eee80a9` | research: qualify full 128M execution and retain one-hour proof timeout |
| 40 | `c857f0bf326c2039f05ea8cddb3cfaa80b64c6d6` | `e7ea15e8009b8f6ef3aaa34b3cec17fbfc3eb5cd` | research: retain verified segment, lift and join proofs with phase costs |
| 41 | `593f3acb6dfafeb8311b3cfad97a642d59197b50` | `c2037893936508d6d61dcb9ee78aea6ba4515aab` | Prepare bounded remote CUDA qualification of PR40 proof phases |
| 42 | `b5719072ed5b0e76a236863c22850910b7121648` | `29f4f22481c288be9c6bb27a53daec9a27d40703` | Qualify L40S partial-proof workload with independent CPU verification and confirmed guard stop |
| 43 | `eca0ebb4ba2ccbd4a9ba4b54f7f3f3c9d3523b9a` | `4709481f2c49ae22f0a83c26492de09cf94ca4ef` | Prove the complete compact-wallet classifier on CUDA and verify it independently on CPU |
| 44 | `c6891246a81cc31525227fe4c045dcfd05fc1c20` | `a6f81057b7d007f49e42ac40cc7063ddd3dd28b8` | Prototype real private-note wallet proofs and atomic economic state |
| 45 | `695c049d255fa2852a9b30fe6a938ea7040cb8eb` | `7b4eb538357d11b1e5b6eec83765aa711774f3c2` | Integrate private-note state with native preimages; record 128M limit |
| 46 | `6dd9bbea6e4db4aaea16d322250941319912563d` | `9db923bb7d0e53ac199a362f85f6b1f63716af50` | Complete the approved 160M private-state CPU calibration |
| 47 | `781b12b1c4ba0075385781f23072f38585086f07` | `d11e38d65f8c5d8309f332c0b7622acc12463020` | Prepare fixed private-note proof package with join-native verification |
| 48 | `051eaa54e49c344c2a5b5ddd36f56a5f829203cf` | `22f2bdc50436e9d1b491162b4759c7004198f95a` | Record real private-note GPU proof and verified native fixture |
| 49 | `b44956e26d99b1f3bf74f7d9b3523788bb563c4f` | `08bd96d6a7ef647b09df7fb241ed164ff6e66b35` | Prepare local native/private payment lifecycle and reconciliation |
| 50 | `39656e33db268cd6c0599e050854397b6d99c850` | `cde2b88de3a16af401a2046bd90a124aa105418a` | Prepare fixed four-batch private-native GPU proof package |
| 51 | `3f6a95c5d316807784f13dddce8df080780ca8af` | `98ee0e4849b4ee477a388344eebf68947a657117` | Prove the four-batch local lifecycle after fixing output directories |
| 52 | `606010c29a4ba30e620b5d40ba44de7a7ef479bd` | `8793c09c7cfc45899ef4c58b2c09640d9c9a3ad8` | Prepare staged TN10 private lifecycle inputs and native initialization |
| 53 | `4864924f9e8adad9ba992b2d2c379365251f37d0` | `da84afbb7daf993f805859ceb40a3fc9f0dabf15` | Qualify staged GPU service for the four-step TN10 lifecycle |
| 54 | `14a73c0ea6c4117a07fa284a60da46d947e5c814` | `40b39a6503d2133da93b9dd7e77a5a1ee8652658` | Complete actual TN10 private/native lifecycle with four verified outer proofs |
| 55 | `bda97e66cbe9edea3298f63de40c0c72b1c00ec8` | `05ea24a5cdb89ba5dd2cfec1041b1e69fa8de68d` | Prepare user-held recovery and exact-reserve terminal exit locally |
| 56 | `cfee7e5f7cd25d9bac600eab5292a8ffcc52e7b3` | `2010684bc40c482e69f0994229385a0a1e0ece78` | Qualify integrated guest for partial and full-reserve exits |
| 57 | `f9a4ec04a9cd4cad40235247b64d902999bc93a3` | `c4dc4d8126c5497447760828ffc10382609d49a4` | Prepare six-receipt recovery lifecycle CUDA package |
| 58 | `607fa4e29ecc5c40434fd4aa2930c4bf53a1af5f` | `52bb2b4e7a1e0a8f98aecb58d33933f0b03d9e33` | Prove six-batch local recovery lifecycle and final reserve withdrawal |
| 59 | `585558091cc7d326e28d10f9c04e709952c85cf5` | `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1` | Prepare offline wallet onboarding for the owner's Linux workstation |
| 60 | `f02e98d5918af3f53985b77809c7e930d888231f` | `3bd363a85169f887f9ad1f155c63c5e9da34447c` | Prepare six-stage TN10 recovery with user-held wallet proofs |
| 61 | `44cb271222db9d1665ae3ac5799de8bff60e2a28` | `35f6a91a8a0ed4279dc575a5b5d49df8ab3bd6bf` | Record actual TN10 wallet recovery and full native withdrawals |

## Coverage boundary

All committed Markdown/rst revisions are copied as exact bytes, including intermediate failures, design proposals, ADR/RFC collisions, historical instructions and superseded claims. Code-only commits retain their complete message and changed-path metadata; their runtime code is preserved in the history archive, not silently integrated into the current implementation.

The 149 privately preserved unfinished files contain 15 selected human-readable notes copied here. Other source drafts, parameters, binaries, raw diagnostic/evaluation records and build output remain private. The [unfinished-work guide](unfinished.md) carries their reusable conclusions and limits. These records do not qualify a new runtime or publish the private evidence.

The original 361-commit bundle omitted two recovered refs; the later verified 369-commit bundle corrected that coverage. Both commits are explicitly present in this ledger. `6362741a` has the same tree as retained `760d2749`; `72166ed7` differs from `2c036c0f` only in changing “committed hidden truth” to “hash-bound hidden truth”.

Run `python3 scripts/research_knowledge.py check` from the repository root to verify local document hashes, commit/document-tree reconstruction, branch/PR coverage and recovered refs. This needs neither the original worktrees, the private audit directory, Git history nor a network connection.
