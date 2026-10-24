# Original-backup recovery and private fallback after the new W settlement

Proposed integration under ADR0058/ADR0059; peer review precedes implementation.
No old package, selected source, parameter file or closed recovery packet changes.
Base `5aaf99532d8714e510d421102df719f60f54d073`.

## Scope and authority

Use only capacity child D `d55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb`, compact manifest `d6f0e2bbafab39a72106ef0a0ebd6483362a858926117721a8be5aa37a459011`, PK `6c518076ed6194d1f0e1925be6902182951ddf8f17347fe4aa8ec200a2a8fb11` (1,307,894,256 bytes), VK `074c06a5f21f46c7c87a948c8ca6a0896198cc9fc255b8d5e08cc01ceb73a987`, owner ELF `4ef4fc4f6290bc1c5472e732e118476b6ad20b692438c0957e27cf3f6bc00621`, build `fcf6e8c757613e6fea9a5dd776727f1c2456865f1185c545ac9751ef9fb26419`.

The separately installed W selection must additionally pin actual guest image, wrapper domain, child profile SHA `492a0981ad04891ea68243f2c8221976f436501acf940e42211bb8773744fbdd`, native codec ELF, initial W point/state/reserve, complete immutable W template and public S0 snapshot hash. Root has selected actual guest image `633b3244225320ddc029a7b3b18d76b5f579bed808bbaecff25a50341b76f7f4`, built program SHA `f3e88182ad3f7e0ce9d60c796d18fcd806b67e52cd9cc3d97a77ae61d7d6bd03`; no placeholder or unsafe hash-oracle program can enter owner recovery. Old D35/c8/B05/HTTPS assets are incompatible and confer no evidence for this profile.

Initial S0 is a constructed public sparse state: n2/m1, two encrypted deliveries, R4B, selected fake Q0. It is not a replayed deposit, accepted backing or confirmed head. Native Full on supplied UTXOs means local validity only. There is no KPX4/KPX5 accepted-chain discovery/currentness adapter; a requested live/current operation fails INCOMPLETE. The old KPX3 adapter is never relabelled.

## Inputs and API

The new `poc/shared-settlement-wallet` owns a small pinned reuse layer, public replay, a pure no-append builder, the actual-W runtime adapter and an isolated owner CLI. No caller-selected import/callback/program is accepted.

```text
recover(selection, public_prestate, ordered_native_cases, ONE_original_backup)
prepare-full-cashout(selection, public_prestate, ordered_native_cases,
                     ONE_original_backup, compactPK, local_prover, rate)
```

Selection is independently installed and hashed before user bytes. Public records contain only complete transaction bodies and input contexts, never owner names, expected owned values/positions, saved indices, receipts, witnesses or previous private outputs. The local controller chooses only an original backup FILE and fresh output, not an actor identifier. Recovery derives every recognized receipt/index/position/original NF through established V2 decrypt/rederive/CM checks. The original backup predates all outputs. No source fixture generator, other owner backup or witness is mounted.

Path checks reject literal '..' components and every symlink component before any seed read or output write; Path.absolute alone is insufficient. The outer launcher checks an existing backup from its parent DIRECTORY and a fresh output from its closest existing DIRECTORY with clean-environment git rev-parse, so another Git worktree or a lexical alias cannot bypass the outside-Git requirement. The one-backup namespace repeats safe-path checks. Metadata checks reject backup inode/hardlink aliases before reading/hashing any caller-selected public source, descriptor, history, manifest, PK or executable. All mounted modules are exact pinned source files with no pycache; executables use ordinary readonly selected releases, full SHA checks and clean environments under the trusted-host/installation premise.

## Public replay before the seed

1. Strictly decode complete S0 CM/cipher deliveries and indexed NF table without sorting allocation indices or renumbering physical positions. Verify the reconstructed snapshot/state and selected Q0/R4B; preserve its constructed-state classification.
2. For the actual aggregate case, independently match current W redeem and UTXO context to the installed image/profile. Recompute canonical native ID/storage/fee with selected software and run fresh Native Full/all engines. Do not accept a supplied success report.
3. Parse exactly `KPX5VP01/version1/count2`, two3920-byte mode2/P0 payloads plus128-byte proofs. Check each compact proof/public policy under the selected new role. Sequentially derive original NF insertions, CM start/arrays/ciphers/boundaries and successor roots/counts/reserves. Compare every witness byte, hash and state. Child0 binds Q0; child1 binds the canonical child0 virtual-body ID. Append deliveries at actual start+i; retain every physical gap/dummy leaf.
4. Match final S2/R2 to the actual single W continuation. **Current spend point is actual outer transaction ID:0**, never either virtual child ID. No virtual body is queried/asserted L1 accepted.
5. Replay later direct exits with the actual W immutable tail, exact current outpoint/context, fresh Native Full and the same public NF/CM/reserve equations. A mode0 positive-reserve exit has no CM/CF append but retains exact W backing for other users. R0 is terminal only when its native/semantic transition validates. Missing bodies/ciphers, wrong profile, discontinuity or unsupported history are INCOMPLETE, never zero balance.

The public replay uses no seed, PK or private witness. It requires no outer prover/compression assets; the actual W verification code/image and public receipt are ordinary public protocol dependencies.

## One owner, all claims, and two-real-input preparation

For private-action preparation, after public replay start selected4ef with an EMPTY data pipe. Authenticate the full owned6c PK, exhaustive decoding, extracted074c VK and dimensions, then match the entire `parameters-ready` record to D/role/arity/manifest/VK/build BEFORE the first backup-byte read. Only then decrypt all deliveries and rederive owned credentials. Recognition-only `recover` deliberately needs no PK or proving worker; it has no private witness, currentness or spend authority and still requires complete public replay before its backup read.

Count ALL recognized actionable positive claims, including accepted duplicate-index claims. Never filter by `normal_credit`, require exactly one, or accept a caller position map. Choose up to two deterministically by largest value, position tie-break; report how many remain. Both claims must originate from this one recovered wallet and current CM/NF state, have distinct positive positions and original NFs, and have checked total V<=MAX/reserve. Preserve duplicate ownership rather than freezing it.

The circuit already supports two real inputs. This wallet adds no relation or primitive. Shuffle the two private input slots once, derive original real NFs, then construct BOTH sequential current indexed-NF insertion paths in slot order. For two real rows all dummy fields are zero. For one real row retain the established actual-slot dummy HMAC and canonical inactive fields. Membership paths authenticate both notes against the same current CM root.

For full no-append cashout:

```text
P = sum(consumed owned note values) - actual fee
Rprime = current reserve - sum(consumed owned note values)
mode = 0, CM root/cursor unchanged, both output Note168/rho witnesses zero
CM metadata/digest zero; ciphertext binding = SHA256(528 zero bytes)
P>=10M; Rprime=0 or>=60M; two sequential fresh NF insertions always required
```

Use the established `KPX3PAY\0 || childD || initial-wrapper-point36 || anchorCM || anchorPositionLE32 || retryLE32` HMAC message, scalar rejection and u32 retry counter. The anchor is the minimum physical position among consumed own claims. Root selects rejection of a retry whenever its public key matches ANY consumed real input nativePK, not just the anchor. This adds no message tag, primitive or group identifier; a one-real exit retains the old rule. Seed-only historical recovery must reconstruct the OWN co-consumed receipts from original NF matches and repeat that exact skip set. Never assume an unknown NF belongs to this wallet or is a real input. This is the bounded same-backup default destination policy, not recovery of arbitrary externally selected destinations. Prover/native helpers receive no seed or payout secret.

Derive the actual current W redeem via the selected codec, never the child C template. Quote exact continuing/terminal body shape and integer fee before witness serialization. Keep selected input order/NFs/anchor fixed through fee convergence. Rebuild public Auth fee/P as necessary; no output encryption is reused because mode0 has no output notes. Require exact final quote ID/body/all-context/rate binding and proof-only substitution, then fresh native Full/all engines. Invalid fee/floors/quote/READY leaves the witness pipe empty; discarded public alternatives remain private.

## Closure and recovery after spending

The proposed crosspay fixture gives each actor an original2B note, a sender change and an incoming payment: expected own3 historical/1spent/2current after W, established by actual scans rather than input expectations. Two genuine same-backup two-real exits may consume all four remaining notes in TWO actions only after source/control/genuine-proof/native qualification. Otherwise use/count FOUR separate exits. Never price only recipients while forgetting both sender changes.

First owner exit leaves precisely all other recognized backing. Each subsequent owner starts a new one-backup process and replays the actual W and every selected prior exit. Terminal R0 and final independent scans must close all recognized claims and count owner-controlled native payouts. Historical payout recovery joins only that wallet's original positioned NFs to actual Auth pairs, selects the minimum OWN consumed position, rederives the exact selected one/two-real retry policy SPK and matches public payout evidence; an unknown NF never implies same owner or real input. Native current spendability still needs an unavailable live-node adapter.

Complete ledger: initial4B = actual outer F0+F1 + ALL direct exit fees + ALL final native payouts. Retained sender principal/exit-credit refunds are not useful payment demand. Keep requested two NET1B payments, their explicit credits and any actual entry/bootstrap cost separately; constructed S0 cannot invent an entry fee. No2%/privacy/provider/currentness qualification is presumed. The old HTTPS result is not inherited; new-profile publication/retrieval is a separate root/fetch gate.

## Controls before heavy execution

Public controls cover one/two-real paths and both slot permutations; duplicate/foreign/spent claims; sum/floor/MAX/malformed encodings; stale/wrong roots/outpoints and source state; ordered NF paths; min-anchor payout recovery and either-input key collision; immutable W-vs-child continuation; exact quote/fee changes; READY and invalid-material zero-write canaries; missing/reordered/virtual-vs-actual history; and public export exclusion. Genuine new2P0+W and owner proof/native jobs are root-serialized14CPU20GiB after operator stop. Early source/controls remain<=2CPU3GiB. No funding, broadcast, mainnet, paid infrastructure, main seed or old frozen-file edits.

Residual assumptions: trusted initial constructed-state contents/valid-history premise, development setup honesty, authenticated software/static descriptor and retained CF/PK data, trusted host, and correctly delivered recipient encryption. A foreign failed decrypt cannot prove absence of every conceivable owned liability. Tests and genuine supplied-context proofs are bounded implementation evidence, not cryptographic soundness or live recovery.
