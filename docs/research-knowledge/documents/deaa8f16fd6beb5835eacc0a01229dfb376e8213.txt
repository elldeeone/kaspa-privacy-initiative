# Private full-note exits at the commitment/nullifier boundary

**The new no-append private cashout works in the completed local proof/native experiment.** Two owners' constructed remaining claims withdraw sequentially with genuine proofs while the CM cursor stays65535. NF counts advance131067→131069→131071 and the native reserve drains2,000,000,000→1,000,000,000→0sompi. The first exit preserves the other claim's backing; it does not require new CM space, an operator signature, another arrival or disclosure through REVEAL.

This is an **unfunded, deterministic public DO_NOT_FUND fixture with supplied UTXO contexts**. The65,533 prior spends are constructed, not65,533 replayed proofs or accepted transactions. The result establishes the tested relation/native boundary and conditional capacity induction; it does not establish accepted-chain backing/currentness, confirmed payouts, financial privacy, soundness, production safety, complete history availability or original-backup recovery for this new instance.

## What changed

[ADR0058](../../../../docs/adr/0058-private-full-note-exits-without-commitment-appends.md) selects a new domain, native policy and fresh compact/wide development setups. In that instance only, mode0 means full-input cashout without private outputs, even when reserve remains. Terminal reserve implies mode0; mode0 no longer implies terminal reserve. All private output bytes including rho are zero; CM root/cursor carry; original positioned real/dummy NFs, current absence, value conservation, exact payout/fee and immutable continuation remain mandatory. Existing instances, source, parameters and funded trials are unchanged.

The [design](DESIGN.md) and independent [review](../review/CAPACITY-DESIGN-REVIEW-01.md) cover the invariant `m+2U<=2n+1`, including genesis, public admission, compact/wide appends, gaps/dummies, no-append exits and retained REVEAL. `U` is a semantic count of outstanding positive notes, not a new public owner field. Under valid history and the reviewed relation assumptions, any remaining positive claim has its two required NF slots. No CM/NF eviction or position reuse is introduced.

## Decisive results

| Check | Completed evidence |
| --- | --- |
| Original native blocker | AtCM65535/NF131067, a conserving no-append exit leaving reserve fails before G16 at48,029SU. A terminal boundary control reaches the final zero-proof G16 seam. |
| New policy public checks | Four zero-proof cases (continuing no-append, terminal no-append, compact append, wide append) reach final G16. Explicit old-domain placeholder VKs are interoperability controls, not new financial positives. |
| Parser/host/hash/loader controls |29 Rust controls pass, including new nonterminal no-append/count boundaries. Generic tiny-parameter controls are distinct from the shielded proofs. |
| Capacity accounting | Five distinct Python count/property controls pass; these do not execute cryptography. Independent review also retains its own finite induction screen. |
| Direct relation controls |19 finalized controls:17 actual UNSAT and two deliberate SAT native-owned obligations (outpoint and NF-root/absence). No parser failure is counted as UNSAT. |
| Finalized positive matrices | Continuing no-append, terminal no-append and ordinary compact append have the same matrix; wide append is separately SAT. |
| Genuine cashout proofs/native positives | Two exact chained bodies pass Native Full and every input engine; exact SDK normalization/roundtrip and both actual fees pass reference rate100. |
| Fresh occupied-NF negative | A third genuine privately valid proof binds the actual first-body transaction ID, current state and sufficient1B reserve. Its occupied real NF is rejected before G16 at54,317SU. This is not a stale-proof or reserve-shortfall confound. |
| Native tampering | Ten exact-body mutations reject. Nine fail before G16; coherent public amount changes with the original proof reach G16 and fail exact Auth binding. |

The ten mutations cover wrong current outpoint, payout substitution, redirected continuation, payout/reserve amount substitution, changed carried CM root, extra/missing/corrupt NF witness bytes, changed Auth amounts with a stale proof and an extra terminal output. They are native supplied-context tests, not node acceptance or reorg simulation.

There are **three genuine shielded proofs**, two successful native bodies and one fresh occupied-NF rejection. The selected packet contains19 native case reports;21 actual native validations occurred because the original two-case baseline was repeated after adding unrelated controller helpers. Both baseline runs' selected bytes are identical; the repeat is not extra independent evidence. No further tests or code changes were made while sealing this documentation packet.

## Accounting and costs

All amounts are integer sompi:

```text
2,000,000,000 initial constructed reserve
= 980,000,000 first native payout
+ 980,000,000 terminal native payout
+ 40,000,000 actual cashout fees
+ 0 terminal reserve
```

Both actual fees are20,000,000sompi; these are deliberate adequate fees, **not minimum-fee/refund qualification**. At reference rate100 the exact first/terminal body quotes require18,766,200 and18,723,900sompi. All selected private budgets remain1600. Entry/payment costs are absent from this boundary fixture; do not describe40M as the complete private-payment lifecycle cost or a qualified fee improvement.

First/terminal Native Full units are14,938,065/14,843,138. Transaction IDs are respectively:

- `9dcdb430938264848f343bdffeca88c0a7ad07a2eb6f3fca292fa0a085b92b0f`
- `be8129b638b23000155747cfcc34d68d33bcd7af3321ca416648713ab7d8eac4`

Genuine proof-and-checked-verification times are8.846967073s,9.357191231s and9.039032710s. The full three-proof/native controller took48.829s and209.244s cgroup CPU (service completion observations). Its exact in-cgroup pre-exit record reports memory peak5,054,877,696bytes, swap peak0, no OOM events and CPU209,197,053microseconds; the final CPU observation is later than that snapshot. The unit completed and was inactive/dead with MainPID0. Missing post-unload resource counters are not converted to zero.

Both fresh role setups completed sequentially in67.326s with447.632s cgroup CPU, formatted cgroup memory peak7.8G and swap0. Exact post-exit cgroup peak was unavailable after unit unload; [resources](fresh-parameters-01/RESOURCES.json) distinguish that from GNU time's maximum single-process RSS. An initial path-guard refusal occurred before RNG/setup because a home ancestor had`.git`metadata. A fresh directory outside all Git ancestors succeeded without weakening the guard; the [failure](setup-path-failure-01/RESULTS.json) remains retained.

## Exact identities

Public instance trial: `a5ce95a4-22dc-4b9c-bd29-7a38c5b2a3a2`.

Domain: `d55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb`.

| Item | SHA256 |
| --- | --- |
| Public instance | `f2ba0670445ee73c73268e62d0750bc49cae9ff31b389cb3bf0aafb11aae1532` |
| Genuine proof/native result | `216371d64e8783fafc7151557b8310fc2e74d445011e02d4558e938ad4415b2a` |
| Native tamper result | `3f757f995d1028414755401a09be835f7f73496617369ec89c787d11051c8316` |
| New relation lib.rs | `638c3f5b1d34be4df0543718bb40dae8ff27aeeba1a53e10434935e1f91a2724` |
| New circuit.rs | `17c39f7d3064d66c0db8ee8d23a97c53fd14e8cfd07531781eab933ff242acef` |
| New native policy.rs | `315655892e55a06c3e69e0c9a08b0c764697497a2e6938e8c4c78914f806420b` |
| Compiled core/build identity | `fcf6e8c757613e6fea9a5dd776727f1c2456865f1185c545ac9751ef9fb26419` |
| Selected owner ELF | `4ef4fc4f6290bc1c5472e732e118476b6ad20b692438c0957e27cf3f6bc00621` |
| Selected native emitter ELF | `07f90455f60e1dd19c4a2a0c28b1529fced0218bd56cb90dca57809f54dc5a78` |

Compact matrix:3,284,767constraints,3,248,304witnesses,3instances including one, FFT4,194,304; matrix SHA`17fc990f38e3495f52ed3aeec5bd1c33fcea0835032c23167ffdf8c15f92d684`.

Wide matrix:7,448,842constraints,7,361,092witnesses,3instances including one, FFT8,388,608; matrix SHA`56182775fad7001dc9e3329d50bb4203016a0d54247d58c55725d8df7709be2a`.

| Role | Public PK bytes / SHA256 | VK SHA256 | Manifest SHA256 |
| --- | --- | --- | --- |
| compact2 |1,307,894,256 / `6c518076ed6194d1f0e1925be6902182951ddf8f17347fe4aa8ec200a2a8fb11` | `074c06a5f21f46c7c87a948c8ca6a0896198cc9fc255b8d5e08cc01ceb73a987` | `d6f0e2bbafab39a72106ef0a0ebd6483362a858926117721a8be5aa37a459011` |
| wide32 |2,892,421,872 / `981c22e27277f5bce71b7fe6d191ae8b9a941bd9db74bf8bdb0d5fc6c3420036` | `160c879f984151c49648490e3b7e1f5aecc8a62b838a085cf9dfa8e9808c8f8d` | `c4689e7f30e1b325bdc71337e3b317c69d4a6f7f3a8e317cd3dffa16ad2a7386` |

These are fresh **single-party development parameters**, not a trusted ceremony or soundness claim. PK blobs and executables remain outside Git. The public finite packet includes VKs, manifests, the three deliberately public canary proofs/Auths and exact native bodies/contexts. No actual private main notes, seeds, backups, witnesses, owner maps or their hashes were read or selected.

[Pre-setup freeze](SOURCE-FREEZE-PRE-SETUP.json) SHA`e05a40eecaa5ab45992dfafab710490390383cbd6cd3b2271be59390662654b3`; [selected freeze](SOURCE-FREEZE-SELECTED.json) SHA`c341fbfbce61ce9d3bf1f198a8ef8be800416d3d99f9910dc0bd0ff0b10160b3`. Fresh setup intentionally replaces six unselected pin placeholders. [Supersession](PARAMETER-PIN-SUPERSESSION.json) SHA`1249812179b628ea073fa852a679506ff82154685b24efd3df3e81a97c759dd8` preserves every exact pre-setup pin preimage and binds current selected bytes. All non-pin pre-setup sources remain unchanged.

## Remaining limits

This resolves the tested commitment-append dependency for a full-note private cashout. It does not permit private partial withdrawal/change once the CM tree is full, qualify future fee spikes/fair inclusion, establish a new accepted-chain trial or integrate the extension into every existing wallet/recovery flow. Sparse roots/history still require independent authentication and current accepted-head reconciliation. Missing receipts/parameters/software remain unavailable; mode0/full-vs-change behavior remains visible to the privacy observer. No administrative recovery path, new token, mainnet code or real funds were introduced.

[PUBLIC-FILES.txt](PUBLIC-FILES.txt) is the finite publication selection; [MANIFEST.json](MANIFEST.json) binds its payload bytes. This records reviewable local artifacts only. Git commit/push, external publication and independent availability are root-owned actions and are not asserted here.
