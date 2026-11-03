# Privacy and recovery design selection

**Status:** bounded research plan, 2026-10-23. Root owns the RFC/ADRs. Exact
[private action](PRIVATE-EXIT-CONTRACT.md) and
[recovery](RECOVERY-CONTRACT.md) contracts carry the implementation rules;
[primary sources](SOURCES.md) record reused/rejected designs.

## Problem and alternatives

The confirmed KPX2 lifecycle proves mechanics, but its ordinary native exit
reveals the selected note/opening/key, and its receiver starts from a supplied
accepted archive. More provers or CPU do not remove either architectural limit.

| Candidate | Benefit | Reason for selection/rejection |
| --- | --- | --- |
| Keep native REVEAL as the only exit | No PK/prover dependency; established owner-signed self-funded escape | Retain as explicit consented fallback, not ordinary-private exit; exact openings remain visible |
| Private proof but payout equals Note.nativePK | Hides CM/k bytes | Reject as privacy fix: public ADMIT/invoices already contain that key |
| Unified hidden-input/private-change/public-payout action | One verifier path; existing ownership/NF relation; exact new public value balance | Selected for new unfunded experimental profile, fresh matrices/VK/domain |
| Separate private-exit verifier/branch | Could specialize relation | Duplicates verifier/policy bytes and costs; no demonstrated need in first prototype |
| New token, admin release, trusted plaintext prover | Operational convenience | Rejected: violates native asset/authority/witness boundaries |
| Operator archive with signed current root | Easy receiver integration | Does not replace trusted snapshots, accepted lineage or missing historical ciphertexts |
| Public descriptor + network fetch + deterministic local replay | Eliminates supplied stage list, snapshots and expected amount map | Selected R1; honest validating node and retained data remain explicit |
| Multiple RPCs | Availability and disagreement evidence | Useful failover, not independent consensus or durable DA proof |

Terminal private exits do not append phantom dummy CMs: R'=0 has canonical
zero output fields/witnesses, unchanged CMroot/n and two mandatory NF inserts.
This preserves a private terminal path at CM capacity. Continuing private change
still requires CM capacity. User-selected fresh payout keys are not input-note
emergency keys; arbitrary external payout ownership is a wallet responsibility.

## Falsifiable work order

1. Freeze a **known-pilot descriptive** chain-observer attack on actual accepted
   bytes, without directory/actor labels in C. It cannot become a blinded
   representative qualification because the small pilot was already inspected.
   Freeze future workload/hidden truth/attacks separately before evaluation.
2. Build/review the new Auth528 relation and shared native path; measure genuine
   proof, wrong destination/value/state/replay and terminal-capacity controls.
   Passing those checks is not a cryptographic audit or privacy pass.
3. From only user-pinned descriptor and own backup, fetch/replay the actual
   completed pool anew, excluding operator archives/stages/amounts. Historical
   spent-note recovery is progress but not an unspent exit result.
4. Exercise missing/pruned/corrupted data, omissions, endpoint loss, removals and
   competing heads. INCOMPLETE must not be reported as an empty wallet.
5. A future fresh testnet recovery trial must rebuild an unspent liability and
   construct/confirm its owner exit after archive/prover removal. Use test KAS,
   fresh identity and actual terminal path; preserve the already completed trial.

## Unchanged gates and trust

The new direct proof exit has an unavoidable native verifier floor. Even the
existing favorable two-10-KAS prefix plus that floor fails the2% complete fee
target; no service subsidy, witness pooling or larger denominator is introduced.
Native P and f are public. Terminal drainage, sparse traffic, public amounts,
timing, directory records and orphaned disclosures remain in observer horizons.
The old21.0977% prior-floor failure and all prior privacy/fee results remain.

The native receiver's proofless fallback exposes historical information even if
the transaction is rejected or orphaned. The wallet must request meaningful
consent before producing that payload; restoring canonical chain state cannot
erase an observer's knowledge. A fresh ordinary exit key also needs an explicit
backup/recovery derivation policy before becoming the wallet default; an unknown
unbounded exit counter is not recoverable from seed alone.

No source change is adopted in a funded instance. No mainnet, real funds, token,
privileged withdrawal, paid infrastructure, new primitive or production security
claim is authorized by this design. Independence from a preferred operator is
reported separately from consensus trust, archive survival, network anonymity,
setup integrity and statistical privacy qualification.
