# Integrated verifier and independent native exit: component results

2026-10-24. **Fresh-domain direct Exit works with genuine proofs in the actual
native Full validator. This packet is supplied-context evidence, not an actual
funded lifecycle, accepted backing, chain confirmation or privacy qualification.**

## Implemented

- A new three-role component profile pins genuine Spend, Output and Exit keys.
- The new mixed-round guest retains three Spend and six Output verification,
  private input membership, exact public CM/NF updates and global value balance.
- The native covenant supports mixed rounds through its pinned outer image and
  independent full-note withdrawals through a direct pinned Exit verification
  key. Exit uses no MPC, shared RISC Zero prover or administrator authority.
- Both continuing reserve and terminal zero-reserve layouts are exact. Current
  state/point, one authenticated NF insertion, unchanged CM state, payout,
  fee, destination, successor tail and native covenant metadata are checked.

The [design](DESIGN.md), [source closure](SOURCE-CODE-01.json),
[runtime identities](RUNTIME-ASSETS-01.json) and
[native source freeze](native/SOURCE-FREEZE-01.json) record the concrete interfaces.
Original prototypes, private wallets, keys and proofs are unchanged.

## Genuine native experiment

Publicly known synthetic notes/keys produced two distinct genuine Exit proofs.
Each passed the accelerated pairing checker, independent Arkworks reference,
actual pinned Native Full validation and the individual input script engine.

| Supplied context | Script units | Allowance | Fee, integer sompi |
| --- | ---: | ---: | ---: |
| Continuing reserve | 14,829,516 | 18,009,999 | 19,040,500 |
| Terminal reserve drain | 14,797,545 | 18,009,999 | 18,998,200 |

All **38 changed native cases preserved the same genuine proof and rejected**.
Six coherent changes to exact effects reached `ZkIntegrity`; the remaining 32
state/NF/path/amount/header/output/covenant controls rejected with `VerifyError`.
Both actual output-covenant metadata positions were tested for continuing exits.
The test-only codec normalized transaction IDs/storage mass through upstream
methods, keeping stale IDs from becoming the rejection reason.

An initial test reader looked for `error` rather than the engine's actual
`typed_error` field. The first changed-head transaction had already rejected
with `ZkIntegrity`; the harness stopped while classifying it. Its original log
and native result are retained. Correcting the reader produced the complete
2-positive/38-negative result without changing financial checks or proofs.

The [public evidence packet](native/genuine-exit-result-01/MANIFEST.json) selects
147 payload files totaling 967,346 bytes, including the fixed public witnesses,
exact projections/proofs, native cases/reports, independent verification and
retained reporting failure. These fixtures use declared synthetic image and
component identities with the genuine selected Exit VK. They do not substitute
for a rehearsal using the final selected lifecycle tail.

## Build and selection

Native unit checks passed 3/3, including pinned identity/template binding and
standard outer-VK equality. Common/host and guest release builds passed using
the established pinned SDK. An initial direct guest build refused the missing
SDK `RISC0_FEATURE_bigint2` environment; enabling the required feature fixed
compilation without changing the financial predicate.

Selected component hash:
`a30fc71038685867ff832a384fc82d2654e0692c58f66667e77cb7e758f42554`.

Selected guest image:
`d4b2d4e2c195533457bbb34a80cca286e489f9bb3624c5767d53ccc525db7784`.

Selected program SHA256:
`ac56bf38fc318920c69f92c83e0a037d554c36dafcbd655032394bb25c5ba87d`.

Selected native tail SHA256:
`2e9e00aa4ba7d9a25db4aff5246d58213b336e7a0c7689de8cc36498bcd09bf6`.

The new 7,657-byte redeem script pins that image/component and the Exit VK.
Final selected-profile mixed execution, genuine outer receipts, owner recovery,
funding/broadcast and confirmed payouts are integration gates recorded
separately. These component checks do not establish those results or the
complete-fee target, operator independence, long-term availability or security.
