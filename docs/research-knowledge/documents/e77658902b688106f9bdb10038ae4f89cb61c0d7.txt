# Independent-payment fee and verifier progress

The new ADR59 wrapper now accepts **one genuine outer proof for two freshly proved private P0 payments** in Native Full validation. The exact public state/body/fee checks, guest execution, genuine CUDA proof, same-claim compression and native verification all passed. Five altered native cases rejected as expected. This is an unfunded public experiment under supplied synthetic UTXOs; independent private exits, recovery, privacy and accepted-chain evidence remain separate.

The [outer result](OUTER-RESULTS-01.json) binds the selected guest image, both public children, exact 8301-byte financial projection and 424-byte journal. The native result is [the genuine W acceptance packet](../settlement/genuine-native-01/RESULTS.json), using the real receipt-verifying program rather than the separate diagnostic hash oracle.

| Actual outer stage | Result |
| --- | --- |
| Guest execution | 107,317,810 user cycles; 2.071 seconds; exact independent journal |
| Genuine Succinct proof | 408.730 seconds; 121,896,960 total cycles; 233 segments |
| Same-claim Groth16 compression | 4.436 seconds; no guest reexecution |
| Separate CPU receipt verification | Both receipt forms passed; development mode disabled; no assumptions |
| Native Full/all engines | Passed; 15,646,440 script units; five typed negative controls passed |
| Actual body quote | 185,080 mining mass; 18,508,000 sompi at reference100; exact pre-agreed allocation preserved |

The authenticated local RTX3070 worker reached a sampled 6094 MiB proof peak and 5300 MiB compression peak. Cgroup peaks were 496,054,272 and 1,785,094,144 bytes, respectively; swap stayed zero. One-second GPU sampling can miss brief peaks. Units stopped with manager PID0 and no surviving observed owned process identities; final kernel cgroup process counts were unavailable after the manager removed those paths.

The first native-proof conversion rejected valid G2 coordinates because an extra roundtrip compared Ark affine sign flags against the SDK's raw field coordinates. The [retained failure and strict fix](converter-failure-01/DIAGNOSIS-AND-FIX.json) keep curve/subgroup/nonidentity checks and compare canonical field x/y bytes instead. Both y-signs and malformed flag/field/order/curve boundaries passed controls. A separately selected rebuilt host converted the **same** already verified receipt; no payment, guest or outer proof was repeated.

At two payments, 9,254,000 sompi per payment plus the quoted continuing private exit's 18,023,200 equals **2.72772% of a 10-KAS net payment**. Terminal exit pricing gives 2.72349%. These are exact batch costs plus explicit exit quotes, not executed-exit or complete-lifecycle qualification. The 2% and low-demand targets remain open; a disclosed REVEAL exit is not substituted.

## Public checker evidence

The public checker executes real Groth16 verification with the unchanged selected Rust binary. The settlement oracle can therefore distinguish valid private predicates from correct public transitions; a recorded `verified:true` flag is not its proof authority.

The [11-case G16 campaign](g16-controls-01/RESULTS.json) performed eight actual Rust checks: four genuine public proofs passed, including the deliberately private-valid/native-NF-invalid statement. A conserving fee/reserve Auth change, a changed proof, a foreign-role proof transplant and a wrong role rejected. Two width checks rejected before Rust; wrong checker bytes were an infrastructure error. A separate initial smoke check preceded the campaign. No PK, backup or private note witness was read, and no new proof was generated.

`public_native.normalize` authenticates the selected official native checker and independently recomputes the real v1 BLAKE3 ID and contextual masses without invoking the VM. It changes only derived ID/storage mass. The relation harness uses this interface alongside its independently checked public state and codec logic.

## Actual B1500 public controls

The [complete budget campaign](budget-controls-02/RESULTS.json) reused the three existing public genuine proofs under supplied synthetic UTXOs. B1600 and B1500 passed Full/all engines; B1475 rejected each case for the exact committed script-unit limit. Auth, proof, payload, transaction ID and authorized outputs stayed byte-identical. Only compute budget and derived mass changed.

| Fixed public case | Actual SU | B1500 slack SU | Reference100 required fee B1600 → B1500, sompi |
| --- | ---: | ---: | ---: |
| Compact continuing | 14,946,274 | 63,725 | 18,826,500 → 17,826,500 |
| Compact terminal | 14,841,729 | 168,270 | 18,718,200 → 17,718,200 |
| Wide32 | 14,969,639 | 40,360 | 19,701,700 → 18,701,700 |

Each observed fee floor falls by 1,000,000 sompi = 0.01 KAS. Actual paid fee remains 1000 sompi, so every body is deliberately underpaid at reference100. These are interoperability and sampled-slack results, **not** a universal B1500 safety bound, new adopted budget, market quote, complete lifecycle fee pass or accepted-chain rehearsal.

Nine calls comprise the successful campaign. The retained [diagnostic](budget-controls-02/DIAGNOSTIC.json) records three calls in an initial controller attempt and one focused diagnosis: the precompile wraps a meter error's Display text inside `ZkIntegrity`, rather than emitting its Debug enum name. The corrected predicate requires that exact wrapper/message and attempted-used > actual committed limit. Total actual native calls across those attempts are13; no timeout or generic failure counts as a budget rejection. The successful unit used2CPU/1GiB,487ms and39.7MB displayed peak, swap0; it was collected with manager MainPID0. Kernel remaining-process observations were unavailable.

## Architecture and remaining fee limit

The [source refresh](SOURCE-REFRESH-01.json), [selected R0 plan](PLAN-R0-SETTLEMENT-01.md) and ADR59 specify this fresh two-payment P0 wrapper using established checked BN254 verification and RISC Zero compression. Exact virtual transitions and actual native-body/fee binding are implemented. Old funded UTXOs do not acquire an upgrade or reusable-intent meaning. The child note/nullifier domain remains distinct from the outer journal's wrapper domain; private no-append fallback shares the original child spentness state.

One compressed outer verifier has a155,000-mass floor before script/bytes/storage; each independently settled private exit retains at least147,500. Even ideal two-way amortization therefore leaves2.25% verifier-only cost for10-KAS payments followed by independent exits. Low-demand economics and privately unilateral fallback remain explicit blockers; REVEAL's disclosed exit cost is not substituted. No privacy qualification follows from the new checker or budget controls.
