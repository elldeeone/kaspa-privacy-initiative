> Imported documentation snapshot. [Canonical status and ownership](../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# v6 relation: conservation, ownership and regression evidence

2026-10-22. Bounded source/evidence review at `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. No tests, proofs, builds, project imports, installs, code changes or current/private evaluation data. Output only in the workload-review lane. Read [AGENTS.md](../../../../AGENTS.md) and [SECURITY-INVARIANTS.md](../../../../SECURITY-INVARIANTS.md); coordinated the boundary with native_surface_review.

**Finding:** no demonstrated conservation or ownership bypass in the inspected relation. Amounts are constrained as bounded unsigned integers, input authority is tied to committed notes and positioned nullifiers, and padded inputs cannot contribute value. The three uncertainties below concern discriminating coverage and unexercised relation shapes. This is neither a formal proof nor independent cryptographic assurance.

The outer proof/public-input/native-UTXO binding and current nullifier-set enforcement belong to native_surface_review. This report does not treat the circuit alone as establishing native KAS backing. The intended `reserve = outstanding positive-note value` induction additionally requires valid genesis, authenticated state, actual native ingress/egress binding and current spentness.

## Source and evidence keys

All paths are under `/home/luke/projects/kaspa-privacy-shared-pool`, at the pinned commit.

- **C:** [poc/shared-pool/src/two_input/circuit.rs](../../../../poc/shared-pool/src/two_input/circuit.rs); **H:** `.../two_input/harness.rs`; **W:** `.../two_input/wallet.rs`; **WT:** `.../two_input/wallet/tests.rs`; **T:** `.../two_input/tests.rs`.
- **P:** [poc/shared-pool/src/protocol.rs](../../../../poc/shared-pool/src/protocol.rs); positioned-NF helper: [poc/shared-pool/src/compact/mod.rs:54–58](../../../../poc/shared-pool/src/compact/mod.rs). Constants: `two_input/mod.rs:20–22`.
- **E13:** `poc/shared-pool/evidence/2026-10-19-two-input-offline/{controls,summary,provenance}.json`, explained by `TWO-INPUT.md:98–139`: 15 constraint fixtures (4 positive, 11 negative), 15 genuine proofs and 13 positive native pool operations. Synthetic UTXOs; the sanitized bundle is not independently sufficient to reverify every private proof.
- **E20:** `poc/shared-pool/evidence/2026-10-20-wallet-lifecycle/{result,candidate-hashes-before}.json`, explained by `WALLET-LIFECYCLE.md:38–100`: six positive pool proofs plus one separate valid-proof malformed-delivery fork. Synthetic ancestry; no chain-acceptance claim.
- **WT** identifies current test implementation, not a fresh passing run. E20's saved 14-wallet/15-replay test result applies to its recorded candidate. Its circuit/H hashes match current source; wallet/P/lifecycle changed later. E13's circuit hash also matches current source, while its H hash differs. Historical results are preserved, not relabelled as executions of today's complete wallet.

## Invariant-to-coverage matrix

| Required invariant | Exact constraint/helper in current source | Existing negative control / genuine evidence | Remaining limit |
|---|---|---|---|
| **I-1/I-2: unsigned ranges; no modular inflation** | C:43–49 packs Boolean bytes; C:62–72 uses UInt64 low/high slacks. C:138,226 bound real inputs and positive outputs to `60,000,000..=MAX`; C:244–246 bounds positive payout to `10,000,000..=MAX`, fee to `1..=MAX`, admitted funding to `60,000,000..=MAX`. P:25 defines `MAX=2,900,000,000,000,000,000`. | E13 `minimum-note` passes; `below-floor-change`, `inflation`, `amount-overflow` reject. WT:790–828 rejects noncanonical/unsafe payment amounts before constraints; WT:541–544 rejects decrypted out-of-range notes. | `amount-overflow` is not an isolated upper-bound test; wallet parser tests do not establish circuit rejection. U1. |
| **I-2: two-input/change conservation in every mode** | C:117–124 restricts mode; C:133/212 prohibits real ADMIT inputs and requires at least one SPEND/DRAIN input. C:227/247–254 forces DRAIN outputs zero, DRAIN payout positive, ADMIT payout zero, and SPEND/DRAIN deposit zero. C:255–270 enforces `i0+i1+D <= MAX` and `i0+i1+D=o0+o1+W+F`. C:249 forbids fee-only destruction. W:477–490,509–512,573–578 uses checked totals/subtractions. | E13 `inflation` refreshes the changed output commitment but breaks conservation and rejects. Genuine H13 trace combines two receipts, returns change, partially withdraws, re-spends change, and drains: `56=50.8+5.2+0` tKAS. E20 recovers/merges two notes and drains: `32=29.6+2.4+0`. | Genuine coverage is selected successful traces, not all branches/boundaries. The current W action API has ADMIT/PAY/full EXIT; H13's partial withdrawal uses the harness. U3. |
| **I-3: real input ownership and historical membership** | C:74–84 commits owner/incoming/value/rho. C:132–151 makes real Boolean, enforces owner=`SHA256(tag,domain,secret,incoming)`, a positive value, 16-bit position and position below anchor count. C:158–179 recomputes the depth-16 membership root. W:299–317,382–402 requires owned, present, unspent selected positions. | E13 `second-owner`, `second-membership`, `wrong-position`, `wrong-domain` reject. WT:425–444 checks founder opening; WT:766–786 checks duplicate/foreign/padding/missing/spent selection. E20's foreign/duplicate/spent selections reject at wallet preflight. | Some fixtures break multiple constraints. The two-real E13 fixture uses one owner secret for both notes; no mixed-owner/permuted-input qualification identified. U2. |
| **I-2/I-3: padding cannot mint or bypass authority** | C:139–146/160–161 forces non-real owner, incoming, secret, value, rho, position and path to zero. C:212 requires at least one real input outside ADMIT. C:223–239 allows zero output values but still binds distinct nonzero commitments in append modes; DRAIN commitments are zero. H:23–31 constructs encrypted zero outputs using throwaway receiving data. | E13 `dummy-value` rejects; `zero-output-padding` passes. Genuine ADMIT/bootstrap/one-note DRAIN traces exercise padded slots. WT:546–556 ignores validated zero receipts; selection rejects padding. | Dummy value mutation also disturbs conservation. Freshness/throwaway ownership of output padding is a wallet construction assumption, not a proved property. Unexercised branch combinations: U3. |
| **I-4: stable real NF; no duplicate consumption inside a transaction** | C:87–101/180–207 implements HMAC-SHA256 real NF over tag/domain/commitment/position; no input-slot dependence. Dummy NF uses a distinct tag plus domain/seed/slot under its dummy key. Active NFs must be nonzero; C:213–218 requires distinct real positions and distinct active NFs. W:313/398 uses current positioned spentness. | E13 `second-nullifier`, `arbitrary-dummy-nf`, `duplicate-input` reject. T's sequential-insertion test checks replay/prior-set preservation. WT:702–762 checks equal commitments at different positions remain separately spendable using an explicitly unproved scanner fixture. | Duplicate-input fixture breaks both position and NF inequality; current-set absence is outside the circuit. HMAC preimage/collision resistance and fresh dummy secrets remain assumptions, not established by these tests. U2. |
| **I-1/I-3: bootstrap starts from one owned initial note** | C:123–124 forbids bootstrap+ADMIT; C:152/162–165 fixes bootstrap real position/path; C:220 forbids two real bootstrap inputs; C:271–274 binds declared bootstrap value to input sum and count to one. W:146–154 checks founder ownership/value/commitment. | E13 `bootstrap` positive constraint check; H13/E20 genuine bootstrap transactions. WT founder-opening mutations reject locally. | Native enforcement of when bootstrap is required and its equality to actual reserve is the other reviewer's boundary. No isolated negative bootstrap branch suite identified; U3. |
| **I-14: receipt credit requires spendability, not successful decryption alone** | C:223–239 binds output commitments/value, not correct encryption or knowledge of an output owner's secret. P:182–204 and W:585–614 validate domain, owner, incoming key, value and commitment; W:305–317 adds membership/position and spentness. W:336–346 ignores invalid deliveries without blocking valid notes. | WT:509–581 covers wrong owner/commitment/domain and floors; WT:646–698 checks scan continuity. E20's seventh genuine proof binds a ciphertext opening to the wrong commitment; no false credit, prior claim retained, and its exit prepared/circuit-checked. | This supersedes the older generic “malformed-delivery negative missing” gap for that case. No eighth proof/settled exit on that fork is claimed; no claim of universal delivery/privacy assurance. |

## Why the field equalities do not silently wrap

This is static reasoning about the inspected gadgets. Arkworks 0.6 `UInt<N>::new_variable` allocates Boolean bits; `AllocatedBool::new_variable` enforces `(1-b)b=0`. All amount inputs/slacks are therefore at most 64 bits. The largest sum in the conservation/aggregate equations has four such terms, below `2^66`, far below the BN254 scalar modulus in pinned `ark-bn254-0.6.0/src/fields/fr.rs`. Lower/upper slack equations likewise remain below that modulus. Nonnegative bounded slack makes the intended integer inequalities follow.

The Rust `saturating_sub`/clamp expressions only supply candidate slack assignments. They do not replace the equations: an over-limit total still has to satisfy `total+UInt64_slack=MAX`, and cannot do so by underflow or field wraparound. This reasoning assumes correctness of the checked arkworks gadget implementation; it is not a formal circuit proof.

The circuit authorizes variable fees in its allowed range. **40,000,000 sompi is the current wallet/test policy, not a fixed circuit fee.** The minimum-note exit argument is therefore conditional on its declared fee/mass envelope.

## At most three material uncertainties

1. **U1 — isolated amount-bound coverage.** H:813–815 changes an input to `u64::MAX` without rebuilding its committed leaf/path/NF or restoring conservation. Its rejection does not independently test the upper/aggregate bound. No discriminating circuit pair at `MAX/MAX+1`, aggregate overflow, or fee/payout extrema was identified. Source constraints appear to cover them; this is a coverage gap, not an overflow finding.

2. **U2 — independent ownership/NF and slot coverage.** H:774–776 changes the spending secret while leaving its real NF unchanged, so owner binding is not isolated. H:768–773 simultaneously violates position and NF distinctness; wrong-position also breaks membership/NF/count constraints. Reversed input ordering, one real note solely in slot 1 and different-owner two-input witnesses are not separately qualified in the inspected records. Existing rejection results remain valid, but do not show each guard would catch a regression independently.

3. **U3 — mode/padding and genuine boundary coverage.** The 15 constraint fixtures do not exhaust mode-specific negatives, such as no real active input, an ADMIT real input, nonzero DRAIN outputs or fee-only destruction. Genuine v6 minimum-note exit qualification remains explicitly open in RFC-0011 and TWO-INPUT.md; older v3/v5 minimum exits cannot close it. The newer lifecycle malformed-delivery result is retained as positive evidence for its exact case.

**Recommended next assurance step, if later authorized:** design guard-isolating constraint controls for U1/U2 before allocating another full-proof or traffic-experiment budget. Preserve the current relation, setup, fees/floors, native KAS backing and independent-exit requirements. No present result permits weakening those gates or resurrecting a failed privacy policy.

## Reproducibility pins

SHA-256, relative to the repository root:

```text
59071901c3abc25daab68c982ef065f8755c09abbb2ce30e6010d821813dd2a7  poc/shared-pool/src/two_input/circuit.rs
3039fe885379aeec3b2378ee4b881a46e01b5bc1d3e6e68d706852c6a39070e5  poc/shared-pool/src/two_input/wallet.rs
8375ce42bcd647060565df32992dc5dd0ed31be9c9e8fc1ce0b93d6180cfe827  poc/shared-pool/src/two_input/wallet/tests.rs
1bad02792f96632892487ec6af9aa94aa4fc2f14c6ecab28602f75174286583d  poc/shared-pool/src/two_input/harness.rs
85749c72f8043d556799cd2045c386093737caa506cb387aa52b553428f3b643  poc/shared-pool/src/two_input/tests.rs
5243cab1b36e0d9cae8bf13e81b7fcdb033c8dc1bc7405daa401c69334cc4ec4  poc/shared-pool/src/protocol.rs
bafe1acfeeef9c9fcb5d360453c48b315c0507f7cf51b7f741b35b8909adaa3c  poc/shared-pool/evidence/2026-10-19-two-input-offline/controls.json
34b1af8920ec3987b9096eb37f800e9f57e457d5f2c1ec3961422763d190d638  poc/shared-pool/evidence/2026-10-19-two-input-offline/summary.json
e720810d264ecfd4195e99ce60306d4e5e228efc55e39e8d41ef9c68acf4e58d  poc/shared-pool/evidence/2026-10-19-two-input-offline/provenance.json
f83ad3cbca35431a605e09a3b80e0845e9c6de21f4ad9c903a69043be876be2c  poc/shared-pool/evidence/2026-10-20-wallet-lifecycle/result.json
0afb542346dd46cf4f5c7e557a8a91d65736c1bfd4a024239d48ce5d71288994  poc/shared-pool/evidence/2026-10-20-wallet-lifecycle/candidate-hashes-before.json
```

Installed locked-library source SHA-256: `ark-bn254-0.6.0/src/fields/fr.rs` = `05bd67486b5fc6ed6ed5e70e2e6673794797502e671aaf0e9108e8ebb7f18fbf`; `ark-r1cs-std-0.6.0/src/uint/mod.rs` = `6b0d0a77a926da6cf5329c8aeec87d84098e2a214d5a38a6da5d4572a4110c6c`; `src/boolean/allocated.rs` = `428c2dc11d7aaaf4ebf923f77d5f2b7465c9c46f27e296d4d9953803862cc406`. No library code was executed.
