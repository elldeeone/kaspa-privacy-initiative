# ADR-0037: Test a continuing S7 lifecycle with direct owner exits offline

**Status:** Accepted — bounded, supplied-UTXO public experiment; DO_NOT_FUND.

**Date:** 2026-10-23 Australia/Sydney.

The [RFC-0018](../rfc/0018-paired-native-settlement-experiment.md) experiments
established a state-aware receipt and a one-shot native diagnostic, but its
fixed predecessor guard cannot continue and its discarded inner proving key
cannot supply owner exits. Test those missing mechanisms in a **new isolated
profile**, using established v6 proof/state primitives. This decision precedes
prototype code; it does not upgrade the completed one-shot policy, establish
accepted backing or select a production architecture.

The owner has already authorized sustained local research and CPU/GPU work.
The source starts in `/home/luke/projects/kpi-intensive-2026-10-22/lifecycle`,
branch `work/s7-owner-lifecycle-20261022`, from
`ec6aa15d586bcc8a90f7232b433fd48d8c73d509`. Preserve integration's existing v6,
J42, J336, images, parameters and one-shot evidence unchanged. Resource releases
below are internal technical coordination, not another user-permission step.

## Evidence and alternatives

The decision uses three independently hash-checked design inputs:

| Input | SHA-256 |
| --- | --- |
| [Binding/source proposal](../../../binding/research/intensive-2026-10-22/OFFLINE-PAIRED-OWNER-LIFECYCLE-FEASIBILITY.md) | `e5f17ca5cc3dc7bcdcaffe904aff655b5d83f00534a640b659dc0648b2f9a47c` |
| [Independent architecture review](../../../observer/research/s7-offline-lifecycle-independent-review-2026-10-22.md) | `9222f33a0a5f2fd6ea3d941fcbf04af001bf5041b5454561c35c9300817dbb8c` |
| [Public replay and owner-wallet plan](../../../native/research/intensive-2026-10-22/S7-PUBLIC-REPLAY-WALLET-DESIGN.md) | `12e0da36d5b15c7da817cb6658d6ba864b30b74e7c637240f7e30c7cbdbbc1e4` |

| Alternative | Disposition |
| --- | --- |
| Extend the fixed-predecessor one-shot diagnostic in place | Rejected: it has no continuing owner-exit contract, and changing it would erase the evidence boundary. |
| Add only a DRAIN branch or privileged rescue | Rejected: initialization, admission and shared spentness remain essential; no administrator may replace an owner's authorization. |
| Reverify both inner proofs natively beside the receipt | Rejected for this profile: the reviewed state receipt already checks them; duplicated verification changes the resource question. |
| New immutable ordinary/paired policy with one shared S7 state | Selected for the bounded offline experiment, subject to actual emitted-code, proof, owner and native gates. |

The independent review found no source-level accounting, shared-state or known
length obstruction. It did not qualify an emitted script, budget, setup,
continuing native transaction or owner exit. Those objections remain explicit
gates rather than assumed outcomes.

## Decision

1. **Use a fresh public test instance.** Reuse the v6 circuit, established
   Groth16 verification, hashes, trees and owner authorization. Keep the
   377-byte inner `KPICU06\0` relation unchanged. Select new fixed domain,
   poolID, inner VK and state image; pin the official outer VK/profile. Setup
   uses fresh `OsRng`. Stream-save and hash the public PK, retaining it through
   both owner proofs; do not serialize toxic scalars or RNG state. Wallet
   seeds alone are deterministic, intentionally public `DO_NOT_FUND` data.
   This single-party setup is **UNTRUSTED TEST** material: absence of saved
   scalars is neither parameter security nor secure-erasure evidence.
2. **Avoid an identity cycle.** Independently fix domain/poolID and fresh VK,
   then the guest/image, complete native body, founding transactions and actual
   paired predecessor/J336. The guest accepts checked predecessor context; it
   cannot compile a not-yet-known founding outpoint or final script hash. Host
   validation must check the exact canonical key before any compiled static-VK
   optimization. Fixed guest keys and image are independently pinned.
3. **Preserve one complete immutable native policy.** The redeem prefix is
   `<poolID32> DROP <S7[105]> DROP`, followed by the entire fixed body containing
   both branches. Prefix poolID is distinct from inner authorization domain;
   every adapted ordinary domain check uses the separately fixed domain.
   Ordinary bootstrap/ADMIT/SPEND/DRAIN retain all proof, funding-signature,
   amount, owner-destination, history and current-NF checks. The paired branch
   uses one compressed outer Groth16 proof and reconstructs J336 from the
   actual supplied predecessor/outpoint/state, P, next state and amounts.
   Both branches require the entire identical successor suffix, including
   both keys, image, dispatcher and direct exit. Terminal DRAIN has no reserve
   successor and exactly the authorized owner payout. No rescue key is added.
4. **Freeze the branch ABI before coding.** Payload header is
   `ASCII("KPI2LCT1")[8] || u16le(1) || branch:u8`; only 0 ordinary and 1 paired
   are valid. Ordinary payload is exactly 5,231 bytes: header11, auth377,
   ciphertexts370, nextS105 and relative witness4368, at offsets
   11/388/758/863. Paired payload is exactly 1,204 bytes: header11, P1088 and
   nextS105, with P at11 and nextS at1099. Reject trailing, unused, mixed or
   unknown layouts. Each scriptSig is exactly
   `4c80 || proof128 || 4d || u16le(redeem_length) || redeem`.
   Selector belongs only in the payload. Each branch consumes its own proof,
   leaves one success item and has no unused selector/alternate-stack residue.
   J336 keeps its existing serialization/tag but the new poolID and image:

   ```text
   "KPI2V6S1" || u16le(1) || SHA256(P)[32] || fixed_pool_id[32]
   || prior_outpoint[36] || prior_state[105] || next_state[105]
   || u64le(R) || u64le(R')
   ```

5. **Initialize and reconstruct the actual offline lineage.** Only the named
   public seed UTXOs are supplied assumptions. Verify all generated founding,
   funding and pool transactions against their actual predecessors and track
   consumed outpoints. Genesis n1/m0 authenticates the founder's initial CM,
   sentinel NF root and count1 history; it is bootstrap-pending until the real
   proof/native transition binds the unique note and actual reserve. Preserve
   legitimate owner-authorized founder DRAIN. ADMIT/pair require initialized
   even m>=2; do not apply the pair parser globally to genesis. Keep ordinary
   funding/change/miner fees separate from pool accounting. All native genesis
   and chain-acceptance claims remain false.
6. **Share every state update and preserve positions.** Keep the reviewed
   raw-byte P record/NF order distinct from the indexed NF set's unsigned
   little-endian comparator. Paired processing applies four current NF
   insertions and four complete CM/ciphertext records, preserving duplicates
   by position, then both history prefixes `(n+2,r2)` and `(n+4,r4)`. The first
   prefix is not another accepted reserve UTXO. Ordinary DRAIN appends no
   CM/history and refreshes current NF witnesses after preceding exits.
   Explicit capacity bounds apply to each branch; arbitrary supplied counts
   do not establish reachable-state or liability induction.
7. **Test owner independence with fresh proofs.** The initial producer makes
   only four genuine inner proofs: bootstrap, ADMIT and two compatible SPENDs
   at the same count5 anchor. After the paired proof/public native context is
   complete, stop the producer, collector and outer-prover workers. Run two
   fresh isolated owner CPU-DRAIN commands, Alice then Bob terminal. Each gets
   only its own public-test backup, the complete public ledger, hash-pinned
   public PK/VK and owner/native code. Exclude other-wallet/truth artifacts,
   hidden A/Q/grouping, outer-prover executables and separate host SDK receipts.
   The public paired transaction's compressed proof remains available for
   native replay. The generic CLI embeds no other wallet seed. Verify each
   payout is spendable using that owner's derived native key. This tests
   dependencies and liveness, not secrecy or independent-human readiness.

The exact main trace is in **millions of integer sompi**:

| Transition | n / m after | Reserve after | Positive claims or native payout | Pool fee |
| --- | ---: | ---: | --- | ---: |
| Founding | 1 / 0 | 800 | Alice800; bootstrap pending | — |
| Alice bootstrap | 3 / 2 | 760 | Alice400 + Alice360 | 40 |
| Bob ADMIT940 | 5 / 2 | 1,660 | Alice400+360; Bob450+450 | 40 |
| Compatible pair | 9 / 6 | 1,580 | Alice320+500; Bob400+360 | 80 |
| Alice direct DRAIN | 9 / 8 | 760 | Alice native780; Bob400+360 remain | 40 |
| Bob terminal DRAIN | logical9 / 10 | 0 | Bob native720; no live claims | 40 |

Thus `1,740,000,000 = 1,500,000,000 + 240,000,000` sompi for pool inputs,
payouts and pool fees. This is six inner proofs, five pool spends and a founding
transaction. Founding ordinary fees are additional, separately accounted
costs. Pair history includes counts7 and9; no standalone count7 reserve exists.

## Qualification, limits and reconsideration

Freeze the generator/source plan, semantic cases and parameter-independent
count/amount vectors before setup. Follow the identity order in Decision2:
freeze fresh VK/domain/poolID, then image/body and the resulting exact public
roots, native bodies, P and J before their respective proof stages. Exact
VK-dependent transaction/journal bytes cannot precede fresh setup. Do not retune
the cases, accounting or success gates after an outcome. First measure/review
the new emitter, exact framing, stack behavior and charge inventory.
**24,576-byte redeem, 24,709-byte scriptSig
and budget1700 are provisional targets.** The reviewed paired envelope is
16,489,282 units versus allowance17,009,999, conditional on the described new
code. The old v6 budget1600/source bound does not qualify it. Actual full-native
compute/storage/transient limits, mass and fee quotes at100/200/500 remain
required; preserve a higher-rate fee failure instead of repricing authorizations
or adding sponsorship. Root releases heavy setup/proof only after the frozen
source/generator stage passes review.

Public replay must use a separate S7 decoder and reconstruct ordinary2 /
paired4 / DRAIN0 records, exact roots, integer accounting, bodies/IDs/fullhashes
and current consumed outpoints. It cannot call a hidden-input state gate on
public P or invent private A/Q grouping. Authenticate the exact public state
transition through native proof/context validation. Require replay with A/Q
unavailable and independent owner scans preserving equal records at different
positions. Existing v6 parsers and descriptors remain unchanged.

Before reporting a completed lifecycle, require genuine inner and outer
proofs, independent host/guest/state equivalence, actual native branch and
whole-transaction checks, both fresh isolated owner withdrawals, destination
spendability and exact conservation. Meaningful controls cover malformed
framing; wrong keys/image/domain/poolID; removed exits/changed suffix;
uninitialized admission/pair; stale/current/cross-branch NF and outpoint replay;
occupied/skipped CM/history updates; reordered/re-paired/deduplicated records;
wrong owner/payout/extra outputs; integer narrowing/negative-zero/overflow;
capacity, stack, underbudget and mass boundaries. A valid reverse owner order
is a separate fork; conflicting reserve spends cannot be combined.

Stop on unresolved root, accounting, framing, exit or native-limit failures.
Record them without weakening checks. Missing public data, PK or prover may
halt liveness; it cannot create another withdrawal authority. Record verified
outcomes in the [results register](../../research/intensive-2026-10-22/RESULTS.md).
No implementation or readiness result follows from this ADR.

Even a complete pass would be tested **offline supplied-UTXO composition**, not
accepted chain ancestry, authenticated KAS backing, parameter security,
financial privacy, production safety or qualification against all adopted
CPU/memory/timing/fee/recovery requirements. There is no funding, trial,
broadcast, mainnet deployment, reserve migration, new token/cryptographic
primitive or publication in this decision. The
[security invariants](../../SECURITY-INVARIANTS.md),
[privacy requirements](../rfc/0012-useful-privacy-requirements.md), frozen
512-ledger result and rejected withdrawal policies remain unchanged. Parked
recovery/attack work is outside this experiment.
