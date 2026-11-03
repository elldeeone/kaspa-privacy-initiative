# Native admission adapter: independent source review

**BOUNDED STATIC ACCEPTANCE. No concrete source blocker found for the fixed four-case adapter.** Snapshot: 2026-10-22T09:45:26.625760+00:00. This accepts the source design for separately qualified build/execution, not compilation, runtime equivalence, new admission coverage or execution release.

Review occurred only on Forge, through source/proposal/manifest reads, byte hashes and Git identity comparisons. No compiler, formatter, import, validator, VM, proof, setup, recovery, replay, private evaluation or service command was executed. The separate recovery-v2 proof job remains outside this review.

## Exact scope and identity

The package is `/home/luke/projects/kpi-orchestration/2026-10-22/native-surface-review/admission-input-adapter-proposal`. All **24 manifest files** matched recorded sizes/hashes. Test-source commit `fde0c288d42ff58482d8b05df85e033806b64ecb` has exactly one addition against `c430dd8a18d738a2d6ead9246d9650a4c1fe1933`: `poc/shared-pool/src/bin/kpi-admission-input-controls.rs` (246 lines). Its current bytes equal the committed object. No production-core or dependency change appears in that delta. The pinned SDK checkout and referenced SDK source bytes match commit `01b532e8b553523216471682649693af92f0fd16`.

The prior report remains **six executed passes and two admission mutations NOT EXECUTED**, with no admission-negative coverage. This source-only proposal adds **zero executed cases**. The fixed public fixture is the previously published wallet-lifecycle positive admission; it supplies an existing genuine proof, not a new proof or fresh chain-state attestation.

## Fidelity to full validation

In the following table, “adapter” means the added file; “SDK validator” means `consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs`.

| Obligation | Source conclusion |
|---|---|
| Complete transaction and exact UTXOs | Adapter 92–122 pins the original fixture, canonical ID/full hash, two-input shape, unique public parent outputs and exact input outpoints. DAA 0/non-coinbase/no-covenant-ID are the declared synthetic offline context, not inferred current chain state. Adapter 64–77 retains the entire transaction and both entries for every indexed VM. |
| Same covenant/sequence context | Adapter 65–71 uses `CovenantsContext::from_tx`, attaches it, and supplies sequence-commit accessor None, matching SDK validator 163–178 and the existing `native::validate` caller at `native.rs:334–345`. |
| Same TESTNET flags and input budget | Adapter 72–78 uses `Gram(TESTNET_PARAMS.mass_per_sig_op)` and each input's actual `compute_commit.allowed_script_units()`, matching `native::validator` at 319–332 and SDK validator 170–173,191–207. It does not substitute default flags or unlimited units. |
| Cache/ordering difference is bounded | A fresh signature cache and unsynchronized reused-hash object are used per input. The production two-input path uses synchronized shared caches and parallel checking. SDK `hashing/sighash.rs:51–138` implements the same hash-producing callbacks with different storage. This supports source-level semantic consistency; runtime baseline/attribution agreement is still required. No scheduling/cache-performance equivalence is claimed. |
| Preliminary gate is never acceptance | Adapter 50–58 retains isolation and populated prerequisites, including mass and covenant context, with `SkipScriptChecks`. SDK validator 37–65 confirms it omits script checks. Adapter 195–221 separately calls full native validation and actually executes both per-input VMs after the gate; records explicitly label the gate as non-acceptance (228). |

## Required attribution and stop behavior

The order and required outcomes in adapter 146–235 are suitable:

1. Genuine admission: full-native acceptance at the fixed fee, plus input 0 and input 1 VM acceptance.
2. Funding-signature-only control: one interior byte changes while framing/hash type remain intact; full native rejects, reserve input 0 accepts, funding input 1 returns `EvalFalse`.
3. Successor VK commitment mutation: full native rejects; input 0 returns `VerifyError`, and funding input 1 separately returns `EvalFalse`.
4. Successor code commitment mutation: the same attributed outcome requirements.

No later case starts after an earlier failed contract. Missing prerequisites, wrong VM variants or unexpected acceptance cannot earn guard coverage; the program emits its partial record and stops. A final complete summary exists only after all four contracts pass (235–245).

The unchanged successor must first reproduce the actual output (adapter 123–140). Mutations then change only the declared field and derived ID; canonical JSON equality plus explicit payload/input-0/storage-mass preservation guards the genuine proof, current redeem, authorization, state, values and context (154–193). The source target is the actual successor output equality in `two_input/covenant.rs:116–132,553–570`. Negative cases do not execute the proposed future redeem/VK or establish a proof under it; those early guards precede proof verification. Aggregate rejection alone remains insufficient.

## Remaining decision

Successful compilation, the genuine baseline, attribution control and both missing guard outcomes remain unverified. The proposal correctly keeps build/runtime allocations separate: no warm cache is currently qualified, no cold dependency build is silently authorized, and no resource reservation follows from this review. Parent owns those gates and current shared-system capacity. Any later pass concerns these two successor-commitment guards on this exact offline public fixture, not current-network acceptance, general admission security, privacy or cryptographic soundness.

## Stable identities

- `PROPOSAL-MANIFEST.json`: `a14dc8a23ec16d105c68de01ee9faa6cae715b00e95d9cc7cf7e9dd42e24cce8`
- `ADAPTER.patch`: `9a3c020fc08a39839551e00eb9d97bfdaec1cf1eb8f593d619034e7aca40bfee`
- `kpi-admission-input-controls.rs`: `54932085b15a44c97669d905643c2c270a7ce555c6cb26ff0a8858bc1ed796e2`
- `ADMISSION-INPUT-ADAPTER-PROPOSAL.md`: `3d3ba9518575df3daf61a404c14ea13c3559bc729868c368503e1aaf41d00778`
- `CONTINUATION-ADMISSION-CONTROLS.md`: `62c998e90cfdd9a09cd1065311ed2b1c2dbe217de4ad7e03dcfbc2435490f281`
- Pinned SDK validator source: `8e6f22b0f0280df9c3baad39654e3ce15c0b25cc5a97b720add1bbdc721e6786`.
