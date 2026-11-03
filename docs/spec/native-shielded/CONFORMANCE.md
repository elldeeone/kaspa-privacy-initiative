# Draft conformance and remaining gates

Run from the repository root:

```sh
python3 scripts/check_native_shielded_spec.py
```

This read-only check binds the actual portable capsule/profile, exact activation,
transaction/signature, header/state/snapshot preimages and hashes, integer
accounting and 13 negative controls. It also checks **symbolic** counter/rollover/
old-marker/undo obligations. It implements no native node, Sinsemilla replay,
authenticated ordinary state, signature verification, actual GHOSTDAG, durable
undo, pruning import or mass calibration. Native acceptance remains false.

The [frozen vectors](artifacts/conformance.json) contain exact hex inputs and
expected hashes. The [transaction bytes](artifacts/native-transaction-encoding.bin)
are a serialization example using public synthetic experimental Action/proof
data. **Its original signatures do not authorize the new native message**, its
ordinary outpoint/header are fake, and storage mass is a placeholder. No test
labels this a valid native transaction, accepted history or qualified snapshot.
These fixtures test bytes and commitments, not validity by self-declaration.

Separate real cryptographic evidence is the preserved
[interoperability package](../../../poc/orchard-interop/README.md): three genuine
complete repaired-V2 bundles and actual Halo2/signature negatives. The
[copied-source key export](key-export/README.md) reverified those existing bundles
and reproduced the actual mathematical capsule without changing that package or
the original dependency cache. Python independently decoded the full capsule
and compatibility scalar provenance. Native key import still needs implementation.

## Adversarial specification review

| Failure | Draft treatment and remaining limit |
| --- | --- |
| Fake input amount or old plain-key signature mints notes | Actual UTXO lookup, new all-effects/context message, standard-key script scope and real native input signature validation are required. Hash-only fixtures authenticate no UTXO. |
| Old contract unaware of shielded balance leaks funds | First profile rejects arbitrary/P2SH/covenant inputs and outputs. General contracts need explicit new semantics/review. |
| Hidden range/field-wrap counterfeit | Complete repaired construction plus explicit integer-lift/backing induction; no fictional hidden M gadget. Independent soundness/accounting review remains. |
| Same real/dummy marker in concurrent blocks | Global immutable-domain N, body uniqueness, serial accepted-state checks, atomic rejection. A valid proof/cache never proves current absence. |
| Tree fills and all future exits become impossible | Automatic depth-32 rollover retains full old anchors and N; no leaf/NF relabeling. Global finite-counter exhaustion still needs migration before exhaustion. |
| Side-block root authenticates an unbacked note in current history | Only A from reconstructed accepted batches is eligible. Side headers alone add no anchors. Current-block qualification is not partial mergeset filtering. |
| Header hashes omit native root or commit wrong point | Proposed header3 explicitly includes native root in full/PoW prehash at the same past point as UTXO state. Actual native PoW/header/pruning code remains absent. |
| Snapshot authenticates itself | Independently qualified P required; exact complete N/A/L/frontier counts/roots and ordinary/native point pairing. Fresh-validator profile requires full replay; no new trusted server/bootstrap shortcut. |
| Capsule hash silently changes proof transcript | Capture/use exact existing scalar; do not replace it with capsule/profile hash. Source Debug derivation remains provenance, not portable serialization. |
| Well-formed malicious key passes decoder | Only the fixed expected capsule identity/profile is accepted. Decode consistency is not authorization, soundness or native key import. |
| Public fees/tree/anchor metadata or later transparentization leaks facts | Keep observer/counterparty knowledge, b/B, age, timing and full drainage in scope. No new privacy pass or threshold change. |
| Archive/prover/relay disappears | Owner authority stays local; complete independently available data/software and affordable fees remain required liveness assumptions. No admin rescue. |

The review identified three substantive corrections to carry forward: current
header2 cannot be reused for this extension; upstream proof transcripts contain
a Debug-derived compatibility value that must be preserved; a single finite note
tree would eventually block exits. The draft addresses each explicitly while
retaining the independent review and qualification gates.

## What still blocks deployment or qualification

1. Independent Kaspa/cryptography review of the complete format, forest/anchor
   semantics, proof ABI, standard-input policy, backing induction and proposed
   I-1/I-2 amendment. No invariant change is adopted by writing this draft.
2. Actual native node/wallet/P2P/RPC implementation, portable key import/backend
   conformance, real UTXO signatures, accepted DAG/store/undo and replay/bootstrap
   integration; genuine conflicting-block/reorg and cold recovery evidence.
3. Approved version/activation allocations and measured mass coefficients/limits.
   The schema/formulas are specified; the real network deployment parameters
   remain deliberately unset. No fixture activates a network or quotes fees.
4. A feasible explicitly scoped privacy qualification claim/population and full
   matched privacy/cost/storage/performance/service-loss recovery evidence. The
   retained 21.10% prior-only floor against 20% remains an unchanged failure.

The next implementation deliverable, after the relevant reviewed accounting
decision, is an unfunded native-consensus integration prototype against this
draft and actual positive/negative transaction/DAG/recovery vectors. This task
writes/tests the specification and portable artifacts; it does not do that work.
