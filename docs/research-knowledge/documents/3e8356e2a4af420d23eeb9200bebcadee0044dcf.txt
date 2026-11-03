# Existing MWEB components: isolated feasibility experiment

Status: preregistered component/API screen before any harness implementation. Exact upstream is Litecoin `ec1b6489a900d09cf5991e220dce089c77a232a2`, already observed/pinned by the sources lane. No frozen capacity artifact will change. This is an unfunded library experiment, not a new currency, native KAS policy, deployment, privacy qualification or accepted-chain transaction.

## Research question

Can the existing upstream builders independently construct two signed, range-proved, value-balanced payments, then merge their **public transaction objects only** with `Aggregation::Aggregate`, retaining valid authorization/global balance while removing explicit per-author input/output partitions from the final serialized transaction? Which fields still permit linking, and which observer already knows the removed partition?

Primary inspected paths before implementation: upstream `src/libmw/test/tests/consensus/Test_Aggregation.cpp`, test-framework `TxBuilder.h/.cpp`, production `src/libmw/src/wallet/TxBuilder.cpp`, `src/libmw/src/models/tx/Transaction.cpp`, `src/Makefile.am`, MWEB consensus/kernels docs. The official aggregation test already validates two individually built transactions, merges/sorts their public inputs, outputs and kernels, sums public kernel/stealth offsets, and validates the aggregate. Inspect actual aggregation headers, serialization, input/output/kernel validators and dependency build before choosing the exact test command.

## Fixed observer boundaries

1. **Final chain plus one legitimate payee receipt (C1):** final aggregate public bytes and prior public UTXO/input references, public kernel fees/features/signatures, range proofs and output IDs/keys; one payee knows their own payment output, amount and declared payer. No producer-side owner map, per-component offset or unaggregated transaction is supplied unless actually serialized/published. Test only what the explicit public format/API shows. Absence of a grouping field is not computational anonymity or an exhaustive linkage attack.
2. **Coordinator/pre-aggregation network:** also sees each independently submitted public component. Original output/input/kernel IDs persist in the aggregate, so an observer can preserve its observed mapping. No claim that aggregation erases this knowledge. No spend secrets need be transferred to record that mapping.
3. **Singleton/sparse timing:** retain the case where one independent source/component exists, or a payment becomes public before any other source. Aggregation must not manufacture a second source, force unrelated demand or require waiting for another user before exit. The prior singleton ancestry failure is unchanged.

MWEB publicly identifies spent output IDs; this differs materially from hidden membership plus positioned nullifiers in the current KAS experiment. Its Pedersen commitments, value-balance kernels, stealth equations and Bulletproofs are an established alternative to study, not a drop-in implementation or a justification to invent a commitment/binding primitive.

## Experiment and limits

Prefer existing upstream `TestAggregation` plus relevant transaction/range-proof/signature/balance tests. If the available build permits a minimal harness, call existing upstream builder, serializer, aggregate and validator APIs only. Construct two independent payment-plus-change components with fixed declared accounting; ensure the aggregate API receives public transaction objects rather than the test wrapper carrying blind/spend data. Upstream test inputs may be synthetic owned UTXOs: label that explicitly, with no accepted-chain/backing claim. Do not dump generated spend secrets or hash them.

Record individual and merged validity, input/output/kernel counts, public offset summation, stable IDs and serialization layout. Record which grouping can be reconstructed by a pre-aggregation observer; inspect per-output sender-key reuse, kernel/offset features and input-output references before any positive interpretation. Use existing negative validators for unbalanced/dropped/duplicate components when available; no custom crypto implementation or altered verification checks. Do not select a privacy score threshold after seeing results.

Stop the executable experiment if it requires an unavailable external environment or unrelated installations. Retain the exact dependency/build error and a source-grounded feasibility result. Isolated source/dependency reads and a bounded build of at most4CPU/6GiB are authorized; no paid resource, node/network broadcast, funding, private KAS material or new capacity tests are allowed. The root's R0 proving window takes priority.

## Acceptance and interpretation

A component-positive result requires genuine upstream signature/range-proof/balance validation before and after aggregation, with public-only aggregate arguments. A separate format finding states whether explicit per-author output vectors/offsets survive the final serialization. A coordinator/pre-aggregation mapping is a retained negative, even if the final format has no grouping vector. If public final fields themselves retain a direct author/output partition, report that negative without changing the workload. Any native-KAS adaptation still needs a separate reviewed architecture, complete spend/output coverage and value binding, owner-local proving, current spentness, private unilateral exits and recovery availability.
