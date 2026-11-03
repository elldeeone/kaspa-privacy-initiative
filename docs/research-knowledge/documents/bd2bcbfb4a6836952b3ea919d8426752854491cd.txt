# Bounded owner-linkage comparison

Date: 2026-11-01

Status: **direct-map attack defeated in the public synthetic structural
control; actual privacy remains unqualified.**

## Attack being addressed

The transparent construction exports enough ordering/grouping information to
link each public input nullifier (`NF`) to:

1. its owner; and
2. the same owner's two created public output rows.

That is an exact owner-to-payment-graph disclosure. With owner 1 fixed as the
legitimate colluder, the transparent map still collapses both honest owners'
input/output graph to one assignment. This is narrower than traffic analysis,
active retry/intersection, arbitrary corrupt-host leakage, or terminal payout
linkage.

The candidate change is equally narrow: the public/terminal boundary exposes
one whole aggregate and no owner-labelled NF, creator map, pair tag, individual
delta, or NF-to-created-pair edge. The observer retains owner 1's legitimate
input, two created outputs, and known incoming creator.

## Minimum comparison

No new launcher, sandbox, proof runner, P1-state recorder, C1 authority graph,
or Testnet trial is needed to test this direct disclosure.

The comparison reused the existing exhaustive enumerator and the same public
rows and hidden two-round truth in both arms:

- baseline: add the transparent direct owner/NF/output-pair map;
- candidate: retain only public aggregate rows and legitimate owner-1 facts;
- enumerate every compatible input-owner, output-creator, pair-partition and
  NF-to-pair assignment before joining truth;
- score truth retention, honest-owner swap and a different-pair graph
  alternative.

The exact machine-readable result is
[`BOUNDED-OWNER-LINKAGE-COMPARISON-2026-11-01.json`](BOUNDED-OWNER-LINKAGE-COMPARISON-2026-11-01.json).

## Result

| Measure | Transparent baseline | Hidden-mapping candidate |
|---|---:|---:|
| Input-owner assignments, each round | 1 | 2 |
| Output-creator assignments, each round | 1 | 3 |
| Output-pair partitions, each round | 1 | 3 |
| Joint assignments, each round | 1 | 6 |
| NF-to-created-pair relations, each round | 1 | 6 |
| Correct unique NF/owner links | 3 | 0 |
| Correct unique output/creator links | 6 | 0 |
| Correct unique NF-to-pair links | 3 | 0 |
| Two-round candidate graphs before extra cross-round leakage | 1 | 36 |
| Honest input swap retained | no | yes |
| Honest different-pair graph retained | no | yes |

Truth remained in both arms. Four focused controls passed, including the
transparent constructor-map collapse, the colluder-only alternative, the
two-round join and the frozen synthetic acceptance check.

```text
python3 -m unittest -v \
  privacy_test.CandidateControls.test_constructor_map_and_individual_delta_controls \
  privacy_test.CandidateControls.test_known_incoming_edge_still_allows_unknown_graph_alternative \
  privacy_test.CandidateControls.test_v2_workload_retains_consistent_unknown_graph_alternative \
  test_privacy_acceptance.AcceptanceControls.test_synthetic_model_baseline_to_hidden_mapping_candidate_passes

Ran 4 tests in 3.712s
OK
```

## Reassessment

The execution work had become over-scoped for this attack. A complete pinned
passive-P1 process image is relevant to the broader question, "does hidden
cryptographic state re-identify the mapping?" It is not required to establish
whether an explicit constructor/terminal map itself defeats privacy.

The current architecture cannot produce an honest **actual corrupt-P1+C1**
comparison cheaply: no actual transparent/candidate pair exists under one
selection, the selected C1 runtime callsites are absent, and the required P1
state families are not integrated. Continuing the Bubblewrap/proof/capture
framework would not change the direct-map result above.

If an actual follow-up is selected, the minimum is one paired offline run at
the existing financial output boundary, capturing only the public projection,
terminal grouping and legitimate C1 facts for the same workload. Those bytes
can feed the existing enumerator. The broader complete-P1 claim must remain a
separate experiment; it must not be smuggled into this bounded result.

This result is not an actual financial execution, corrupt-P1 measurement,
cryptographic privacy proof, terminal-exit result, Testnet result, or production
privacy claim.
