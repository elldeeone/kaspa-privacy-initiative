# Retained W1 owner-map execution evidence

Date: 2026-11-01

Status: **the projection-only view hides the two honest owner maps, but the
current offline executable bundle does not enforce that view and therefore does
not hide the map from a construction-root observer.**

## Named attack

The attack is the owner-labelled ingress/order-to-effects join:

```text
owner -> input NF -> that owner's two created output tuples
```

The observer uses explicit input ordering and output grouping, not a statistical
guess. Success means recovering both honest owners' complete maps after owner 1
contributes its legitimate self-knowledge and one known incoming creator.

## Existing executable paths

1. The retained offline W1 component path is executable code in
   `offline_w1_fixture.py` and `offline_w1_components.py`. Its retained two-round
   run is `.local/private-batch-offline-w1-components-20261029-01`. It produced
   real component witnesses, 12 genuine output proofs and two 10,685-byte
   projections within its explicit
   `OFFLINE_SYNTHETIC_UNBACKED_CLEAR_WITNESS_FEASIBILITY_ONLY` scope.
2. The current `compare_joint_core` release example executed the production
   constructor source twice and exited zero. It compared 12,919,677 model-core
   variables and 31,296,293 trace variables. Its scope is explicitly
   `PUBLIC_INVALID_CORE_ONLY_ORACLE_NO_PRIVATE_BODY`, so this proves constructor
   execution, not privacy.
3. The intended registered financial path is not executable. The selected gate
   was run directly and exited 78 with only:

   ```text
   KPI_REGISTERED_FINANCIAL_UNCONFIGURED_REFUSED
   ```

   It refuses before argv, files, owner input, sockets or MPC work.

## Actual retained-byte comparison

A read-only adapter was executed over the retained bytes. It used the existing
projection parser and exhaustive enumerator; no launcher, P1 capture, server
capture or new measurement subsystem was added.

- Baseline view: `projection.bin` plus the retained clear construction map.
- Candidate view: an explicit allowlist of `projection.bin` and
  `c1-residual.json` only.
- Candidate exclusions: `joint-ordering.json`, `w0-selection.json`, all owner
  records and preparation receipts.
- Every selected artifact matched its component checkpoint size and SHA-256.
- Truth was consulted only after enumeration.

| Observation | Round 1 | Round 2 |
|---|---:|---:|
| Baseline owner-linkage graphs | 1 | 1 |
| Candidate owner-linkage graphs | 6 | 6 |
| Honest complete maps uniquely recovered, baseline | 2/2 | 2/2 |
| Honest complete maps uniquely recovered, candidate | 0/2 | 0/2 |
| Candidate output-pair choices for each honest NF | 6 | 6 |

Across two rounds, the direct map has 1 baseline graph versus 36 candidate
graphs before any additional cross-round leakage. Owner 1's self-map remains
known by design.

Projection identities:

- Round 1:
  `f92f902668c569085aa27b9c03a5aeecda45a0e0a307890391337e9fe1dca037`
- Round 2:
  `913c82f44e75e4e908140f9c342feb7d222a977b9758a15acdeb77c598bf7b4d`

The full retained seven-stage checkpoint chain was also rehashed: 80 artifact
leaves and 526,061,629 bytes led to final checkpoint
`d787de9f71e206850f3d30c45628d5f0affbbc0d55149605117a9fec2a9abdd2`.

The machine-readable result is
[`RETAINED-W1-OWNER-MAP-OBSERVATION-2026-11-01.json`](RETAINED-W1-OWNER-MAP-OBSERVATION-2026-11-01.json).

## Why the current bundle fails to hide the map

`offline_w1_components.py` writes three clear map sources beside the projection:

- `joint-ordering.json` gives the input owner order and six output source rows;
- `w0-selection.json` gives the complete selected graph;
- the three owner records independently join each NF to its two output tuples.

Any observer able to read the component directory therefore recovers one exact
graph. The 6-per-round candidate result is valid only at an enforced
projection-plus-C1 boundary. The current offline path has no such boundary.

## Exact missing implementation

The first missing registered implementation is:

```cpp
int kpi::mpc::financial::selected_registered_financial_main();
```

`registered_service_selection.hpp` fixes
`KPI_REGISTERED_FINANCIAL_CONFIGURED` to `0`; no selected driver header defines
that function. A complete registered trial would additionally need the
production model/roster authority minters, their selected parent callsite, the
role-1 MP-SPDZ state hook or a narrow decoupling from it, and a production
projection-to-terminal handoff. That is not a small comparison patch.

## Smallest remaining change

For the public/terminal observer, the smallest functional change is a strict
release boundary that exposes only `projection.bin` plus legitimate C1 facts.
It must make ordering, selection, owner records and preparation receipts
inaccessible. The retained comparison already measures that exact boundary, so
no additional measurement framework is needed.

For a corrupt host or construction-root observer, an allowlist cannot provide
privacy: the map already exists in clear memory/files. The construction must
stop materializing it outside MPC or isolate it behind an actually private
boundary.

## Limits

- Both retained C1 residuals say `contact_value_authority_was_live: false`.
- This is actual retained component execution evidence, not a live registered
  MPC run, aggregate proof, corrupt-host privacy result, Testnet result or
  production privacy claim.
- The current full historical validator correctly refuses with
  `artifact-size-substitution` because three pinned relation-source files have
  changed. The retained checkpoint bytes are intact, but current-source semantic
  revalidation is not claimed.
- Broader server-state/P1 capture remains deferred.
