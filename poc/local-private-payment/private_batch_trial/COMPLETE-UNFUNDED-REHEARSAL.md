# Complete unfunded lifecycle bridge

Status: source contract and final gate are fail-closed. No complete lifecycle
has executed. No private input, proof job, network operation, funding or
broadcast was run while adding this bridge.

Under ADR-0084 this is an end-of-run cryptographic/evidence recheck, not the
pre-funding launch authority for the first current-profile Testnet trial. The
narrow launch boundary is `activation_preflight.py`; it carries no terminal or
readiness claim. After the full Testnet path, `complete_testnet_trial_gate.py`
must additionally join the actual accepted CASEs, payouts, service loss,
double-spend refusal and terminal privacy evidence.

## One-command boundaries

A fresh unfunded Original identity remains:

```sh
python3 -B poc/local-private-payment/private_batch_trial/funding.py new \
  --label FRESH-UNUSED-LABEL
```

The intended post-run interface is one command:

```sh
python3 -B poc/local-private-payment/private_batch_trial/complete_rehearsal_manifest.py \
  --source ABSOLUTE-SOURCE-CONTRACT.json \
  --source-sha256 EXACT-SHA256 \
  --output FRESH-MANIFEST.json
```

This command is currently expected to refuse. It is an evidence join, not an
execution driver or readiness claim. `rehearsal_gate.py` reads the source
contract again and reconstructs the manifest before it runs any native checks.
A hand-written CASE list cannot pass.

## Required chain

The v1 source contract binds all of these by absolute path and SHA256:

1. one fresh three-Original trial and signed NativeFull GEN3;
2. exact baseline/candidate capture chains, owner non-regression receipt and a
   recomputed four-view privacy result bound to both pay results/projections;
3. R1 and R2 Original-only pay selections/results and their exact input-history
   prefixes;
4. for each round, a pre-private-intake
   `kpb-owner-intake-financial-binding/v1` joining trial, round, lifecycle
   operation, current head and owner-contract identity;
5. the directly qualified public core/proof/projection/journal record;
6. a direct registered-driver selection/result binding exact source, build,
   configuration, all-three party agreement, durable EGRESS, owner contracts,
   accepted head and history; a Boolean release JSON is rejected;
7. exact selected offline-final source, request/result/replay, opened R0 receipt,
   whole CASE and recomputed native witness/candidate identities for both rounds;
8. a direct ordered service-loss producer whose receipt is bound into every
   later Exit selection; a zero-count JSON is rejected;
9. nine successive Original-only Exit preparations and explicit releases,
   three per owner, each against its exact current history;
10. the terminal three-Original scan selection/result and zero-reserve history.
11. a terminal privacy capture binding the exact nine Exit CASE/results,
    service-loss evidence and terminal scans into the candidate graph.

Received/change roles remain private. R2 is bound by the frozen wallet source,
trial, operation and history: owner1 selects recovered change; owners0/2 select
recovered received notes. The bridge never exports those roles or reads/hashes
an owner body.

The gate also replays the actual first Payment and first Exit against their new
states and requires both stale replays to refuse. It then reexecutes NativeFull
for GEN3, both Payments and all nine Exits, checks actual Exit proofs in the
witnesses, replays complete integer-sompi reserve/fee state to zero, and checks
all three terminal Original scans.

## Current hard stops

- The current privacy v2 contract is not release-bound and can be satisfied by
  administrative/source assertions. The bridge recomputes the available
  evidence but then deliberately refuses it. A separate terminal capture is
  also required because the owner-labelled Exit route can undo payment privacy.
- Registered driver source/build controls now pass, including default refusal,
  but no exact configuration has been selected and run, and no verified
  registered result exists. `REGISTERED-DRIVER-REQUIREMENTS.json` records the
  producer contract; the bridge unconditionally refuses standalone
  registered-release booleans.
- No ordered service-loss producer exists and current Exit selections do not
  bind a service-loss barrier. The bridge unconditionally refuses zero-count
  service-loss JSON.

- `qualify_public_release.py` produces the exact
  `kpb-qualified-public-financial-artifacts/v1` lower-level record, but the
  current Source05 run is fixed Round1 synthetic/unregistered evidence. It has
  no Original lifecycle/owner-contract join and cannot satisfy the registered
  release requirement.
- Round2 needs a generalized launcher bound to the actual R1 CASE head and fresh
  R2 owner inputs. Reusing the fixed Round1 point/state/paths is rejected.
- `private-batch-public/outer-selection.json` is still `selected:false`. R0 must
  refuse until Root selects exact source/image/parameters. The bridge also
  requires direct selected-host reexecution of `native-proof` over the retained
  receipt and journal; mirrored FINAL/REPLAY JSON and a nonempty receipt cannot
  satisfy it.
- No current controller constructs the Payment/Exit CASEs and canonical history
  from these exact records, and no current controller emits the service-loss
  receipt. Those are execution-driver gaps, not fields that may be filled with a
  caller PASS Boolean. Until all hard stops are implemented, no v2 manifest can
  be assembled and activation cannot cross its offline gate.

Therefore the present partial proof result cannot be relabelled as a complete
rehearsal, privacy pass, accepted backing, native settlement or Testnet
readiness.
