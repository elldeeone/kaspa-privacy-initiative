# Three-owner constructor privacy observation

Date: 2026-11-01

Status: **the existing ADR-0065 construction hid the direct owner map from its
declared coordinator in one fresh three-owner run. The newer ADR-0074 offline
W1 constructor remains leaking and is not repaired by this result.**

## Attack tested

The named attack is the owner-labelled ingress/order-to-effects join:

```text
owner -> input NF/CV -> that owner's two created output tuples -> Spend proof
```

Success for the attacker means one exact complete map. This is not a generic
anonymity score.

## First plaintext leak in the retained W1 path

The leak precedes every retained map file:

1. `offline_w1_components.py:448-461` holds the logical owner and plaintext
   input while creating that owner's two plaintext outputs in the same stack
   frame.
2. Lines 484-504 serialize a map already known to that process.
3. Lines 726-739 read all three owner records and derive the joint ordering.

Deleting `joint-ordering.json`, `w0-selection.json`, or owner records cannot
provide constructor privacy.

## Smallest executable change

No safe shuffle-only patch exists for ADR-0074. Its restricted intent binds an
NF to two exact outputs, so that correspondence must be checked inside the
secret-shared aggregate relation.

The smallest bounded executable construction was the already implemented
ADR-0065 path:

1. Each owner privately supplied `NF32 || CV64 || 2 x Output520 || beta` to its
   own MPC party.
2. MASCOT independently sorted three input rows and six complete output rows,
   then opened only the two mixed lists and aggregate delta.
3. Each owner checked the exact mixed effects, its two outputs, its current note,
   integer conservation, all Output proofs, and global balance.
4. Each owner privately supplied `NF32 || CV64 || SpendProof128`.
5. A fresh independent MASCOT sort opened three unlabelled authorization rows.
6. The public finalizer enforced the exact NF/CV bijection and verified all
   three Spend and six Output proofs.

The fresh run used equal 250,000,000-sompi payments to avoid amount tagging. It
performed no funding, broadcast, Testnet action, outer proof generation, or
chain acceptance.

## Actual comparison

| Observer | Complete map candidates | Exact honest map recovered |
|---|---:|---:|
| Retained offline-W1 construction root | 1 | yes |
| ADR-0065 public/coordinator | 540 | no |
| ADR-0065 coordinator + owner 0 | 6 | no |

The coordinator's 540 structural candidates are `3!` owner-to-input bijections
times 90 owner-labelled partitions of six outputs into three unordered pairs.

Owner 0 legitimately knew its own NF/CV, its two created outputs, private delta,
Spend proof, full one-party MPC state, and decrypted receipts. In this run it
decrypted its change plus one incoming payment and learned that incoming
sender's slot. That left two honest input assignments times three honest output
pair assignments: six complete maps.

The one-party MPC transcript is covered by the selected one-corrupt-party
MASCOT privacy assumption. The scorer does not claim to prove that assumption.

## Actual process observations

Public protocol data contained:

- three roster aliases;
- three mixed NF/CV rows;
- six mixed complete output rows;
- three mixed NF/CV/Spend-proof rows;
- six neutral owner readiness messages;
- zero explicit owner-to-mixed-row links in the validated schemas.

Coordinator observations were from the live isolated processes, not a filtered
copy of the leaking W1 bundle:

- admission: 22,742-byte coordinator IPC, 7,156-byte mixed result, 80,228 ms;
- authorization: 6,249-byte coordinator IPC, 1,657-byte mixed result, 17,478 ms;
- each phase received three identical public party projections;
- coordinator saw only `lo`, no owner paths, host home, Docker socket, private
  invocation handle, or execution API;
- host controller recorded zero owner-input reads;
- public builder/finalizer each reported public stdin only and no owner-labelled
  inputs or proofs.

The complete owner-0 colluder view comprised 44 regular files, six local
certificate symlinks, and 2,718,305 regular-file bytes. Its manifest digest is
recorded without publishing any private wallet material.

## Authorization and conservation evidence

The completed run recorded:

- three verified Spend proofs;
- six verified Output proofs;
- exact NF/CV-to-authorization bijection;
- independent Arkworks pairing reference check;
- public state, native effects, and global commitment balance checks;
- successful genuine CPU guest execution.

Passing these checks is implementation evidence, not a cryptographic audit or
production-security proof.

## Why this is not filtered-artifact privacy

The coordinator never received the owner-labelled map. Each owner process wrote
only its fixed-size private MPC streams, each MPC party alone opened its stream,
and the coordinator consumed only the common mixed projections. The trusted
post-run scorer consulted all three owner truths only after the observations
existed and emitted counts/hashes rather than the map.

The machine-readable observation is
[`THREE-OWNER-CONSTRUCTOR-PRIVACY-OBSERVATION-2026-11-01.json`](THREE-OWNER-CONSTRUCTOR-PRIVACY-OBSERVATION-2026-11-01.json).
The runtime observation SHA-256 is
`99a9b50b7a819822b6b2b4386bda315bb62f1e61b1faf2193d5e82302cba03b4`.

Key fresh-run identities:

- world: `8d631be24c0aabc821f345cb925f85264dd20651212ee2867e63d2e0947668e9`;
- admission: `470a160bf539c17bed8f7aee7031447a44923cb511a7b0d944650db9d4f33c6c`;
- authorization: `ce33c28383ef539a1b0bf2a87a7676725f90cd2a2ee2a3d8df3490c29cb58d6b`;
- final projection: `22fd3b7d177bc786ebdc6d5c99337c8bda298b47d3baa1a52f40839c7755a9fb`.

## Current ADR-0074 gap and viability

This execution does not make the leaking offline W1 path private.
`registered_service_selection.hpp:8` remains `CONFIGURED 0`, and
`registered_gate_main.cpp:22-40` still requires the absent selected registered
driver.

The exact missing protocol seam is the proposed single-use
`SelectedRelationAdmissionAuthority` in
`REGISTERED-RELATION-ADMISSION-BLOCKER.md:98-115`. It must bind the live selected
relation, exact matrices/mapping/layout, owner columns, session/context, and
failure epoch before any owner listener accepts input. A digest, receipt,
allowlist, or post-run filter cannot replace it.

The design remains viable: ADR-0065 demonstrates that owner-local construction,
two independent malicious-secure shuffles, post-mix owner authorization, strict
NF/CV matching, and aggregate verification can hide this direct map. Porting
that property to ADR-0074 is a separate registered-relation integration task,
not part of this bounded comparison.

## Limits kept explicit

- The host administrator remains trusted and can read all three local owner
  processes.
- Two colluding wallets identify the third by elimination.
- Active changed-cohort retries can intersect stable nullifiers.
- Endpoint and timing anonymity were not measured.
- Broader server-state capture and Testnet work remain deferred.
