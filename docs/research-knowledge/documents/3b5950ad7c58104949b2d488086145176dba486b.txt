# Integrated owner-private native KAS lifecycle: selected interfaces

2026-10-24. Root selection under the owner's instruction to execute steps 1,
2, 3 and 5. Research and TN10 only. This is not a privacy qualification.
The ADR0063 unfunded profile, previous funded profiles and their private assets
remain unchanged. ADR0064 records the coherent new construction.

## Identity and component roles

- Domain is SHA256 of the ASCII bytes, without newline:
  `KPX8 owner-private native KAS lifecycle v1 / TN10 RESEARCH ONLY`.
- Domain hex: `be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480`.
- Tags: Spend `KPX8SP01`, Output `KPX8OU01`, Exit `KPX8EX01`,
  state `KPX8ST01`, batch/body `KPX8PB01`, effects `KPX8EF01`,
  journal `KPX8JR01`, founding `KPX8GN01`, native projection `KPX8FX01`.
- New code: `poc/owner-private-lifecycle/{relation,verification,wallet,
  integration,bootstrap,chain,recovery}`. Selected original code is not edited.
- Fresh Spend, Output and Exit keys/manifests are selected by the component
  profile, which excludes the later guest image/native tail to avoid a cycle.
  The guest image and Exit VK are pinned by the final native policy/profile.

## Financial modes

GN3 adapts the existing reviewed founding: three actual ordinary funding inputs,
three authenticated initial Note168/CM/CF records, full native backing, initial
CM count 3 and indexed NF count 1. All three ordinary owners authorize the exact
complete transaction. Fees split `[F//3,F//3,F-2*(F//3)]` in integer sompi.
The 1576-byte public frame is tag8/profile32/domain32/trial16/three496-byte rows.

Mixed mode retains three genuine spends and six complete mixed outputs, with
the existing stock malicious MPC engine. Input note CM/position remain private.
Spend200 and Output168 have their previous shapes with the new fixed tags and
domain. Public global conservation and current CM/NF updates are mandatory.

Exit mode is one full-note withdrawal, without new private outputs or MPC or
shared outer proving. Exit152 is `tag8|domain32|CMroot32|NF32|effects32|payout8|
fee8`. The circuit proves hidden current membership/ownership, the stable
positioned NF, bounded note value and exact integer `value=payout+fee`.
The native policy itself verifies the indexed NF insertion and exact full
prior/successor state, current reserve point, payout destination, payout/fee and
remaining reserve. It checks the genuine Exit proof against its pinned VK.
The immutable CM root/count stay unchanged at exit. Positive remaining reserve
has a same-policy successor; terminal zero has no continuing reserve. State,
financial effects and the exact native output layout are authenticated, never
accepted from a host verdict. Native author must confirm the canonical payout
SPK encoding/width and publish the final offsets before dependent callers.

## Owner and history boundaries

Seed-only immutable backups contain domain/participant and seed, never a saved
ownership map. Initial and later ciphertexts plus the complete authenticated
accepted CM/NF history are sufficient inputs to owner-local recovery. Invoice
indices are fresh per session/role and recoverable from encrypted receipts.
Public READY contains participant/session/NF/CVin, not recovered note CM or
position. Native effects and complete payment inclusion are checked before
durable authorization; an old authorized body may still settle after timeout.

## Runtime and resource coordination

Root reserves `/var/tmp/kpi-owner-private-lifecycle-01/private` as a whole private
parent BEFORE any new secret generation. All wallets/MPC inputs/controller plans
must live there unless an additional whole private parent is declared first.
Public artifacts go under the sibling `public`, and public build/setup assets
under the sibling `assets`. Supervisors inspect private metadata only; original
backup/seed/map/capsule contents or hashes never cross owner-local boundaries.
No funding or broadcast until the complete genuine local path has passed.

Host has 14 available CPU cores, about 21 GiB available RAM, RTX3070/8GiB.
Coordinate costly jobs: at most one GPU proof, one major relation setup and
one major Rust build at a time; independent lightweight work remains parallel.
Use at most four Cargo build jobs per independent lane until notified. Root
coordinates the proof queue and resource observations.

## Completion boundary

Success requires successive genuine mixed rounds, backup recovery/spending of
payments and change, independent one-note exits after original coordinator and
shared prover loss, actual confirmed TN10 payouts, and a complete integer fee
ledger/zero final user liabilities. Fee target remains a separate verdict.
Separately administered storage requires a real separate administrator and
retrieval; connected Drive/same-admin GitHub do not establish this property.
Step 4's expanded privacy experiment is outside this requested execution batch;
normal financial correctness checks and required second-pass review remain.
