# ADR-0096: Feasibility-aware Observer v4 acceptance

Date: 2026-10-29 UTC.

Status: Accepted source architecture, implementation incomplete. Observer v3
remains immutable, explicitly open and non-authorizing. No v4 output worker,
selected authority join, fresh-trial ledger, prediction permit, privacy pass or
network activation exists; all selection and configuration flags remain false.

## Problem

Observer v3 faithfully records the frozen open Step-2 inventory, but an open
inventory cannot become privacy acceptance merely because a child emits new
booleans, counts or digests. The current research ledger also distinguishes
cryptographic claims that superficially share literals but have different
statements and assumptions. In particular:

- six per-round Output proofs are not the two aggregate proofs;
- ciphertext confidentiality and hidden delivery-key labels are separate;
- delivery-key and nullifier derivation share one owner seed and need one
  joint multi-domain HMAC game;
- the narrow MPC realization hypothesis does not absorb aggregate Groth16;
- arithmetic rewiring is not feasibility until the exact Full-W1 relation and
  its actual runtime Close descendants come from one live source instance; and
- the successful final trial alone cannot erase privacy-relevant failed fresh
  trials, aborts or partial tails.

Accepting serialized evidence would recreate a caller-authored PASS surface.
Accepting independently reconstructed authorities because their public
identities match would allow a valid W0, C1, proof or Close from different
instances to be spliced together.

## Decision

1. Observer v3 is frozen and remains non-authorizing. V4 is a new role ABI and
   parser; it does not reinterpret any of v3's 26 generic family rows as the
   assumption families below. Its fixed binary rows are evidence formatting,
   never authority. The initial registry marks every row
   `MISSING_LIVE_AUTHORITY`; historical or local S4/S12 provenance is
   assumptions-ineligible.
2. The v4 child may write a canonical body only after consuming private typed
   inputs. The parent independently parses the exact fixed-size body and
   retains the authenticated sealed output. No caller JSON, Boolean, summary,
   digest, same-literal shortcut or child-chosen opaque identity can close a
   row.
3. `S4_OUTPUT_GROTH16` is a distinct applicability authority for the joint 12
   Output proofs: exact statement
   `domain || CM || CV || SHA256(ciphertext)`, frozen source/matrix/PK/VK,
   canonical subgroup encoding, honest circuit-specific CRS with unavailable
   toxic waste, frozen auxiliary view, and 12 fresh independent randomizers.
   It does not establish encryption correctness or hide direct bytes, hashes,
   positions, timing or failures.
4. `S12_AGGREGATE_GROTH16` is a separate applicability authority for exactly
   two Appendix-E `(A,B2,C)` proofs with no raw `B1`, exact source/matrix/key/
   verifier identities, fresh authenticated `r,s`, exact public statements,
   frozen auxiliary view and its `S8+S10+S11` prerequisites. S4 cannot
   substitute for S12. The nonauthorizing provenance row separately binds the
   historical setup source, current source, exact current-to-historical matrix
   equivalence receipt, matrix, canonical and compressed proving keys,
   verification key, and independent verifier. Matrix equivalence does not
   make the local setup eligible.
5. `S5_CRYPTOBOX_CONFIDENTIALITY` and
   `S6A_V3_HIDDEN_DELIVERY_PRF` must both be live and must be consumed by one
   conjunction authority. S5 covers honest 264-byte receipt confidentiality
   and outsider integrity under its exact X25519/SalsaBox/BLAKE2b construction.
   S6A covers only hidden-owner label replacement for source-owned one-use,
   abort-poisoned delivery indices whose identifiers are absent from the exact
   P1+C1+public view. Neither authority implies the other.
6. S6A and `S7_NF_HMAC_PRF` additionally join in one multi-output,
   multi-user HMAC-SHA256 authority over the exact disjoint `DELIVERY`,
   `NULKEY01`, `KPX1NF` and `KPX1KEY` domains. It binds the same genuine owner
   seed source, entropy/nonexposure, distinct owner seeds, unique indices,
   exact Rust/Python/circuit messages and forbidden-view absence. Two
   independently asserted PRF labels are insufficient.
7. `S14_KPB_MPC_JOINT_REALIZATION` is deliberately narrow: it covers the exact
   frozen DDNNT/MASCOT/AuthG1/AuthG2/mixed implementation against static active
   P1 plus passive C1, with declared leakage and abort. It explicitly excludes
   aggregate Groth16. Acceptance therefore consumes a separate live S12
   authority and an S14+S12 conjunction. S14 may subsume S12 only after a new
   reviewed statement explicitly imports every exact S12 CRS, auxiliary-view,
   randomizer and joint-proof-distribution condition.
8. Counterfactual feasibility is one opaque move-only authority. Its sole
   source instance atomically owns the selected W0 truth, complete C1
   operation/contact/attempt/value/ciphertext/decryption residual, accepted
   public/effects lineage, exact W1 alternative, full relation witness, and
   actual projection/dispatcher/terminal/archive Close descendants. The
   arithmetic shape, Rust Full-W1 closure and Close closure are burned
   together. Equal ids or separately reconstructed inputs cannot mint it.
9. A distinct outer fresh-trial-ledger authority owns every attempted trial in
   order, including parser refusal, abort, partial tail, crash and the final
   complete trial. A failure invalidates that whole trial. Any retry uses a
   fresh trial identity and repeats R1+R2; there is no same-trial R2-only retry
   and no fixed retry-count cap. V4 consumes the exact ledger plus the direct
   empirical result derived from its sealed histories.
10. A source/runtime-freshness authority binds the exact selected worker,
    source, build, runtime, assets, executable, launcher, finite assumption
    registry and byte grammar actually consumed. A manifest digest, current
    path or matching version string is not sufficient.
11. The native v4 acceptance bridge move-claims every supplied capability
    before validation. It exact-matches the private `RunBinding` and source
    instance, retains the one sealed output inode, and returns one opaque
    non-splittable acceptance authority. Only that live authority may later
    authorize the salted barrier and three independent FD41 endpoints. Open or
    missing rows, replay, cross-binding, mixed source instances, dropped failed
    trials, stale runtime or a body/authority mismatch burns the whole join.

## Rejected alternatives

- **Flip v3's open dispositions.** V3 has no source-owned S-family registry and
  was frozen as open-only evidence.
- **Treat equal hashes or literal fields as the same authority.** Equality
  does not prove common origin, one-use possession or source-instance
  continuity.
- **Let S4 stand in for S12.** They prove different statements with different
  proof counts, keys, randomizers and prerequisites.
- **Use separate S6A and S7 PRF assumptions.** Both query the same owner seed;
  the required claim is their joint multi-domain distribution.
- **Let narrow S14 absorb S12.** The narrow hypothesis expressly excludes the
  aggregate proof distribution.
- **Accept only the final successful trial.** Abort/retry/partial history is an
  observer feature and dropping it changes the experiment.

## Security and privacy consequences

This design prevents a serialized PASS, child-selected nonce, assumption label
or matching digest from authorizing privacy. It also makes the strongest
remaining trust explicit: the selected source must genuinely mint all family,
feasibility, attempt-ledger and freshness authorities from the same live
experiment. Missing authorities safely halt. This can reduce liveness and does
not prove the cryptographic assumptions, the model's completeness or general
anonymity.

## Evidence and remaining gate

The fixed nonauthorizing byte grammar is implemented in
`privacy_measurement_output_abi_v4.{py,hpp,cpp}`. It preserves the entire
151,552-byte v3 body as an immutable prefix, adds a 640-byte v4 requirement
section, and pads the exact body to 155,648 bytes. The registry identity is
mechanically derived from the canonical per-family requirements and pinned
historical provenance; the exact section also binds the v4 descriptor
identity. Cross-language controls mutate every section byte and keep all live
join, selection and configuration status bits false.

The family statements are frozen in
`research/combined-p1-c1-public-finite-assumption-ledger-2026-10-29.md` at
SHA-256 `ca2328efdc5b4508f57cb37b4d223e520f476dd747720bd2c2691f02ca930162`.
S6A, S7, joint S6A+S7, narrow S14, Full-W1/Close, fresh-trial history and
source/runtime freshness have no frozen source-owned applicability identities;
the registry records those identities as missing rather than deriving them
from labels, file hashes or matching literals. S4/S12 pins record provenance
only and remain ineligible.

The existing counterfactual source now separates arithmetic shape, exact
Full-W1 relation and runtime Close and exposes only an opaque linear transfer
to the future v4 bridge. The direct empirical result is also opaque and
one-shot. Production minters for the family conjunction, full fresh-trial
ledger, source/runtime freshness and selected v4 worker do not yet exist.
Those absences are hard blockers, not values a fixture or receipt may fill.

## Reconsideration

Revisit the split only if a reviewed primary-source statement proves one
family strictly contains another under the exact selected implementation and
auxiliary view. Any replacement must preserve the atomic same-instance join,
all-fresh-trial history, source/runtime freshness and the ban on serialized
authorization.
