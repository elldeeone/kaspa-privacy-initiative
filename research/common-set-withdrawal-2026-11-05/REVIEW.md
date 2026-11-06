# Adversarial review of the finite replacement

Scope: new finite offline experiment only, current pinned native engine and
declared application transcripts. AI-assisted source review is not an independent
human cryptographic audit. No production architecture or invariant amendment.

## Findings resolved before the final sealed run

1. Public native snapshots initially omitted compute-commit and output covenant
   metadata. They now include both; the observer rejects unknown fields and
   profile deviations instead of omitting them. Native policy fixes value-critical
   effects and absent output covenant bindings. Compute budget is a captured
   resource parameter; VM/resource success is not full transaction qualification.
2. Wallet entitlement checks originally surrounded only the first joint call.
   They now execute inside the authorization helper for every positive joint or
   solo proposal, immediately before proving. Missing/duplicated entitlement
   controls reject. Deliberately invalid proof controls bypass owner approval
   only to test native rejection.
3. A duplicate-set-insertion check overstated joint/solo conflict evidence. The
   replacement local UTXO map submits the actual joint/solo proposals, runs native
   authorization, consumes the real proposed predecessor, follows exact successor
   scripts/values and tests both conflict orders plus complete drainage.
4. The original identified control supplied a map directly from the controller.
   A separate identified-registration API now actually receives owner plus
   canonical plaintext output request and records that exposure. This remains a
   linkable control using the new native path, not an upstream lifecycle benchmark.
5. A raw eight-byte sequence introspection value was compared with minimal script
   zero. The correction compares the exact LE64 encoding and retains the same
   zero-sequence safety requirement. Failed native-positive attempts are retained.
6. A failed shell build initially fell through to an older executable. The runner
   now performs a checked build before freezing source/binary identity or creating
   a fresh runtime. No failed attempt supplied published privacy predictions.

## Safety and trust analysis

- **Minting/conservation:** native input amount, every payout and exact successor
  backing are pinned. Explicit fee allowances are separate from claim principal.
  Blind credentials have no native spending authority. Synthetic genesis/backing
  is supplied, not independently authenticated from an accepted deposit.
- **Double spend/replay:** each joint branch checks every active expected claim
  exactly once; solo removes exactly one and pins the corresponding successor.
  Proofs bind actual outpoint, current subset/domain/branch and full output list.
  Native negatives exercise wrong-claim reuse and stale contexts. Global UTXO
  spentness is executed only in the labelled local model, not a running node.
- **Unauthorized release:** every active claimant's secret-bound proof is needed
  for a joint spend. Every wallet checks its complete entitlement. An issuer can
  create extra coordination credentials, withhold service or omit outputs; it
  cannot produce the missing owner authorizations. Solo branches use the same
  backing and require no issuer or peer. Experimental toxic waste would defeat
  these assumptions; no generated policy may be funded.
- **Privacy:** identified issuance never receives output message, randomizer or
  blinding factor. A common issuer key/mode, canonical context and issuance
  barrier prevent the exercised direct tags. Actual redemption order is retained;
  keys are sorted independently. One-party knowledge, all-but-one elimination,
  leaked origin/randomizer and old public destinations are explicit observations.
  No code/test establishes RSA blindness, Groth16 zero knowledge, global network
  privacy, a real honest cohort or resistance to malicious timing/Sybil retries.
- **Dependency failure:** registration/prover loss can stop a joint round, while
  native solo authorizations remain executable from held secrets and public
  software/state. This does not establish independent recovery after loss of keys,
  all archives/proving parameters or all infrastructure.
- **Reorg/stale state:** wrong outpoints/subsets reject; accepted-chain ordering,
  DAG reorgs and rollback were not exercised. A valid supplied old UTXO is not proof
  it remains unspent on a real chain.
- **Interpretation:** input owners/claim IDs are public in this finite instance.
  The benefit is ambiguity over actual recipient keys. Output amounts remain
  public, externally mapped payouts still identify owners, and eventual ownership
  revelations can collapse ambiguity. Full private-payment privacy remains open.
- **Resources:** exact native metering/component mass fits three proofs but leaves
  little compute headroom. Four separate same-profile Groth16 checks already
  exceed the block compute limit before overhead. No general scaling claim.

Public-only replay verifies the real saved joint predicate, eligibility proofs
and final credentials in a new process. Changed recipient/context/message
negatives reject there without access to the private controller or setup key.
Received-output spending, full node validation, live funds, privacy qualification,
paid costs and independent specialist review remain outstanding.
