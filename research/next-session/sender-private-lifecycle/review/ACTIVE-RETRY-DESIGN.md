# Active abort/retry privacy: design follow-up

**2026-10-25 UTC. Source/design analysis; no protocol execution or actual owner
map constructed.** Baseline `2e56d8a10fde5c998dde3bac3c7070c9d36f6827`;
[ADR-0065](../../../../docs/adr/0065-sender-private-admission.md) remains the
selected bounded prototype. This note proposes no new cryptographic primitive
or financial-rule change.

## Finding

No inspected mitigation is a drop-in solution preserving all of: known-member
coordinator admission, arbitrary changing cohorts, stable nullifiers, current
owner-local proof generation, and seed-only recovery without unpublished
attempt history. This is a limited design finding, not an impossibility result.
Removing the direct READY/proof-slot disclosure remains useful, but does not
qualify active-coordinator anonymity across retries.

**Verified local facts.** The current owner validates the complete projection,
finds its NF/CV, and only then proves a Spend statement over its effects digest
([worker authorization](../../../../poc/owner-private-lifecycle/wallet/worker.py),
lines 275–346). The digest covers the native prefix and complete body core
([wire](../../../../poc/owner-private-lifecycle/verification/wire.py), lines
219–221). Restoring the original seed deliberately imports no attempt journals;
stable nullifiers survive restoration
([wallet API](../../../../poc/owner-private-lifecycle/wallet/API.md), lines
52–54 and 127–129). An aborted attempt does not consume its note on chain.

**Established-design boundary.** WabiSabi separates registration roles and
network identities, uses signing/blame to discourage disruption, and explicitly
leaves targeted denial/intersection mitigation to transaction structure. Its
optional encrypted unsigned transaction restricts early disclosure to round
participants, rather than excluding a colluding participant.
[Pinned protocol](https://github.com/WalletWasabi/WabiSabi/blob/1e6deb989f58bc6edce91bc300252d2bed18db30/protocol.md#attacks-on-privacy),
also sections Round Structure, EncryptedUnsignedCoinJoin and Network Identity
State Diagram. The inspected head was resolved through GitHub on 2026-10-25.

## Candidate comparison

The assessments below are design inferences from those facts, not implemented
or measured guarantees.

| Candidate | What it addresses | Remaining requirement or cost |
| --- | --- | --- |
| Delay NF release until joint authorization | Reduces the interval between disclosure and a usable transaction. | Current local provers need the final effects before proving. Giving that body privately to all owners still gives a colluding owner the NF set. Proving over a hidden body jointly would be a substantive construction change. Even a complete transaction can lose a race to another valid reserve transition; recovery after that event still needs analysis. |
| Durable encrypted attempt log | Could restore a previous cohort/retry restriction after seed recovery. | Needs authenticated, complete, non-rollback retrieval before another disclosure; a content hash alone cannot establish that no newer entry was withheld. Encryption does not erase already observed sets. Upload identifiers, timing and membership can introduce linkage. Enforcing a cohort restriction additionally trades private-payment liveness for privacy. |
| Deterministic fixed cohort | Avoids the particular intersection caused by changing a note's known participant set. | The rule must be reconstructible from the original seed plus authenticated public data and checked before disclosure. A whole-pool fixed cohort is simpler to recover, but constrains membership and requires the same peers for private payments. An unavailable peer must leave unilateral exit possible. A local saved roster lock is insufficient after restoration. |
| Anonymous membership and isolated network identities | Could remove the coordinator's knowledge that the same owner appears in overlapping cohorts. | Fresh aliases alone are insufficient. Real transport, invoice/admission and retry unlinkability need explicit assumptions and testing. Sybil selection, colluder knowledge, amounts and timing remain. This changes the observer assumptions and operational architecture; it is not supplied by the shuffle. |

For the last candidate, Tor's own documentation excludes an observer capable of
correlating traffic at both ends and warns that circuit reuse can associate
connections. Therefore anonymous transport would require a declared adversary
and identity-isolation policy, not a blanket network-privacy claim.
[Tor limitations](https://support.torproject.org/about-tor/security/attacks-on-onion-routing/).

## Smallest decisive negative experiment

Use fresh synthetic owners and genuine admission MPC, without funding:

1. Run a round with known members A, B, C. Open the shuffled NF set, then abort
   before financial settlement. B is the permitted colluder.
2. Retry the same unspent A and B notes with members A, B, D. C and D are distinct
   honest owners. Preserve the actual public/coordinator transcripts.
3. Seal the observer's prediction from the two sets and B's disclosed own NF.
   The intersection minus B's NF contains A's NF. Each round separately has two
   honest owners. An isolated evaluator checks the prediction; export aggregate
   results, not an owner map.

Use NF alone for intersection: CV blinding may legitimately change on retry.
The expected outcome is an **active-intersection privacy failure**, even if
each individual shuffle succeeds. This is a proposed experiment; its actual
execution belongs in the frozen attack study. Repeat with original-seed
restoration between attempts to test any proposed journal-based remedy.

## Recommendation

Retain this failure alongside any passive-observer improvement. Before choosing
an active-retry remedy, require a reviewed lifecycle specifying who sees stable
identifiers before settlement, how a restored wallet discovers every relevant
prior disclosure, and what it does when the original cohort or public log is
unavailable. Preserve exact-effects authorization, backing, single-spend checks
and unilateral exits. Loss of a dependency may halt private payment; it must not
authorize theft or strand the independent exit path.
