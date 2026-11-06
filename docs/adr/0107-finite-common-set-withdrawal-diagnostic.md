# ADR-0107: Test finite common-set withdrawals without consensus changes

**Status:** Accepted for the owner-authorized offline experiment only.
**Date:** 5 November 2026 (Australia/Sydney).

## Decision

Implement the finite three-claim diagnostic in [RFC-0005](../rfc/0005-common-set-withdrawals.md)
to test two concrete missing seams: actual unlinkable registration messages and
current-L1 authorization of an entire payout set. Preserve the failed public-EXIT
wrapper unchanged. The owner explicitly authorized this replacement investigation
after its predecessor was committed at `9dd72bbb`.

Use an existing RFC9474 library for offchain registration and the existing
Groth16/native output-inspection interfaces for spending. All current input-claim
owners may be known: the specific question is which real output belongs to each.
Use one common proof relation and finite public-claim subset policies, including
independent solo exits. Introduce no operator spending authority, new asset,
consensus feature or requirement that a user wait for a cohort to exit.

## Alternatives and scope

- Reusing individually public destination authorizations fails the previous gate.
- An ideal anonymous-registration oracle would evade the question; exercise real
  blind/unblind/sign/verify messages and retain linkable negative controls.
- A terminal all-owner-only contract would make cooperation mandatory. The same
  reserve must also support each owner's independently authorized solo exit.
- A new general private ledger/runtime is unnecessary to answer this bounded
  question. Public finite claim identifiers isolate payout ownership, leaving
  private-note integration and general scaling unresolved.

## Security and interpretation

Keep SECURITY-INVARIANTS.md unchanged. Prove exact actual effects; enforce reserve
principal, explicit fees, active claims and successors in native script. No host
verdict, blind credential or coordinator key may spend. Experimental single-party
setup, synthetic supplied UTXOs, same-host clients, cryptographic assumptions and
unmeasured network observation must remain explicit.

A passing test establishes only the executed layer. It cannot qualify full
payment privacy, accepted chain backing, independent administration/recovery or
cost targets. Known payout owners and all-but-one collusion may remove every
ownership alternative. Reconsider the design if actual native limits, a public
binding, or a coordinator transcript exposes the assignment; preserve failures
without hiding information or expanding the experiment into another framework.
