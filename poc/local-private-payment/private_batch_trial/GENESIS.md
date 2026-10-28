# Explicit new-profile three-owner admission

`genesis.py` reuses the existing strict GEN3 funding predicates with an explicit
new codec and the actual new Output verifier. It creates no signature, funding
transaction, accepted-history assertion or broadcast.

The new payload is exactly1648 bytes:

```text
KPBGN301 || actual component-manifest SHA25632 || D32 || fresh UUID16
         || initial Output520[3]
```

The selected component manifest binds the chain, prospective pool, ProfileID,
domain, service and three actual role keys. The explicit5-ID tuple must match
the existing aggregate setup; the old `KPXAGN01` payload is refused. The initial
state is `KPBAST01 || D || CMroot || count3 || sentinelNFroot || count1`.
The actual selected native policy tail determines its P2SH reserve output.

Each of the three genuine Output proofs must verify under the selected new
Output VK, and each public CV must equal independently evaluated
`Commit(2,000,000,000 sompi,0)`. The implementation calls the already-admitted
native `derive-output` operation on a deterministic **public dummy receipt**;
it adds no curve arithmetic or new primitive. The dummy receipt is never an
Original, deposit or funded claim. The first actual public control derived
CV `d1860d636fd3921caa9bba3535dff50187fef8e21ac6b429d4f7092dce6b311bfe7f3bc9e62c0c118080b164e13b6087ce8e487cd2bf8c8108261a623fabc914`
and matched all three genuine private-bootstrap initial Outputs. No Original or
Output proving key was read or mounted by that verifier control.

The CASE validator requires three distinct ordinary P2PK funding points/keys,
canonical ALL signature frames, exact60-KAS reserve, no foreign/duplicate or
reordered ordinary change, and each integer funding equation:

```text
input_i = 2,000,000,000 + own ordinary change_i + allocated entry fee_i
```

The first two fee shares are `total_fee // 3`; the third is the exact remainder.
An independently recomputed native quote, when supplied, must equal the actual
input-minus-output fee. Proposal budgets remain10; accepted-history shape allows
canonical actual u16 budgets and still requires real native execution. A signed
frame is not signature validity. Public validation cannot establish that an
encrypted note belongs to the owner of a funding key: each isolated Original
owner must separately reopen its own initial note, check its exact payload row
and designated funding key, approve the complete CASE/quote and generate its
actual ALL signature before any native rehearsal or funding.

Callable APIs support the already-isolated public settlement adapter:
`NamespaceGenesisVerifier`, `Selection.from_component(...)` and
`validate_case(...)`. They require admitted public bytes and a selected actual
verifier. They do not load the host guard or start nested namespaces. The host
CLI uses guard09 for its finite public admission. The returned admission record
always says native Full/SDK ID/accepted chain have **not** been verified; those
steps must independently bind this exact complete CASE and selected policy.

Eight focused public CASE tests pass, including contribution subsidy, reserve
inflation, wrong CV/proof/CF, duplicate CM/funding keys/points, changed trial or
profile, old tag, non-ALL framing, non-integer aliases, wrong budget/fee and wrong
native state policy. Their rows use explicit model proof bytes. The separate
actual known-value control verifies all three real initial Output proofs. Full
new-profile GEN3 signatures, NativeFull, acquired acceptance and withdrawal
rehearsal remain unexecuted by this module.

Actual public receipts and their preserved source copies are local at
`.local/private-batch-genesis-admission-20261028-01/`. The state derived from the
new private Original bootstrap is separate from the earlier known-seed
financial-prover fixture05. That fixture's initial notes have no claimed Output
admission proofs, so its successful future payment proof cannot establish a
genuine GEN3 deposit or accepted backing.
