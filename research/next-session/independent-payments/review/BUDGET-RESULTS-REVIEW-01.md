# Selected native budget evidence review

Reviewed the actual public adapter, `budget_controls.py` source
`d19f403b266378e9c4767ae5c6b9661787abbcfcd6a154a97eca6a282e2e5599`
and `fees/budget-controls-02/RESULTS.json`. ACK for the stated bounded supplied-
context interoperability result.

The same three fixed public genuine proofs pass Native Full at B1600 and B1500.
Auth, proof and transaction ID remain byte-identical; only budget and derived
mass change. B1475 rejects all three with the precise precompile-wrapped
committed-script-budget error. The source matches that exact typed wrapper and
used/limit equation, rather than accepting any failure. The first assertion used
the wrong Debug/Display representation; its retained diagnostic and final
campaign give13 total actual calls, nine in the completed campaign.

B1500 has observed slack40,360..168,270 script units for these fixtures. At
reference rate100 it reduces each fixture's required fee by1,000,000 sompi
(0.01KAS). All actual fixture fees remain deliberately underpaid1,000 sompi.
This is neither a uniform worst-case1500 budget proof, a repriced complete
lifecycle nor relay/chain acceptance. A claimed per-payment improvement still
needs actual matched bodies, complete entry/distribution/exit costs and an
independent private fallback. It does not remove the existing two-verifier
floor or solve public output grouping.
