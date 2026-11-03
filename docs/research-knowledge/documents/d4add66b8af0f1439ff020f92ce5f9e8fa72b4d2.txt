# Activation operator review

2026-10-25 UTC. Static source review; no network, mining, funding, original
backup content access or broadcast performed by this reviewer.

No financial authorization blocker found in the reviewed operator/roundtrip
changes. GO for the reviewed source behavior; the exact final activation closure
must match the root-selected release before execution.

Reviewed operator `bootstrap/activate.py` at
`8e90155c557963f0fed6d0d050916723152c0541a03d8b49f394b07211399a60`
authenticates the pinned profile, trial, funding identity, source closure,
parameters and wallet assets before its execute gate. It then records a birth
anchor, runs three sequential two-worker TN10 miners, waits using read-only
coinbase maturity queries, performs own-only consolidations and readbacks,
obtains all three genuine GEN3 owner approvals, requires actual Full, submits
once and confirms the actual accepted GEN3 whole CASE. It stops before private
payments/exits and keeps ordinary preparation fees separate from GEN3 fees.

`chain/roundtrip.mjs` at
`fb7624a9b5b4c928279123c31425bde6f263ec7d68098e55ff04e4273bdacf56`
uses the existing SDK transaction constructor for arbitrary input counts,
preserves populated contexts and canonical whole transactions, and performs no
RPC/signing. This fixes the previous GEN3-only roundtrip assumption for ordinary
one-input consolidations.

The reviewed preflight and submission paths require actual Full/all inputs,
exact normalized ID/storage mass, exact 100-times-mass fee, lossless SDK
roundtrip and two exact live input queries around durable stage/global-ID
reservations. The only submit RPC is followed by acknowledged-or-unknown
query-only handling; the activation loops do not automatically rebroadcast.
Miners also reserve trial/party attempts and individual block intents. All SDK
network access uses the explicit Tor bridge and testnet identity checks.

A non-blocking liveness observation was sent to the author: the operator's
hardcoded first-trial label would require a source edit for a different fresh
label. Exact trial SHA, canonical label, private-prefix checks and once-only
registries can support a fresh-label retry without weakening financial checks.

This review is not confirmed GEN3 funding, canonical consensus independence or
terminal payout readiness. The actual payout rehearsal remains required.
