# Finite common-set withdrawal experiment selection

Date: 5 November 2026 (Australia/Sydney). Base: `9dd72bbb`.
Authority: owner instruction to investigate the replacement and build the smallest
offline test if feasible; [ADR-0107](../../docs/adr/0107-finite-common-set-withdrawal-diagnostic.md).

## Named hypothesis

With three known eligible input owners and equal-denomination outputs, real
blind registration plus common-output-set owner authorization removes the
explicit owner-to-recipient assignment from the declared application and native
transcripts. Native safety and immediate solo withdrawal must remain intact.

This tests a new finite authorization path. It does not delete the predecessor's
public EXIT records and does not implement a shielded ledger, private-note
membership/nullifiers or a complete payment lifecycle.

## Workload, truth and observations

Generate three fresh synthetic claimant secrets and three fresh native recipient
keys only after this selection is written. Keep secrets, blind factors, setup
keys and the owner's private randomizers inside ephemeral runtime storage or
memory; publish no wallet/proving secrets. Keep the hidden owner-to-output
mapping separate from coordinator objects and inference until observations are
sealed. Matching positive/negative views reuse the same public output keys.

The coordinator sees identified issuance owner/claim/blinded message/eligibility
authorization and response; anonymous redemption supplies only canonical output
message, final credential and message randomizer. Native observation includes
the full redeem/signature scripts, known active claim identifiers, actual output
scripts/values and whole-set authorizations. All program-generated public data
belongs to the observation. No IP/cookie/global-traffic privacy is inferred from
logical neutral connections.

The bounded observer treats the established blind-signature and Groth16
properties as assumptions. Enumerate actual owner-to-output-key bijections,
condition on explicitly observed identity links and amount constraints, and seal
predictions before consulting controller truth. Check complete truth retention
and relabeling invariance. Never report this enumerator as cryptanalytic testing,
posterior probability, real-user anonymity or a network measurement.

## Gates and stop rules

1. Source/design gate: current proof/output-inspection interfaces express the
   policy; an actual standard blind-registration implementation is available.
2. Native gate: genuine proofs verify, changed native effects reject, and both
   joint and independent solo branches run under the pinned native script engine.
   Report supplied-state/spentness checks independently. Do not treat VM predicate
   success as full node validation, funded state or actual chain acceptance.
3. Ownership gate: baseline identified registration uniquely maps all outputs;
   the complete candidate application/native view retains more than one correct
   ownership assignment, including with one participant's own legitimate output.
4. Required failure controls: all-but-one collusion and full external owner
   mappings collapse ambiguity; echoing owner/session metadata, issuance
   randomizers or old explicit requests must expose their corresponding links.
   Equal amounts alone must not overcome an explicit destination map. Unequal
   exact amounts remain identifying; unsupported amounts reject the equal-value
   implementation rather than being rounded or compared as floats.
5. Safety: reject invalid ownership/proof/encoding, modified effects, duplicate
   payout keys, stolen/duplicated authorizations, wrong domain/current state/
   outpoint, incorrect principal/fees/successors and replay. Server loss leaves
   solo exits executable. Preserve negative native errors, not generic failures.

Stop and report the exact blocking layer on a gate failure. Fix ordinary
implementation errors, but do not change the observer, target or cryptographic
assumptions to turn a privacy failure into a pass. No consensus changes, funded
trials, broadcasts, real funds, mainnet action, provider work or paused MPC runs.
No success here relaxes old known-owner/full-drainage or absolute qualification
requirements. Fee numbers are synthetic resource/accounting evidence only.
