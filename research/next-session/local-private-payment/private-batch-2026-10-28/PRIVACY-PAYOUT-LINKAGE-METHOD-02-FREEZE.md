# Paired payout-address linkage method 02 — FROZEN

Status: FROZEN before actual candidate Original, payout-key, view or proof generation.
Scope: bounded UNFUNDED_SUPPLIED_CONTEXT native-component privacy experiment.
This is not reserve backing, accepted GEN3/history, chain settlement, deployment
readiness, cryptographic anonymity or the old global H1.

## Fixed comparison

There are three owners, one declared corrupt owner (component 1), and one exit
per owner per arm. The same owner set and SAME hidden receiver assignment apply
to both arms. Receiver choices remain inside owner-private plans; no public
cyclic/permutation schedule may substitute for them. Legitimate own contacts,
receipts and payouts are known in both arms. The old cyclic-workload/H1 failure
and old pair-tag CONTROL remain unchanged; the current format has no pair tag.

Main arm A uses independent genuine note instances at invoice index 7 and the
retained baseline wallet rule: payout SPK equals the invoice native_pk SPK.
Main arm B uses independent genuine note instances at invoice index 9 and the
fresh owner-secret-derived payout rule. The same Original may derive these
different indexes; copying an Original into a new trial must not reset a query.

Use existing Receiver.invoice and OutputProver.create, with distinct actual
receipts/rho/CM positions/NFs. No same-note alternative is a main paired arm.
Any same-note alternatives retained as crypto controls must report the
cross-arm same-NF lookup as EXPECTED FAIL. Public known-seed controls are not
private-wallet anonymity evidence.

Fixed note value is 200,000,000 integer sompi; fixed fee is 1 sompi. All three
selected exits have payout 199,999,999 sompi. Use a continuing-head component
shape: CM count 3, initial NF count 1, reserve 6,000,000,000 sompi, with the
selected common chain/pool/profile/domain/service. Context fields are common
across owners within each arm; changed CM/NF roots, actual outpoints and random
actions are retained as public facts, never erased. If the actual component
cannot meet this shape, stop as UNQUALIFIED rather than choose favorable amounts
or a different workload after observing results. No transaction is broadcast.

## Source and authorization binding

The cryptographic profile, Output VK and AuthExit VK are unchanged and selected
by .local/private-batch-public-native-final-parameters-01/PARAMETERS.json SHA
3f9f2f294c8203c8fc99ba66e1a78e769a1eecc4ecc5cf8f8b631eea28138751.
The baseline wallet source is
04a7f4da5d5b9a512e8e7e86fb29119961cef771ae1f532a77ce3840443816e5.
Fresh payout helper source is
886fed167f177fd1781bddf090ca2b5fd01dd2df7d10f5a664016f6aee46d456.
Public Exit codec source is
fabf7361f030e25ec4a52a72691fef4bcfe03f6fef369ff33b8fa55dd01ccb6a.

Fresh payout derivation uses the owner's secret, existing profile/domain
separation and exact old head Context276, spent NF and existing action. Canonical
wallet authorization independently re-derives the exact fresh SPK and rejects
the old invoice-native-key SPK. The owner AK signature MUST bind the whole exact
Exit. Mutating destination, amount, fee, action, context or domain after signing
must fail. No privileged redirection path or new proving setup is permitted.

Root/native/wallet must select the complete generator/verifier/observer source
manifest before private generation, using this immutable method SHA. That
selection supplies implementation hashes and fixed input/output paths; it may
not change this method, facts, arms, workload or criteria. Actual result/proof
digests are recorded AFTER execution; future results are not a freeze prerequisite.

## Complete declared views

CONTACT: actual legitimate contact invoice(s), the receipt/rho/value/CM the
sender constructed, own known receipts and actual own payouts, all public
amount/fee/cohort/timing/workload facts, and complete public native proof and
terminal projection bytes. No honest private plan/key or creator truth is given.
Invoice208 is not published as a global catalog: native_pk and domain-stable
delivery_pk are known recipient identifiers.

DISPATCHER: all actual observed argv, mounts, traffic and clear candidate/output
routes, including the existing owner-labelled exit_release path. It links owner
to fresh payout and MUST be included. No renamed field or redacted route counts
as a mitigation.

UNION: both views and the declared corrupt participant's legitimate knowledge.
Unmodeled full corrupt-server/terminal observations prevent overall qualification.
Until real common/anonymous native submission exists, dispatcher and union
linkage are expected to remain collapsed despite any CONTACT improvement.

The full native prefix and BODY1604 remain visible: context/outpoint/roots,
counts/reserve, action, new NF state, remaining, fee/payout, destination SPK,
spent NF and indexed-NF witness. Keep ordering, timing, NF history and routing
correlation. The public statement has no spent CM, receipt/index, AK/ASPI or
original native_pk; a sender cannot derive an honest NF from its known receipt
without recipient nk. Do not drop any actual computable identifier on that basis.
Opaque proof bytes are not modeled as a cryptographic anonymity guarantee.

## Precommitted attack and predictions

For each arm/view, enumerate all owner-to-exit bijections consistent with ALL
declared facts. The exact baseline attack converts each known contact native_pk
to its native SPK and looks it up in actual outputs. Intersect direct matches
with amount/fee/timing/cohort, actual own payout/receipt/NF knowledge, public
context/history and actual labelled release routes. In arm B the known policy
allows an independent fresh owner-authorized destination; failure to match the
old key must not exclude the true owner.

Before truth, seal: total compatible bijections; per-honest-owner compatible
exit counts; compatible honest-honest edges; unique predictions/unresolved sets;
and public-digest tie rank intervals. Digest ordering is an auxiliary tie break,
not adversary knowledge. Input manifests, method/trial/source bindings and all
prediction outputs are fixed before scoring.

Prefer actual owner-labelled release metadata as post-seal ground truth for
this bounded lookup test; it is already a dispatcher-visible leak. Do not read
private Original, controller, invoice, key or truth bodies at Root/controller.
Closed roles alone consume permitted private contact/own-wallet inputs. If
private scoring is needed, reserve one persistent admitted-Original query for
the ENTIRE fixed paired vector before private reads; new labels/methods/output
paths cannot reset it. Never provide truth to the observer.

## Fixed criteria

1. Baseline exact invoice-native-key lookup succeeds on the actual selected
   baseline artifacts, or record a falsified premise / UNQUALIFIED baseline.
2. CONTACT improvement requires strictly more actual compatible honest matches
   after intersecting EVERY frozen fact, with all true matches retained.
   Lookup disappearance alone is not a gain. A unique remaining match means
   NO MEASURED GAIN; excluding truth means INVALID MODEL.
3. Record actual rank/tie size and correct/wrong unique predictions after seals.
   Do not assume a uniform workload or turn ties into probability claims.
4. Current labelled release requires DISPATCHER/UNION no overall gain; preserve
   that failure. Old strict H1/workload FAIL is never retuned or reclassified.
5. Missing actual proof/source provenance, exact authorization, required views,
   prediction seals or permitted truth provenance yields UNQUALIFIED.
6. Retain all negatives. No outcome-driven source/view/workload/threshold change
   may enter this method; a new proposal needs a separately frozen experiment.
