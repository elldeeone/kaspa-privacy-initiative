# ADR-0084: Two-phase Testnet trial authorization

**Status:** Accepted bounded research design; offline native core implemented,
actual lifecycle adapters and network blocked

**Date:** 2026-10-28

**Related RFC:** [RFC-0030](../rfc/0030-private-batch-construction.md)

## Context

The first new-profile Testnet trial was circularly gated. `activate.py` required
evidence for two payments, nine confirmed Exits, service loss and terminal scans
before it could create the GEN3 reserve that those accepted-chain observations
depend on. The offline gate also explicitly denied that it established Testnet
terminal confirmation or readiness.

Test KAS is the research asset. A first full Testnet path may be the rehearsal,
provided every value-moving step retains its proof, authorization, conservation,
NativeFull, one-use submission and fresh accepted-state checks. Failure must halt
safely and use a fresh trial identity; it must never weaken or replay a check.

## Constraints

- Preserve `SECURITY-INVARIANTS.md`, especially backing, conservation, single
  spend, state binding, withdrawal safety, recoverability and scoped privacy.
- Testnet only; no mainnet deployment or real funds.
- A launch receipt or preflight JSON is audit evidence only. It is not terminal
  completion, readiness, privacy authority or permission to touch the network.
- No caller PASS Boolean may replace direct privacy, registered-driver, proof,
  native, accepted-chain, service-loss or recovery evidence. Party-local EGRESS
  is insufficient; ADR-0085 requires a separate global payment-capture join.
- Missing prover, driver, service or terminal authority must halt safely.

## Options considered

### Keep the complete future lifecycle as a pre-funding prerequisite

This is fail-closed but impossible for the first current-profile accepted-chain
trial. It prevents the evidence it requires from being produced.

### Remove the pre-funding gate

This breaks the circularity but loses exact identity, privacy, driver and native
admission before the first network action.

### Split launch authorization from post-terminal completion

Use a narrow same-trial preflight before funding, then require the complete
accepted lifecycle after the run. This preserves stage-local safety checks while
making the first full Testnet path executable.

## Security analysis

Only the selected live parent may start one fresh Testnet research trial. The
safety factory must atomically consume three typed inputs:

1. `BatchPrivacyPassAuthority`, produced only after the frozen transparent
   baseline and hidden candidate captures, observations, truth barrier, owner
   scores, aggregates and comparison all complete; and
2. the global payment-capture completion; and
3. the ordered signed GEN3/R1/R2 native completion authorities for the exact
   fresh three-Original trial, funding identity, component profile, immutable
   tail, and both payment NativeFull/R0/value-conservation candidates.

The factory returns one opaque `PreNetworkSafetyJoin` that retains both the
live privacy-pass continuation and the privately constructed safety authority.
Neither half can be taken or used alone. A caller-authored
`PublicBatchPrivacyPass` is never accepted by the factory. Public receipts may
be retained for audit, but receipt bytes, hashes, JSON, CLI flags and
environment values cannot reconstruct the join. All inputs must bind the same
trial, profile, tail, projections and parent-recomputed finite
source/build/runtime manifest.
The same parent constructs the namespace and argv in memory and owns the first
RPC. If it forks a pinned Python activation child, a fixed authenticated IPC
channel may carry requests back to that still-live parent; the Python process
cannot authorize network use itself. A crash consumes the attempt and requires
a fresh trial identity; no saved launch can be replayed.

The source now implements the one-shot `PreNetworkSafetyFactory`, the
non-detachable live privacy/safety join, and a selected-parent
consumer whose only first-RPC-shaped method requires the resulting live permit.
That method emits an inert move-only boundary capability; it performs no RPC.
The factory accepts only typed global-capture and ordered GEN3/R1/R2 native
completion authorities, never their public receipts.

The offline native-terminal core now runs a hash-pinned sealed executable over
an authenticated fixed seqpacket endpoint. It requires an exact offer ACK,
kernel sender credentials, one completion, control EOF and clean `waitpid`.
R1/R2 own only their fixed terminal-history writer endpoints (FD21/26). The
existing parent-owned producer is the sole reader of all ten streams. Its live
closure and the two live payment-lifecycle authorities are burned together;
private record-root, END, EOF and byte/count evidence must match before the
join returns exactly one producer continuation and two native candidates. A
second linear continuation can instead consume that already-matched bundle
into an opaque `TerminalV2ModelAdmissionAuthority`; it privately retains the
same producer and ordered lifecycle capabilities and exposes no receipt,
terminal hash/count, route identity, PID, group or row accessor. Terminal
content hashes, grouping, counts and child PIDs do not appear in a public
lifecycle or activation receipt.

The parent-owned retained-projection route now carries the exact 10,685-byte
public projection privately into the authenticated sealed child. The child
parses the complete projection grammar and binds its retained-route, fork,
intake, trial and outer-parent lineage into one opaque mapping-source authority.
The hidden candidate emits exactly one complete unlabelled three-NF/six-tuple
group and rejects every supplied owner row. The explicit baseline emits exactly
three owner groups only after consuming the separate disclosure-policy
authority. Private route/process lineage cannot label the public group ID;
changing a public group row changes it. The terminal statement that there is no
explicit owner-to-NF/tuple mapping export is deliberately narrow. Public
accepted-head/successor/state/context continuity is a separate authenticated
constraint and is not claimed absent.

This core deliberately stops at offline durable-final capture. Candidate,
R0, NativeFull, durable-final, complete terminal grouping, the narrow explicit
owner-to-NF/tuple mapping-export statement, structural projection continuity,
END and writer close precede `PreNetworkSafetyAuthority`. Testnet submit, ACK and
`AcceptedCaseV2` are a separate linear continuation that may begin only after
the first-RPC permit and must later feed the post-network complete-trial gate.
This split is non-cyclic: pre-network authority never requires evidence that
can exist only after it authorizes the first network action.

The genuine producers remain incomplete. The registered driver exposes only
party-local typed EGRESS completion, not the outer six-party plus ten-stream
`PaymentCaptureCompletionAuthority`. The native supervisor is not called by
the real GEN3 or payment Python lifecycle. Although the retained projection
intake and private terminal-model admission capability exist, no production
route/producer/model callsite consumes them; the model still needs the separate
typed structural-continuity join and must return the sole live continuation. An
opaque structural residual now binds the exact matched projections, private
route/process/exit lineage, and requires R1-new/R2-old CM/NF roots, counts,
reserve, state, script and profile context to match. It also binds the R2 old
reserve outpoint, but deliberately carries `accepted_chain_continuity=false`:
projection bytes alone cannot prove that outpoint was accepted from R1 native
history. No genuine accepted-history producer supplies that final relation;
the fresh-owner successor authority lacks these raw fields and cannot be
relabelled. A source-unreachable Step-3 validator now models the first exact
accepted-history handoff without changing that boundary. It accepts only an
opaque authenticated network-child observation tied to the First-RPC lineage,
Testnet-10 genesis, activation candidate, full whole-CASE/context and native-
completion identities, fixed confirmation depth 20, current successor,
old-input absence, and a same-checkpoint post-query with no removed blocks.
GEN3 confirmation may authorize only the Round-1 input. Its one-use network
continuation must survive Round-1 construction and submission before a
separate accepted Round-1 observation can authorize the successor used by
Round 2. Both stages bind the exact run, trial, Round-1 attempt and cohort; the
second also binds the first confirmation and source session.

The fresh-owner supervisor has typed overloads for those two opaque stage
authorities. It burns all supplied capabilities before validation, exact-
matches its plan, injects the three private owner lineages from supervisor
storage, and then invokes the existing input/successor gates. Public receipts,
digests and caller lineage arrays cannot enter these overloads. The genuine
First-RPC consumer, authenticated network-child producer and selected
controller callsite remain absent, so this is source validation only and
cannot invoke a network. Accepted history remains a separate Step-3
prerequisite, not a pre-network privacy-pass prerequisite; requiring it in
Step 2 would recreate the authorization cycle this ADR removes. The selected-
parent producer, namespace builder and network adapter are absent.

A failed R2 observation burns the sole continuation before validation. There
is no R2-only or same-trial retry authority: retry requires a different fresh
trial identity and a complete new GEN3/R1/R2 sequence. This accepted-history
gate admits only the ultimately successful fresh trial. The separate private
observer archive must retain every failed fresh-trial attempt for privacy
analysis; its history cannot be discarded, summarized into this success
authority or used to reopen the failed trial.
Therefore activation remains `CONFIGURED0`; public structs, JSON and success
booleans cannot reach the factory or first RPC.

After launch, every payment and Exit still needs its exact current head, proof,
authorization, NativeFull result, one-use submit and fresh whole-CASE
confirmation. A current-head duplicate-nullifier attempt must refuse without a
FINAL candidate, submission or accepted-chain change. The financial service is
then stopped and observed absent before nine successive Original-only Exits.
There is no admin withdrawal path. A failed trial may strand only free test KAS
and must safely halt.

Post-terminal completion separately joins GEN3, two payments and nine Exits;
exact-once accepted CASEs; nine payout UTXOs; zero reserve; stale replay and
double-spend refusals; service loss; three terminal scans; and actual terminal
Exit-privacy evidence. Only this later gate may call the research lifecycle
complete. It still cannot claim independent consensus, mainnet or production
readiness.

## Privacy analysis

The payment privacy result remains bound to its exact trial and two projections.
It does not cover owner-labelled payout routes. Terminal service-loss/Exit/cold-
scan capture is a separate mandatory gate. Starting a Testnet trial publishes
normal funding and GEN3 metadata before terminal privacy is known; this is an
explicit research boundary, not a general anonymity claim.

## Decision

Adopt the two-phase split:

1. `activation_preflight.py` emits audit evidence only and is never a launch
   authority.
2. The source-only parent seam consumes one opaque `PreNetworkSafetyJoin`
   retaining the live privacy residual and safety authority, then requires the
   resulting permit to issue an inert first-RPC boundary capability. The
   authenticated offline native core
   and private sole-reader join exist, but actual lifecycle/global-capture
   producers, namespace construction and network consumption remain absent;
   `activate.py` and the funding children therefore remain `CONFIGURED0`.
3. `complete_rehearsal_manifest.py` and `rehearsal_gate.py` remain end-of-run
   cryptographic/evidence rechecks, not prerequisites for creating GEN3.
4. `complete_testnet_trial_gate.py` is the post-terminal accepted-evidence gate.
   It currently refuses at the missing actual terminal Exit-privacy authority.

## Objections / unresolved questions

- Implement ADR-0085's authenticated six-party/two-round collection, genuine
  ten-stream closure and live `PaymentCaptureCompletionAuthority` producer.
- Connect the actual GEN3 and R1/R2 validation callsites to the sealed native
  child and genuine retained 10,685-byte projection authority.
- Complete the authority-backed terminal-v2 artifact plus independently
  authenticated structural-continuity join. The projection-only residual now
  exists; consume it in the pre-network model, apply it to the exact two-round
  workload candidate set and return the sole live continuation.
- In Step 3, connect a genuine selected First-RPC consumer and authenticated
  Testnet-10 network child to the staged accepted-history validator, then add
  the separate accepted terminal/native-history relation proving the R2 old
  reserve outpoint is the accepted R1 successor. Neither may be relabelled
  into, or required by, the Step-2 privacy pass.
- Implement the selected-parent producer/network adapter. The safety join and
  parent-only conjunction are source-implemented but deliberately unreachable.
- Implement the current-profile accepted CASE submit/confirmation controller.
- Execute and bind the actual current-head duplicate-spend negative.
- Implement ordered service-loss production and bind it into every Exit.
- Implement the isolated terminal Exit capture/scorer and acceptance authority.
- Acquire and exercise a current-profile finite recovery package independently.

## Evidence

- `poc/local-private-payment/private_batch_trial/activation_preflight.py`
- `poc/local-private-payment/private_batch_trial/activate.py`
- `poc/local-private-payment/private_batch_trial/complete_testnet_trial_gate.py`
- `poc/local-private-payment/private_batch_trial/testnet_activation_authority.hpp`
- `poc/local-private-payment/private_batch_trial/testnet_activation_authority.cpp`
- `poc/local-private-payment/private_batch_trial/testnet_accepted_history_authority.hpp`
- `poc/local-private-payment/private_batch_trial/testnet_accepted_history_authority.cpp`
- `poc/local-private-payment/private_batch_trial/testnet_accepted_history_fresh_owner_bridge.cpp`
- `poc/local-private-payment/private_batch_trial/test_testnet_accepted_history_authority.py`
- `poc/local-private-payment/private_batch_trial/test_testnet_accepted_history_fresh_owner.py`
- `poc/local-private-payment/private_batch_trial/native_terminal_completion.hpp`
- `poc/local-private-payment/private_batch_trial/native_terminal_completion.cpp`
- `poc/local-private-payment/private_batch_trial/native_terminal_mapping_source.hpp`
- `poc/local-private-payment/private_batch_trial/native_terminal_mapping_source.cpp`
- `poc/local-private-payment/private_batch_trial/native_terminal_projection_intake.cpp`
- `poc/local-private-payment/private_batch_trial/privacy_measurement_native_terminal_bridge.cpp`
- `poc/local-private-payment/private_batch_trial/privacy_terminal_capture_v2.hpp`
- `poc/local-private-payment/private_batch_trial/privacy_terminal_capture_v2.cpp`
- `poc/local-private-payment/private_batch_trial/test_activation_preflight.py`
- `poc/local-private-payment/private_batch_trial/test_activate.py`
- `poc/local-private-payment/private_batch_trial/test_complete_testnet_trial_gate.py`
- `poc/local-private-payment/private_batch_trial/test_testnet_activation_authority.py`

The terminal-capture, native-terminal, activation, producer and measurement
controls were rerun together. Thirty-one tests passed, including genuine
ten-stream drain, private root/END/EOF comparison, replay, swapped-round,
wrong-lineage, malformed terminal and pre-permit controls. These results
qualify only the tested offline capability ordering and source validators.
The accepted-history core and fresh-owner typed adapter add six focused host
controls covering staged chronology, wrong network/genesis, insufficient
depth, stale/reorged checkpoints, replay, cross-run/attempt/cohort/trial and
receipt/digest/lineage substitution. They are not an actual privacy pass,
production history producer, Testnet run or readiness evidence.

## Revisit if

A reviewed protocol can prove the full future accepted lifecycle before GEN3
exists without importing caller assertions, or Testnet trial policy changes.
