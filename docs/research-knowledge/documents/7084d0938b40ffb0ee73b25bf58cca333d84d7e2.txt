# METHOD03 owner-origin Exit route study — UNSELECTED DRAFT 02

Status: design/source draft only. Root has not approved or frozen this method.
This file grants no generation, capture, network, Original, scoring or broadcast
authority. METHOD02 and its evidence remain immutable.

## Question and smallest comparison

Does moving the validated Exit body from a controller-labelled release into a
network-off owner-to-transport pipe increase the honest-owner matching set at
the actual receiving terminal, after retaining controller/transport metadata?

Both arms use the already implemented fresh self-payout rule. This isolates the
release/origin route; it does not compare old invoice-native payouts with fresh
keys again. METHOD02's actual direct lookup3->0, same-position/dispatcher
collapse, UNQUALIFIED result and old H1 failure remain unchanged.

Proposed finite workload, for Root to select before any new private generation:
three owners, corrupt owner1, one actual owned note/Exit per owner per arm;
same hidden receiver assignment and economic requirements in both arms; self
choices allowed, no public cyclic schedule. Use distinct actual note instances,
rho/CM positions, NFs, actions and outpoints across arms. Proposed unused invoice
indexes11/13 are placeholders until the admitted Original/budget selection is
fixed. Never reuse METHOD02's six published outputs/NFs or relabel their order.

For comparability, propose the existing supplied continuing-head component shape:
CM3, initial NF1, reserve6,000,000,000 sompi, note200,000,000, fee1,
payout199,999,999; selected common chain/pool/profile/domain/service. Roots,
outpoints and actions remain their actual public bytes. These are independent
supplied contexts, not a collectively accepted chain or reserve-backing claim.
No new profile, VK, proving setup or primitive is proposed.

ArmA: the unchanged cafb release validation exposes the actual prepared public
candidate and owner-labelled digest/route to the controller, then the established
packet/transport sends it. ArmB: the same genuine validation runs in the owner
release role; that role encodes4096 bytes and writes stdout1 directly into
transport stdin0. The controller never opens, reads, hashes, tees, caches or
exports the candidate/frame or an owner-labelled content digest in ArmB.

Use the same selected Tor transport/endpoint/receiver behavior for both arms
where possible, so A-versus-B measures the origin boundary rather than also
changing network path. The existing direct release remains independently
available. The draft does not require or implement automatic fallback.

## Source boundary and functional prerequisite

Keep cafb's exact selected head/tail, finite candidate schema, exact statement
equality and real930/bc41 proof validation. Reject unrecognized fields. The
owner release role has one private prepared candidate, public source/context/
verifier leaves, no Original, proving key or network. It closes ambient setup
FDs before candidate intake, writes one4096-byte packet plus EOF on a blocking,
write-only stdout1 FIFO, and fixed status only on stderr2.

The parent connects the owner's stdout read end to transport stdin0 and closes
its duplicate endpoints. It must never consume bytes or calculate a labelled
digest. Record actual PID/PPID, pipe inode/FD topology, executable/namespace,
argv, mounts, start/end/readiness/status/HTTP outcome metadata without reading
candidate, frame, private config, SOCKS credentials, Tor keys or raw logs.
Transport has no candidate/Original/key mount. Its frame/config memfds and
per-process SOCKS isolation credentials remain private; no credential, frame
hash, request ID or response ID may be silently exported as an owner label.

4096 is framing, not authorization or anonymity. The packet exposes magic,
projection width, exact public projection/proof and random padding. Equal byte
lengths do not hide connection count, timing, stream/request/response metadata
or per-owner process/pipe identity.

No forced waiting for peers, batching barrier, delay, shuffle or padding traffic
may be introduced solely to make this comparison pass. Use the actual selected
readiness/launch schedule and retain it as attacker knowledge. Receiver output
is its actual append/arrival order. Do not reuse one secret publication owner
order across arms, pair positions or post-process arrivals into favorable order.
If the real implementation creates such a coupling, include it and retain the
failure; do not sanitize the measurement.

One transport attempt per admitted event; no retry, rebroadcast or regenerated
note inside this vector. Preserve all refused, late, duplicate, partial and
possibly-arrived attempts. Existing direct fallback is a liveness option, not
a privacy requirement: if actually used, retain its exact labelled route and
report that event accordingly; do not drop it from the comparison or call it
anonymous. There is no transaction broadcast in this proposed component study.

Actual owner-pipe/transport functionality is not yet a privacy qualification.
Probe08 retained2/3 frames. Probe09 observed3 arrivals but remained INCOMPLETE
when termination preempted receiver summary. Fresh drain/launcher work is still
pending. Latest status: probe12 drained cleanly but received only1/3 frames;
fresh13 changes only the operational ClientSocksTimeout to900 and is not yet
a complete qualified rehearsal in this draft. Require an exact-source complete
functional rehearsal, drained final
typed receipts and independent Native checks before Root freezes any privacy
execution. Public known-seed probe frames cannot become privacy evidence.

## Declared views and actual attacks

TERMINAL+CONTACT: all actual received4096 packets, request headers, peer/session
metadata, receive/order/status records and public native projections; corrupt
owner1's legitimate contacts, actual constructed receipt/invoice/rho/CM/value/
blind/tuple knowledge, own payout/NF/session/timing facts; all actual public
amount, fee, cohort, head/history and source-computable schedule facts. Preserve
domain-stable delivery-key knowledge. Do not publish full Invoice208 globally.
Unmodeled byte/cryptographic semantics are explicit missing coverage.

CONTROLLER+TERMINAL: the preceding view plus actual owner-labelled invocation,
mount, PID/PPID/pipe/FD, transport/curl/Tor endpoint, readiness/exit/status and
fallback records. Preserve any actual content-labelled artifact or request/
response/digest identifier. Owner->pipe->transport labels an outgoing
submission. Joining it to a particular terminal frame requires actual
body/digest, stream/circuit/response identity or a valid causal timing bridge;
same-host existence alone is not a proven remote-stream mapping.

GLOBAL-HOST/UNION: also retain any actually available local SOCKS/loopback body,
Tor control/circuit/stream mapping, FD/process, client/receiver-host metadata
and the declared corrupt participant/server view. Such facts may exactly
recover the removed association. Same-host or global-host privacy is not
qualified merely because controller source refrains from reading bytes.
A privileged host able to inspect client secrets is outside a trusted-client
claim; missing full host/server observations force UNQUALIFIED, never omission.

The PRIMARY comparison is CONTROLLER+TERMINAL in BOTH arms. Compare the same
view and complete knowledge in A and B. TERMINAL+CONTACT and GLOBAL-HOST/UNION
remain separately reported secondary views; a smaller-view result cannot replace
a collapsed primary result or the missing full-host/server qualification.

Finite attack for each declared view: enumerate owner->received-Exit bijections jointly
over both arms, using all available facts above. Remove the corrupt owner's
known own frame/session as an adversary could. Include public amounts, contact/
receipt knowledge, head/action/outpoint structure, launch/readiness order,
connection/session/request/response identities and conditional A/B joins.
Independent keys/NFs prevent a direct identifier join; they do not prove
independence of observable execution histories. Same hidden assignment alone
does not label B; actual source/metadata bridges must determine the joint
constraints. Do not compare separate-arm marginals while dropping those joins.

## Successful202 timing attack — source-specific

Current transport88cb waits for curl to return success AND exact HTTP202; this
is not a send-only completion. It discards the response body and prints only a
fixed transport receipt. HTTP202 means an untrusted packet was received, not
proof, financial, chain or fee-policy acceptance.

Receiver037 reserves accepted_monotonic_ns at accept, sets
post_handler_monotonic_ns before body intake, reads4096 and hashes/decodes it,
then writes202/ACK. recorded_monotonic_ns is written/fsynced in finally AFTER
the response write. It is completion bookkeeping and is NOT guaranteed earlier
than the client's successful completion. Do not use that latter field as a
pre-ACK frame timestamp or alter frozen receiver037 to improve the score.

For a successful owner-labelled transport, the frame-associated
post_handler_monotonic_ns must lie inside the actually recorded transport-
process launch lower bound (guaranteed before its curl request and POST handler)
and successful202 completion upper bound, widened only by the
preselected clock-domain uncertainty. accepted_monotonic_ns can provide
additional source-justified bounds; no unjustified preconnection assumption.
Intersect these interval edges in the owner/frame bipartite graph. Sequential
disjoint successful intervals can identify every owner without any body hash,
Tor FIFO assumption or circuit-control evidence.

Fix clock domains, monotonic namespace/offset evidence and a public calibration
procedure BEFORE private generation; never fit clock uncertainty to hidden
truth. If clocks cannot be compared safely, mark the timing view UNQUALIFIED.
Do not invent a network delay distribution or a uniform posterior.

For client errors/no202, a frame may still arrive. Transport send/close/failure
does not impose a finite remote-arrival upper bound or prove nondelivery.
Preserve conservative possibly-arrived tails, failures and late records; do
not delete them, assume FIFO or use a favorable drain deadline.

## Prediction, truth, budget and criteria

Root selects the complete generator, owner/transport/receiver/launcher,
capture/extractor, adversary/scorer, runtime/parameter and input/output manifest
before any new notes/keys/views. ActorAPI or transport functionality probes are
not that selection. Pending launcher/capture/scorer code cannot be treated as
already qualified. Actual output digests are filled after execution, not used
as a prerequisite for the source freeze.

Never reopen an admitted Original's consumed observation/scoring budget with a
new method, attempt, output label, copied backup or rollback. Root must admit a
genuinely unused identity/budget or explicitly select the already-authorized
unconsumed vector under persistent per-Original state. Do not reuse revealed
METHOD02 labels as unknown truth. Capture/observer input paths are finite;
controller never reads/hashes private contacts, raw captures, predictions,
salts, honest truth, witness/matrix/financial state, TLS/Tor keys or raw logs.

Freeze all views' joint predictions before truth: exact selected projection
universe; compatible bijections/edges, per-honest-owner counts; unique
predictions, digest tie-rank intervals; modeled/missing coverage and source/
trial/method bindings. Commit with private high-entropy salt; public seals
contain commitments, not private graphs. Scoring consumes the whole fixed
vector once. If honest owner truth is not already legitimately public, only
isolated one-owner scorers may read that owner's actual truth after all seals.
No Root content-labelled digest may be added before sealing to make scoring
easier. Exact model-row universe and joint-projection equality are required.

Define cA(o) and cB(o) as owner o's compatible-Exit counts in the SAME primary
view after ALL joint A/B constraints. Numerical route gain requires cB(o)>=cA(o)
for EVERY honest owner, cB(o)>cA(o) for at least ONE honest owner, and EVERY true
match retained. No decrease for another honest owner may be hidden by an
aggregate edge-count increase. Record per-owner counts/ranks and correct/wrong unique
predictions; no probability claim from ties. A unique remaining honest match
is no improvement for that owner. Excluding truth is INVALID MODEL. A baseline
that does not show its claimed labelled-route exposure is UNQUALIFIED baseline.
Missing valid proofs, source/provenance, required packets/views/clock facts,
seals or permitted truth is UNQUALIFIED. Full global-host/server coverage and
cryptographic anonymity are not claimed even if a smaller finite view gains.
Keep direct-fallback, transport failure and old H1/METHOD02 negatives intact.
No outcome-driven source, schedule, economics, view or criterion change enters
this vector; a subsequent proposal requires a separate Root freeze.

## Concrete public dependencies and remaining work

ROOT=/home/luke/projects/kpi-intensive-2026-10-22/continuation

Pinned public inputs (independently read through qualified guards for this draft):
- poc/local-private-payment/private_batch_trial/exit_release.py
  cafb737b2957b6a11743de8a319add82dc1dab520e708cd2ea0ca669b4577d4e
- poc/local-private-payment/private_exit_submission/packet.py
  7c0ad5f630a94a1481384c8726d98ebcfbab7ff1f6ba5395b3d8da9fafda38a6
- poc/local-private-payment/private_exit_submission/transport.py
  88cb8d0c0eb7c8a533556f7323d30c115a56a97a53b45263b3f0932dbbeba4f4
- .local/private-exit-submission-proposal-01/owner_release_pipe.py
  7d65b4c51c88b834f644088747f06e7926044411b3f77c945f238e2150970ed9

Independent source review also admitted receiver037 below and confirmed its
pre/post-ACK ordering. Other supplied dependencies and the complete closure
still require independent admission before any selected execution:
- receiver.py under private_exit_submission:
  0375401b3f3b2844c60e78bf4450cf1ad7f8e574462bc98b71395078d07601ac
- owner source selection OWNER-PIPE-SOURCE-SELECTION.json:
  05d77baf6917aa5ac7a326ccee0e9b7877eddf4558f7046d3b3060282132e1f0
- exit_wire.py fabf7361f030e25ec4a52a72691fef4bcfe03f6fef369ff33b8fa55dd01ccb6a;
  verification/wire.py6727e00a143596dbd31abf06c7fd5a2ceafa07082d6e3e6de47fa389a826def8
- public verifier930972ac461ec4d9300836d4127212a594c55b90b56b8732bc9bfd98507a6fa6;
  AuthExit manifestbc41c97e06f07a06ee9ab2af59ef1ba8c5190a126dfb0eb120d586667aaddd8f
- fresh_self_payout886fed167f177fd1781bddf090ca2b5fd01dd2df7d10f5a664016f6aee46d456;
  complete current wallet/prover/parameter/generator dependencies still selected
  by Root; use fresh-key policy in BOTH arms.
- METHOD02 frozen methoddc5026741ccc3bf8d19105a1528257d6934ed76877ec1fc3fe19e3e2b586834d
  and its immutable actual no-gain result6c720defe40d76dd965485396254801a2bf17e7fb0ffcd44e34e8049989e457b.

Pending, not source-frozen by this draft: owner_pipe_launcher; complete drained
functionality selection; new-note generator integration; exact capture/view
extractors, joint timing/session attacker, truth-budget/scorer and full runtime
source manifest. No privacy execution is authorized while these are pending.

Qualified guards keep all known private roots excluded. Extra Tor metadata roots:
old /var/tmp/kpi-local-private-payment-01/assets/ingress-runtime/tor-state;
probe08 /var/tmp/kpi-owner-private-lifecycle-01/private/diagnostics/owner-origin-probe-93f5f533-ff61-42bb-b9b1-cda28254d3bb;
probe09 /var/tmp/kpi-owner-private-lifecycle-01/private/diagnostics/owner-origin-probe-7dbd8ce6-6a1d-4629-9d9b-62de34016ac7.
Probe12 root5d74eea0-dde9-4415-a09e-05b873fe9001 and the latest selected probe13
root /var/tmp/kpi-owner-private-lifecycle-01/private/diagnostics/owner-origin-probe-bb4f2d10-57da-4913-b4cd-0b424defd468
are under the same protected diagnostics ancestry; include if created, metadata only. No Tor
key/config/rawlog body was read or hashed for this draft.

Minimal next plan: finish the public functional drain/launcher first; implement
only the finite fresh-note/capture/joint-attacker/scorer seams above; have Root
select/freeze METHOD03 and its complete source/budget; only then run the fixed
actual vector and retain its outcome.

Draft02 incorporates independent source/design review: exact primary-view identity,
transport-launch causal lower bound and the explicit per-honest-owner gain predicate.
No Source/metric change after private results is involved: no METHOD03 private
experiment, note/Original generation or capture has been run or authorized.
Draft01 remains unchanged. Root still owns approval and freeze.
