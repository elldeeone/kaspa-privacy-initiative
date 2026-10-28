# RFC-0031: Owner-origin Exit submission over Tor

2026-10-28. Status: isolated receive/verify-only experiment selected by
[ADR-0082](../adr/0082-optional-owner-origin-exit-submission.md). Current workload,
proof roles, publisher, withdrawal authorization and broadcast behavior remain
unchanged. Actual framing, namespace and Tor-path results are still required.

## Concrete problem

`private_batch_trial/exit_release.py` validates an owner's candidate in a
network-off role, writes clear `PUBLIC-CANDIDATE.json` into an owner-selected
output directory, and lets the controller read it. Its public selection and
observed release record also name the owner component and private candidate
path. The controller therefore has an exact owner-to-NF/payout handoff.

The METHOD02 publisher additionally emits A and B in the same owner order.
Once an invoice contact identifies an A row, that source-known position maps
the B row despite distinct NFs and fresh payout addresses. Keep this existing
counterexample and its frozen publisher unchanged. The proposal is a separate
transport candidate and experiment; reordering existing results is not evidence.

## Reuse and primary evidence

Tor provides SOCKS5 hostname requests; using its remote hostname form avoids
local destination DNS resolution. Application isolation tokens can keep
logically independent streams off a shared circuit. These are transport
properties, not owner authorization or resistance to both-end timing analysis.
[SOCKS specification](https://spec.torproject.org/socks-extensions.html),
[isolation specification](https://spec.torproject.org/path-spec/stream-isolation.html).

Use an ordinary v3 onion service forwarding to a loopback-only application.
The Tor process owns its service keys; the controller receives only the public
onion address from an isolated helper. Reuse the retained public Tor executable
and installed curl, without touching the running Tor process or private state.
[Tor service setup](https://community.torproject.org/onion-services/setup/).

Monero's official transport documentation separates local transaction relay
over anonymity networks from general network traffic and handles a missing
anonymous connection as an availability failure. Reuse that separation, not
Monero transaction rules, Dandelion++ or another anonymity protocol.
[Monero source at commit 2c327aa325871c18f3b84685b8d1843d49167ca4](https://github.com/monero-project/monero/blob/2c327aa325871c18f3b84685b8d1843d49167ca4/docs/ANONYMITY_NETWORKS.md).

Tor explicitly does not protect against an observer correlating traffic at both
ends. Preserve real launch, pipe, arrival, completion and volume observations;
this design makes no same-host or global-host anonymity claim.
[Tor limitations](https://support.torproject.org/about-tor/security/attacks-on-onion-routing/).

The old zcashd Tor documentation demonstrates historical proxy/service
separation, but contains obsolete v2 setup examples. It is not an implementation
authority for current onion settings.
[Historical zcashd documentation](https://zcash.github.io/zcash/user/tor.html).

## Smallest proposed seam

1. Keep signing and candidate verification inside the existing network-off
   owner role. It reads only its own Original/prepared candidate, rechecks the
   exact selected head/tail, approved fee and genuine AuthExit proof. It sends
   the finite public candidate through a private pipe instead of writing an
   owner-labelled clear public export. The controller never reads that pipe.
2. A separate transport role has no Original, wallet seed, signing key or private
   opening mount. It receives that one pipe and submits through SOCKS5 to one
   fixed onion endpoint. No owner component, invoice, path, client certificate,
   cookie, callback address or candidate digest leaves in controller receipts.
   Fresh SOCKS isolation tokens stay inside the transport role. Use established
   curl/libcurl behavior, not a new cryptographic or SOCKS implementation.
3. A common dispatcher receives public candidates without an application owner
   identity. It preserves true arrival order, socket peer, timestamps, sizes and
   all validation outcomes. It never sorts by owner or reproduces a paired owner
   loop. Client roles operate independently/concurrently; there is no required
   batch, delay, cover participant or public owner-order schedule.
4. Reuse the public native adapter: reconstruct the exact CASE from projection,
   proof, State112 and selected immutable tail; normalize only cached ID/mass;
   require byte-identical reconstructed projection; independently acquire the
   real current head and run selected proof/native checks before a live submit.
   The first prototype is receive/verify-only and has no broadcast operation.

## Fixed application frame

Candidate frame is exactly 4096 bytes: `KPBXNET1` (8), projection length u16LE,
the canonical 1796- or 1844-byte Exit projection, proof128, then independently
random padding. Terminal/continuing mode remains visible to the receiver and
eventually on-chain; it does not change outer application length. Reject any
other length, width, tag, header/body inconsistency or trailing framing error.
This wrapper is not a signed statement or new spend authority. Existing owner
AK signatures and proofs still bind the entire existing Exit statement.

Use one endpoint/path, constant generic headers and a fixed-size reply. There
is no owner token, URL parameter or returned public digest for a controller to
join to a dispatcher row. The owner may keep its delivery/ack record privately.
The public event ID is SHA256(projection), computed by the dispatcher. Curl
must disable personal configuration, redirects and automatic retries, require
the selected SOCKS hostname path and avoid clearnet fallback.
[curl options](https://curl.se/docs/manpage.html).

## Authorization, failure and independent Exit

The relay has no spend key or administrative withdrawal method. Changing the
destination, fee, NF, head or payload invalidates existing authorization; the
actual fresh-payout proof/native controls remain the reference. Relay admission
is not an accepted-head, settlement or history-resolution capability.

A missing relay or Tor connection reduces this optional route's availability.
Do not automatically downgrade to clearnet or silently retry an ambiguous trial
submission. The owner can consciously use the unchanged independent direct Exit
path. No reserve, minimum working balance, forced waiting or peer quorum is added.

## Required decisive evidence

Freeze a NEW method before generation. Keep METHOD02 and its same-position join
as the baseline. Verify exact packet/projection/proof equality, no private key or
Original in the transport/dispatcher, refusal of malformed/unauthorized/stale
candidates, and continued independent direct Exit when the relay disappears.

Record actual controller role/pipe/launch metadata, all dispatcher arrivals and
timings, all permitted sender/colluder facts, public payouts/fees and identifiers.
The new dispatcher must receive no explicit owner/path and no source-imposed
paired owner order. Any residual timing or economic candidate collapse remains
a failure for the relevant full observer; do not remove fields to obtain gain.

An HTTP/SOCKS loopback simulation can qualify framing and dependency boundaries
only. A same-host real Tor run can show that the actual onion path is used and
measure application observations, but cannot establish global-host anonymity.

## Pending selection

Root must select the isolated source/transport method before owner data is
submitted. Public runtime/version metadata and current upstream source hashes
are in the [source receipt](../../research/next-session/local-private-payment/private-exit-submission-2026-10-28/PRIMARY-SOURCES.json). No setup, source-profile rotation or new proof key
is required for this transport wrapper. Any eventual live submit must use the
separately qualified current-head/native/confirmation path; this draft does not
upgrade the unfunded fixture or authorize a network broadcast.
