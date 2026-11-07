# Source reuse and assumptions

Starting source: `79f71e65993134bfa1bea830744375f08e9d4500`.
The [privacy guide](../../docs/research-knowledge/privacy.md), corrections,
SECURITY-INVARIANTS and [RFC-0005](../../docs/rfc/0005-common-set-withdrawals.md)
govern. In particular RFC-0005 already requires one common issuer/configuration
for the entire round. A new test must check enforcement, rather than assume it.

Reuse these exact producing sources unchanged:

- `poc/cached-approval-verification/host/src/actor.rs`: fresh local wallet backup,
  actual private credit/transfers, eligibility, unblinding/redemption and approval.
- `poc/cached-approval-verification/host/src/anonymous.rs`: canonical
  `round || issuer || value || payout key` message and eligibility context.
  `issue_local` verifies its supplied configuration's state/value/key identity;
  `approve` checks the whole intent, but does not compare a shared registration
  configuration digest with that intent. This is a source observation; the
  fresh experiment determines whether it is exploitable.
- `poc/cached-approval-verification/common`: unchanged complete economic kernel,
  current nullifiers, anchors, exact output set, fee cap and backing checks.
- Existing packed Groth16 wallet relation/parameters, checked submitted-point
  decoder and pinned native script. No new setup or circuit is introduced.

The previous [primary-source review](../cached-approval-verification-2026-11-07/SOURCES.md)
pins current Kaspa/Toccata/vProgs and mature private-payment implementations.
This deployment test adds no notes, nullifiers, state or cryptographic relation,
and imports no alternative runtime. Orchard/Aztec/RAILGUN/Monero/MWEB research
does not make the ordinary Kaspa outputs confidential.

Primary web sources re-read 7 November 2026:

- [RFC9474](https://www.rfc-editor.org/rfc/rfc9474.html), particularly randomized
  message preparation, local final verification and expected-issuer context.
  Blindness for one context does not erase an explicit per-client round marker
  that the application itself later includes in its redemption message. This
  latter statement is an application-level inference tested here, not an RSA
  break or a claim that RFC9474 specifies this application's round agreement.
- [Tor SOCKS extensions](https://spec.torproject.org/socks-extensions.html):
  hostname/SOCKS requests and separate authentication contexts. Separate Tor
  processes/circuits are transport controls, not proof against timing correlation.
- [Docker security](https://docs.docker.com/engine/security/): namespaces and
  separate network stacks; daemon/host control remains outside the separation.

Retain service timestamps, full messages and returned fields. Never replace a
successful active tagging result with the honest common-configuration count.
