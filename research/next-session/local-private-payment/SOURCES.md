# Local private payment: primary sources and anonymous ingress

Observed 2026-10-25 UTC. This is a source and transport design record for
[RFC-0029](../../../docs/rfc/0029-local-native-kas-private-transfer.md).
The existing [source review](../sender-private-lifecycle/SOURCES.md) and
[retry options](../sender-private-lifecycle/review/RETRY-PRIVACY-OPTIONS.md)
were read through the public guard. No original wallet, private truth, backup,
attempt log or hidden experiment answer was inspected. The frozen study is unchanged.

## Refreshed upstream identities

The GitHub commits API resolved these branch heads during this work. A head pin
is source identity, not a deployment or audit claim.

| Primary source | Observed pin and consequence |
| --- | --- |
| [Kaspa Toccata decision guide](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/decision-guide.mdx) | docs `0ac77d043a802fc8196abfd5812ac2afbd97a2b9`; select the smallest state model that preserves the invariant. Inline ZK and based apps are distinct options. No new vProgs requirement follows from changing local payment shape. |
| [Rusty Kaspa RPC documentation](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/README.md#json-or-borsh-over-websockets-rpc) | master `4edcbbccb449f84832afb1ca157904b35f37d006`; JSON wRPC can use any WebSocket library. [Request/response models](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/rpc/core/src/model/message.rs#L673) require complete `transaction` plus `allowOrphan`, returning a transaction ID. Mempool submission is not confirmation. |
| [Current official release](https://github.com/kaspanet/rusty-kaspa/releases/tag/v2.1.0) | v2.1.0 is the observed latest release; the separate master pin above is the inspected source. No node binary is upgraded here. |
| [vProgs README](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md#L5) | master `f9b84a863a7c7c20586a9cf947550475e894f72e`; explicitly early/prototype. Runtime integration does not provide anonymous ingress by itself. |
| [Kaspa research specification](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex) | main `c923faca11a49148fa7d912d27ce00197a5c5a4a`; computation-DAG/stitching research is not deployed shielded-wallet functionality. |

## Existing designs: reuse and rejection

| Inspected primary design | Reuse/adaptation | Excluded inference or subsystem |
| --- | --- | --- |
| [Orchard local builder](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs), [note encryption](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs) | Keep owned-note construction, proving and incoming-view-key decryption local; authenticated public ciphertexts can be scanned without revealing a view key to a server. | No Orchard curve/circuit port and no claim that encrypted notes hide connection origin. |
| [Aztec PXE](https://docs.aztec.network/developers/docs/foundational-topics/pxe) | Private inputs remain in client execution; transmit public requests/proofs only. [Aztec source](https://github.com/AztecProtocol/aztec-packages/tree/c1b606f97dcd56668ccd8087a794190c34b4c571) was resolved independently. | No rollup/runtime dependency. No private PXE or wallet exposed as a remote service. |
| [RAILGUN broadcasters](https://docs.railgun.org/wiki/learn/privacy-system/community-broadcasters) | Separate public-chain submission from the wallet's identified account. Distinguish relay availability from proof validity and chain acceptance. | No new broadcaster market, Waku dependency, reward note, privileged relay key or assumption that a broadcaster guarantees metadata privacy. |
| [Monero proxy guidance](https://github.com/monero-project/monero/blob/3fd0f88c20f559839cafb20911cb13cb45eba7bd/docs/proxies.md) | Transaction relay and ordinary reads each need an explicit privacy transport; selecting a transaction proxy does not automatically protect every connection. | No ring-signature or P2P transport rewrite. No direct fallback when a privacy proxy is unavailable. |
| [MWEB light clients](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md) | Download public history and perform filtering/decryption locally. Sharing scan keys with an untrusted node reveals owned outputs and values. | No remote view-key filtering, wallet-specific leaf/scan-index endpoint or MWEB consensus port. |

## Selected ingress contract

Use established Tor SOCKS5 with proxy-side DNS, verified TLS, and a new
isolation context for each unrelated connection. The
[official Arti example](https://arti.torproject.org/guides/connecting-to-onion/)
uses curl `--socks5-hostname`; the
[Tor SOCKS extension specification](https://spec.torproject.org/socks-extensions.html)
recommends username `<torS0X>0` plus a random isolation password. This is a
local circuit label, not wallet identity or remote application authentication.
[Stream isolation](https://spec.torproject.org/path-spec/stream-isolation.html)
does not promise different exit nodes or unlinkability to a global observer.
The source repository HEAD resolved to `f0cda49bb86c016edbae3d331849eb7e2fdacfc6`;
its rendered specification was inspected, while GitLab file rendering was blocked.

The transport accepts only explicit public-history requests or a complete public
native transaction produced and validated locally. Private proving witnesses,
seeds, note plaintext, invoice indices, view keys, owner labels and participant
rosters do not enter its interface. Public transaction signature scripts/proofs
are consensus-public material, distinct from private proving witnesses.
It supplies no cookies, authorization header, identifying client header or
persistent application session. Credentials in destination URLs and redirects
are rejected. No proxy failure, TLS error or stale transaction permits direct
network fallback, weaker verification or automatic rebroadcast.

The [official resolver list](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/rpc/wrpc/client/Resolvers.toml)
and [URL construction](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/rpc/wrpc/client/src/resolver.rs#L144)
provide public endpoint discovery, also over Tor. Only an explicitly selected
TLS JSON endpoint is eligible. The node must report `testnet-10` before a submit;
this is a network guard, not independent authentication of chain history.
Existing local native/full checks and accepted-history reconstruction remain
mandatory. A remote mempool acknowledgment is never a confirmed payment.

Use the node's documented JSON wRPC framing, not generic JSON-RPC `result`:
[workflow-rpc 0.18.0 protocol](https://docs.rs/crate/workflow-rpc/0.18.0/source/README.md)
uses `id`, `method`, `params` on both request and response. Method spelling follows
the node's [camelCase operations](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/rpc/core/src/api/ops.rs#L17).

## Dependency and runtime evidence

Initial command metadata: `tor`, `arti`, `torsocks` absent; `/usr/bin/curl` 8.18.0
present. Authorized reversible local runtime lives exclusively beneath
`/var/tmp/kpi-local-private-payment-01/assets/ingress-runtime`.

- Selected [official expert bundle](https://download.torproject.org/tor/):
  `tor-expert-bundle-linux-x86_64-15.0.26.tar.gz`, Tor 0.4.9.14,
  SHA256 `19cf18726eecb362e0f21d27afa9ea9efe5da928bfdfbb1ceb5fe54519e87f4a`.
  The detached signature verified with the
  [documented Tor Browser Developers key](https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/),
  primary fingerprint `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`;
  signing subkey `022DA248432D2A0E0F54E65E316C1FACD62D07D9`.
  No global package, service, account or purchase was created.
- Local client-only daemon: loopback SOCKS `127.0.0.1:19050`, `SafeSocks 1`,
  `IsolateSOCKSAuth`, separate local data directory. A verified-TLS request to
  `https://check.torproject.org/api/ip` succeeded with `IsTor == true`.
  The returned IP was discarded. This proves that one probe used a recognized
  Tor exit; it does not prove application traffic privacy.
- [websockets proxy documentation](https://websockets.readthedocs.io/en/stable/topics/proxies.html)
  supports explicit SOCKS5h via
  [python-socks](https://github.com/romis2012/python-socks).
  Local pure-Python wheels were checked against primary PyPI JSON digests:
  [websockets 17.3](https://pypi.org/pypi/websockets/17.3/json), SHA256
  `dc2b495a92b3971966bf102e73589f950db3ec1ca6713265355ce7771d97b199`;
  [python-socks 3.1.1](https://pypi.org/pypi/python-socks/3.1.1/json), SHA256
  `327e0d6378702c73a7790bf732e9f01392f17b48c7348a50b5bd1f710c2df1be`.
  Explicit proxy selection overrides ambient proxy/bypass configuration;
  redirects are disabled separately. No custom anonymity or cryptography is added.

## Evidence limits and remaining integration

Tor's [stated attack limits](https://support.torproject.org/about-tor/security/attacks-on-onion-routing/)
include correlation by observers of both ends. Public NF/output grouping,
transaction size/timing, fee sources, shared-head retries, recipient collusion,
invoice delivery and a stable invoice delivery key can still link activity.
Fresh sessions do not erase a repeatedly exposed public NF or transaction.
HTTP/WebSocket fingerprints remain observable to the destination.

Local fake-proxy controls establish client routing/framing and failure behavior;
they are not Tor-network evidence. The real read-only probe is separate.
Fifteen local controls passed: twelve JSON transport/contract controls and three
raw-frame bridge controls. Current official-list resolver probes
over Tor did not yield a usable TLS JSON testnet peer: `eric.kaspa.stream`
failed; `john.kaspa.red` returned HTTP 404 and `jake.kaspa.green` HTTP 521
for `/v2/kaspa/testnet-10/tls/wrpc/json`. These are observed availability
failures, not evidence that all testnet peers are unavailable. The existing
public [chain adapter](../../../poc/sender-private-lifecycle/chain/fetch.mjs)
then supplied its selected peers. Actual read-only `TorIngress.rpc()` requests
to the JSON suffixes of `vector-10.kaspa.green` and `electron-10.kaspa.blue`
both succeeded with `network == testnet-10`, reporting DAA scores 606270542 and
606270554 respectively. These were real Tor/SOCKS5h/TLS WebSocket requests,
not the local fake-proxy control. The JSON method/response framing is therefore
exercised against native node RPC.

The selected official SDK chain adapter retains Borsh via
[`startTorBridge`](../../../poc/local-private-payment/ingress/bridge.mjs): an
ephemeral loopback WebSocket forwards raw text/binary frames unchanged to the
selected peer through mandatory Tor/SOCKS5h/TLS. It implements no Borsh codec.
Only one local SDK session is accepted; the listening socket closes after that
connection and no upstream retry occurs. The controlling adapter must make only
public RPC requests and enforce network/history/full-case validation and execution
release. Raw forwarding cannot identify a private field hidden inside an arbitrary
Borsh frame, so this boundary is an obligation on the local SDK caller.

An actual read-only run used the selected Node binary with `--use-openssl-ca`,
the existing public SDK loader with its JS/WASM/package identity checks, the
loopback bridge and the vector peer's TLS Borsh endpoint. Official SDK
`getBlockDagInfo` succeeded through Tor with network `testnet-10` and DAA
606273282. This establishes SDK/transport compatibility, not payment acceptance
or anonymity against traffic correlation. Local controls preserved exact binary
and text frames, rejected a second local session and closed without retry when
the upstream failed. Wallet integration remains pending.
Native broadcast, accepted payment/change recovery, independent exits and
confirmed payouts are pending the root's separate execution release. No funding
or transaction broadcast was performed by this source/ingress workstream.
