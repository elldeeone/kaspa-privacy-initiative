# Public-only Tor ingress

`TorIngress` accepts public history queries or a complete locally validated SDK
transaction. It has no wallet, seed, proving or remote scanning API. An explicit
local Tor proxy, remote DNS and verified TLS are mandatory. No redirects, ambient
proxy bypass, cookies, destination auth, automatic retry or direct fallback.

For this workspace the verified local runtime is at
`/var/tmp/kpi-local-private-payment-01/assets/ingress-runtime`; Tor's SOCKS port is
`127.0.0.1:19050`. Its pinned pure-Python dependencies are in `python-deps` there.
No global install or system service is required. See
[sources and limits](../../../research/next-session/local-private-payment/SOURCES.md).

Call `await TorIngress().rpc(selected_wss_json_url, method, params)` for public
reads. Each call creates fresh Tor isolation credentials. `getBlocks` requires
complete blocks/transactions; no view keys, addresses or owner-specific filters
are accepted. Public block hashes are public synchronization cursors, distinct
from private invoice or owned-note indices.

`client.py --rpc <selected-wss-json-url> --method <public-method>` accepts only
the public params object on stdin and returns `{ok, params}` JSON. Set
`PYTHONPATH` to the pinned local `python-deps` directory above. Use this CLI from
the chain adapter to keep wallet/proving code out of the transport process.
The selected peer suffix `/kaspa/testnet-10/wrpc/json` was read successfully
through actual Tor+TLS on both `vector-10.kaspa.green` and
`electron-10.kaspa.blue`. `/wrpc/borsh` is a different encoding and must never
receive JSON frames. SDK construction/serialization and full validation stay local.

The `submitTransaction` method additionally requires `allow_broadcast=True`, a
complete selected SDK transaction with integer sompi, and `allowOrphan=False`.
This call is authorized only after the root's explicit execution release and
local native/full validation. The peer must first report `testnet-10` on the same
connection. The transport does not establish policy correctness or confirmation.
Reconcile accepted public history separately; an RPC error or missing response
does not authorize a second broadcast within a used trial identity.

HTTPS fetches accept only explicit query-free artifact URLs and return complete
public bytes. Verify history/proofs locally before trusting or scanning them.
The transport cannot detect a secret intentionally encoded inside a public byte
field: callers must preserve the local private/public builder boundary.

For existing official SDK callers, `await startTorBridge({upstream})` from
`bridge.mjs` returns `{url, close}`. Construct the selected pinned `RpcClient`
with this loopback URL and the upstream's matching encoding. The Python bridge
forwards text/binary frames unchanged through verified TLS/SOCKS5h; it implements
no Borsh codec. Keep `try/finally` around SDK disconnect plus `await close()`.
Only one local SDK WebSocket session is accepted, so reconnect cannot implicitly
replay a used submission. No upstream retry or alternate endpoint is attempted.
The SDK caller owns public-method selection, network/genesis checking and all
native/full validation. In particular, public reserve UTXO queries and complete
history fetches must not become private invoice-index/view-key/owner filters.

Tor narrows the endpoint's direct IP observation under its stated assumptions.
It does not prove global-traffic privacy, anonymity-set size, invoice secrecy,
counterparty honesty or unlinkability of repeated public nullifiers.
