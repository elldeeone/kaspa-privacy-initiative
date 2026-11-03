# New TN10 rehearsal: funding access

**The known dedicated staging wallet is insufficient:** its sole current ordinary
output holds 306,866,100 sompi (3.068661 test KAS), below the frozen 40-test-KAS
pilot source. Use another dedicated test-only source or the official faucet in a
normal browser. No funding or spending was attempted during this investigation.

The pilot's supplied source is **4,000,000,000 sompi (40 test KAS)**. This includes
the two 10-test-KAS principal notes, native fees and returned ordinary change;
40 test KAS is the frozen pilot input size, not the amount consumed as fees.
A larger received output can first produce the exact pilot source plus ordinary
change, with the extra ordinary fee accounted separately.

## Verified access

1. [Kaspa's current builder page](https://kaspa.org/build) links
   [faucet-testnet.kaspanet.io](https://faucet-testnet.kaspanet.io/).
   Both that hostname and [faucet-tn10.kaspanet.io](https://faucet-tn10.kaspanet.io/)
   returned HTTP 403 with “Enable JavaScript and cookies to continue” to this host.
   [Exact read-only observations](ENDPOINT-OBSERVATIONS-01.json) retain response
   hashes, sizes and timestamps. The [link-match correction](OFFICIAL-LINK-CORRECTION-02.json)
   preserves the initial trailing-slash string-match error. Current payout amount, balance, limit and request
   API were **not verified** behind that challenge.
2. The repository documents a dedicated funding directory: public `funding.json`
   contains `network: testnet-10` and its public address; the separate
   `funding.key` is private. See [existing source description](../../../../poc/shared-pool/README.md).
   The root supplied the public address of its dedicated ordinary test-only
   staging wallet. [Native wRPC observation](STAGING-UTXOS-WRPC-01.json) found one
   non-coinbase canonical P2PK output,
   `a7508a118db8f392faf2671280c5434188c8b6ba5de3baf8645cf9d32adf731d:4`,
   worth **306,866,100 sompi**. No covenant metadata appears in the returned
   entry; historical ancestry or off-chain obligations were not independently
   reconstructed. The endpoint reports version 2.1.0, `testnet-10`, synchronized
   and indexed. This is one remote node observation, not independent chain proof.
   The investigation did not read private keys or invoke an earlier live runner.
3. The official [TN10 setup guide](https://github.com/kaspanet/rusty-kaspa/blob/master/docs/testnet10-transition.md)
   describes mining to one's own address through a synchronized TN10 node. This
   is a fallback; no miner was started, no node was synchronized here, and no
   expected earnings or time estimate is asserted.

## Request APIs: historical source only

The archived official faucet at commit
[`ddeb311bce21aa7e371b430fe56807966bfab749`](https://github.com/kaspanet/faucet/tree/ddeb311bce21aa7e371b430fe56807966bfab749)
has `GET /request_money?address=...`, a fixed one-KAS payment and a 24-hour IP
interval in `server.go`, `faucet.go` and `ip_usage.go`. **This is not evidence that
the current deployed faucet uses those settings or that the endpoint should be
called.** The repository is archived and the deployed frontend was inaccessible.

A separate historical [faucet implementation](https://github.com/supertypo/kaspa-faucet/tree/d5ec6b333d3f82a505d6f1a4ff4cc7c2bf392413)
uses WebSocket `/rpc`, message `faucet-request`, integer sompi amounts and a
CAPTCHA response, with a configurable daily limit. Its deployment identity is
unverified; its default limit must not be presented as today's available funds.

## Immediate action

The known staging wallet cannot fund this pilot. Query another already-authorized
dedicated test-only source if one exists; otherwise open the official faucet
for the **new private trial address**, complete its browser challenge, and verify
the resulting payment and network through the selected TN10 node. Never fund the
public synthetic `DO_NOT_FUND` integration fixtures.

The public REST host `api-tn10.kaspa.org` also returned HTTP 403 for read-only
network and address-UTXO queries; the native wRPC query succeeded instead.

Funding access remains a concrete dependency until one of those routes produces
a verified spendable TN10 output. The current faucet barrier is browser access;
it is not evidence that test KAS or the protocol primitive is unavailable.
