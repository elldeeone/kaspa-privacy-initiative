# GN2/W accepted-prefix recovery

Separate ADR0060 client for the selected four-wallet testnet profile. The old
KPX3 recovery client and constructed-W study are unchanged. Public acquisition
reads no owner backup, funding key, proving key or private controller file.

Select the exact financial-profile and descriptor raw SHA256 values outside
the RPC/release data. The profile is `kpx6-four-wallet-financial-profile/v1`;
the descriptor is `kpx5-gn2-network-descriptor/v1`, with the recent birth anchor,
actual funding outpoint0, trial UUID, exact initial W and external profile pin.
Profile setup is separate from one-command fresh trial identities.

```sh
SELECTED_NODE --use-openssl-ca poc/four-wallet-chain/anchor.mjs PROFILE PROFILE_SHA NEW_ANCHOR --rpc WSS_URL
SELECTED_NODE --use-openssl-ca poc/four-wallet-chain/fetch.mjs PROFILE PROFILE_SHA DESCRIPTOR DESCRIPTOR_SHA NEW_FETCH --rpc WSS_URL
```

The selected SDK's three files are independently byte checked. `--sdk-dir DIR`
may locate those same bytes. An anchor observation does not create a trial or
authorize funding. `fetch.json` status is **FETCHED_PENDING_REPLAY**, never a
confirmation or spend authorization by itself.

Acquisition retains every decoded Full page, scans to a fixed confirmed
frontier, follows actual GN2/W transaction IDs and queries exact funding,
ordinary change, W and private payout outpoints. It watches every queried live
point in a post-query scan, then performs a final exact UTXO requery to catch
near-tip spends still inside the confirmation window. Any changed entry gives
INCOMPLETE. Virtual child IDs are not L1 heads. Direct private fallback may be
the first W spend after funding; the campaign sequence is not an authorization
rule. Historical compute budgets are judged through actual native execution,
not the wallet's own quote preference.

`verify_bundle.mjs` freshly recomputes official SDK IDs/header hashes and
rejoins complete selected bodies **and all populated contexts** to retained
Full page locators. V1 txid omits witness and compute budget, so matching txid
alone is insufficient. Canonical relative page paths, exact hashes, full finite
coverage, unique successors, consumed points, live-head/payout/change queries,
post-query watched points and final requery are checked. This SDK stage does
not validate GN2 note liabilities or execute W proofs/native scripts.

The fixed Python composition is:

```python
replay_bundle(raw_descriptor, descriptor_sha256, raw_fetch, fetch_sha256,
              financial, selected_runtime, fresh_output,
              bundle_directory=fetch_root, sdk_directory=selected_sdk_directory)
```

The optional `sdk_directory` is a fixed application-selected, checked directory;
the verifier still authenticates all three SDK files against its selected hashes.
Public callers stage and pass that directory. Omitting it preserves the owner
namespace's masked SDK path. Neither an input JSON nor a callback selects code.

It executes the actual selected SDK stage, strict signed accepted-GN2 validator,
fresh official GN2 normalization/roundtrip/Native Full, and the fixed selected
lifecycle `Runtime.replay_cases` implementation. Initial state comes only from
actual GN2 bytes. The result supplies snapshot, reserve, physical point, actual
DAA `head_context`, fees, payouts and observation checkpoint. Accepted/current
flags describe the **recorded validating-node observation**, not independent
consensus or currentness at an arbitrarily later replay. `spend_authorized`
stays false. The broadcaster must acquire/reconcile again and requery exact
spend inputs immediately before submission.

The owner launcher must guard the fetch/profile/descriptor files against its
one backup inode before reading them. After the fetch metadata is authenticated,
`bundle_public_files(raw_fetch, fetch_sha256, fetch_root)` returns a tuple of
all main/post-query page paths without reading page bytes. Guard **every**
returned inode before hashing or decompressing any page. Parent/leaf symlinks
and traversal reject. The selected software inventory authenticates the fixed
source graph; an input JSON callback cannot select a validator.

Amounts use JS BigInt/Python int; canonical decimal strings cross the RPC/JSON
boundary and convert explicitly before native integer comparisons. Missing,
pruned, removed, conflicting, stale or partial data is INCOMPLETE, not zero.
The validating node, authenticated transport, trusted host/software and
non-atomic observations remain premises. SDK hashes do not prove PoW,
GHOSTDAG or accepted-ID inclusion. Two endpoints do not prove independent
operators, archival history or durable recovery availability.

Public controls use mocked accepted assignments and actual SDK hash/ID code:

```sh
SELECTED_NODE --test poc/four-wallet-chain/test_chain.mjs
```

They generate no private proof, execute no Native Full and make no live RPC.
The retained RED/GREEN near-tip race and public-only live API probe are in
`research/next-session/four-wallet-testnet/chain`. Source/control success is not
actual GN2/W acceptance, confirmed payout, financial privacy or a 2% fee pass.
