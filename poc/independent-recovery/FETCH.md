# Descriptor-only read-only chain acquisition

```sh
node poc/independent-recovery/fetch.mjs PUBLIC_DESCRIPTOR NEW_OUTPUT \
  --rpc wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh \
  --rpc wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh
```

The descriptor's nine exact fields identify a user-selected pool, its canonical
founding output and public initial policy/VK, and a retained pre-founding birth
anchor. It contains no current state, snapshots, known payment amount, owner,
other operation IDs or private material. See the transport
[contract](../../research/next-session/privacy-recovery/fetch/CONTRACT.md).

The client authenticates the installed official SDK and approved app policy,
finds a finite confirmed frontier and discovers the actual reserve-spend graph
from Full accepted chain data. Headers are retained with expanded parents and
independently rehashed by the SDK after clearing the reported cached hash.
Selected transaction IDs are recomputed from complete bodies and populated
inputs. U64 values remain integers/decimal strings; header blue work retains its
native fixed-width hexadecimal encoding.

`fetch.json` contains the selected public rows, full headers/input contexts,
current queried outputs, finite coverage and post-query chain checks. Required
missing/pruned data, reorgs, incomplete pagination and stale pool heads are
`INCOMPLETE`, never a zero balance. Failed endpoints retain separate attempts;
their partial prefixes are not spliced into another source's scan.

The fetcher has no signer, wallet seed, PK, prover or transaction submission API.
Use replay and an isolated receiver process to authenticate the recovered state
and discover ownership. A complete fetch alone reports no recovered balance.

The recorded cold runs mount only this client, public descriptor/template, pinned
SDK, selected Node/system libraries, DNS/TLS files and fresh output. They do not
mount the operator archive, old bodies, local-check receipts, profile, backup,
private fixture, PK, prover or tests. The fetcher queried every discovered pool
input/output rather than sending private ownership hints to RPC.

This first implementation restarts a scan after a race rather than maintaining an
incremental verified prefix. Its liveness under sustained pool activity is not
qualified. Distinct contacted endpoints add availability/corroboration; their
operator independence and the underlying consensus have not been independently
verified. The original full decoded pages are local gzip files with hashes;
publication includes selected pool data and page identities, not unrelated bulk.
