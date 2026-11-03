# Auth528 public network recovery

This separate ADR0053 client supports the approved 24,417-byte Auth528 program.
Older frozen fetch/replay/wallet modules and completed packets are unchanged.

```sh
node fetch.mjs PUBLIC_DESCRIPTOR PUBLIC_MANIFEST NEW_OUTPUT --rpc WSS_ENDPOINT
python3 network_replay.py PUBLIC_DESCRIPTOR PUBLIC_MANIFEST NEW_OUTPUT/fetch.json NEW_REPLAY_OUTPUT
```

The application uses the exact ten-field
`kpx3-private-network-descriptor/v1`; its canonical sorted compact JSON SHA256 is
separately authenticated by the user. The small public parameter manifest is
canonical sorted compact UTF-8 JSON with **no trailing newline**, making its raw
and canonical SHA256 equal. Its D/VK/network/genesis must match the descriptor
and approved complete policy. Neither command reads the public parameter blob,
seed, backup, key, proving executable or operator archive/tree/profile.

Python API:

```python
network_replay.replay(descriptor, bundle, public_manifest,
                     output_directory=FRESH_PUBLIC_VALIDATION_DIRECTORY)
```

The optional directory preserves public SDK/native cases and receipts. Without
it, a new temporary directory retains those public checks. The caller never
supplies a validator callback or executable hash. Trusted application constants
select the installed Node and domain-generic native validator.

`run_live.py` supervises one root-authorized read-only acquisition with ordinary
SHA-checked trusted-release
Node execution, restricted public mounts, current system CAs, fresh output,
resource telemetry and final cleanup. It copies only public configuration and
source into the new stage; an optional controller release marker is not mounted:

```sh
python3 run_live.py PUBLIC_DESCRIPTOR PUBLIC_MANIFEST NEW_STAGE --rpc WSS_ENDPOINT
```

No actual RPC run is authorized merely by these instructions. The coordinating
root releases each fresh prefix/successor/terminal acquisition. `run_fetch.py`
is the sandbox entry and expects the selected Node mounted at `/node`. The
supervisor bundle is `NEW_STAGE/client-output/network-data/fetch.json`. Only
the initially empty `client-output` subtree is writable/mounted as `/out`;
controller plans, release markers, source snapshots and telemetry stay outside.

The read-only fetcher follows the founding output/input0 graph, scans to a fixed
confirmed frontier, retains Full pages and queries exact selected input/output
points. It recognizes Auth528 terminal topology, then watches every currently
unspent selected point during a finite post-query catch-up, including payouts.
Missing/pruned/truncated/reorganized/stale data returns INCOMPLETE, never zero.

Replay checks public manifest/policy identity, finite coverage and confirmation
consistency, all consumed/current/payout queries, exact live-point watch coverage,
and the frozen semantic adapter's Auth528 state updates. It separately executes
the pinned SDK to recompute actual transaction IDs and complete header hashes,
then runs fresh generic native Full and all input engines for every selected
body/context. No prior exact-case/native-result cache participates.

The frozen inner adapter's `complete:false`, offline context and unchecked-crypto
provenance remain intact in `offline_semantic_result`. A **new outer result**
reports the composition's observed network completeness and fresh local native
checks. Local native verification authenticates supplied contexts/proofs, while
the selected validating node supplies accepted membership/history/current view.
SDK header hashes do not prove PoW, GHOSTDAG, accepted-ID inclusion or consensus.

Fresh execution of local checks does not make an arbitrarily old bundle current.
The caller must acquire a fresh observation; output retains its checkpoint and
frontier. RPC views remain non-atomic and the root broadcaster rechecks the
actual spend point. Historical payouts may legitimately have a queried-null
current UTXO after a later ordinary spend. Terminal reserve zero requires the
actual valid terminal transition and observed consumption.

ADR0054 selects ordinary executable paths: exact SHA-checked 0500 Node/native
files in a private trusted release directory, mounted read-only in the sandbox,
with a fixed clean child environment. The host and release directory are
assumed immutable during use. There is no claimed protection from a malicious
same-inode host writer. Runtime code uses its own pinned source namespace,
avoiding a caller module collision. Shared libraries/base system remain trusted.
Earlier special-FD/loader probes and unexecuted selections are retained only as
historical artifacts after automated screening stopped that execution approach;
no active client imports or executes that route.

Public controls combine existing supplied Auth528 bodies with unrelated genuine
headers into an explicitly synthetic acceptance assignment. They test public
predicates, SDK hashes, mocked transport and runtime behavior, **not actual chain
acceptance or proof generation**. The Native ELF/PK/prover/backup are absent from
their namespace. Failures and corrected source/runtime receipts are retained in
`research/next-session/private-service-loss/network`.

This client does not prove setup soundness, durable history/parameter availability,
independent providers/consensus, general wallet recovery, financial privacy,+sustained active-pool liveness or 10k-operation/20Mbit/s/15-minute performance.
