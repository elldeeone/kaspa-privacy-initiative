# Descriptor-only network acquisition

**Both cold network acquisitions completed without the operator archive.**
The client discovered five pool transactions from one canonical founding output,
not a list of expected transaction IDs/stages. Both contacted endpoints return
the same canonical pool bodies, populated input contexts, full accepting headers
and eight current queried-point entries. This is the acquisition component;
replay and isolated backup ownership checks are separate workstreams.

## Actual input and trust boundary

The runtime mounts only the new fetcher, app-approved public policy template,
nine-field public descriptor, pinned official SDK, selected Node/system libraries,
DNS/TLS and fresh output. It does not mount the operator archive, previous bodies,
local-check receipts, profile, seed backup, private fixture, PK, prover or tests.
The descriptor selects public network/genesis/domain, initial policy/VK, founding
outpoint and pre-founding birth anchor. Its source/provenance is recorded in
[DESCRIPTOR-ORIGIN.json](DESCRIPTOR-ORIGIN.json). It is user-pinned pool identity,
not an independently authenticated global genesis-selection mechanism.

Descriptor canonical SHA256:
`434cefba486cf7d41afb44c0f538be898f93d4440bf70b1b40cbfaff4cfef1dd`.
The client accepts no payment amount, owner label, expected stage count,
snapshot or operator archive path. Generic reserve outpoint traversal discovers
founding, admission, private payment and two reveals. Ordinary funding preparation
predates the pool birth anchor and is not falsely counted as a sixth pool event.

The public endpoints assert synced/indexed TN10 version2.1.0. Their operator
ownership/independence and the underlying consensus were not independently
verified. SDK header/transaction hashing checks internal identity, not proof of
work, GHOSTDAG selection, acceptance-Merkle inclusion or permanent finality.

## Measurements

| Source | Controller wall | Node user+system CPU | Node peak RSS | Swap |
| --- | ---: | ---: | ---: | ---: |
| vector-10.kaspa.green | 97.405 s | 25.90 s | 973,816 KiB | 0 |
| electron-10.kaspa.blue | 114.656 s | 26.69 s | 977,140 KiB | 0 |

Each requested two CPU workers, 4 GiB cgroup memory and zero swap. Actual cgroup
peaks are 1,066,889,216 and 1,067,249,664 bytes; these include more than process
RSS. Both units are stopped, MainPID0 and empty. The runtime plans, telemetry,
GNU time logs and cleanup are retained in the respective `*-refetch-02` folders.
The source is frozen by [PRE-LIVE-FREEZE-03.json](PRE-LIVE-FREEZE-03.json).

Each primary scan traverses 251,330 unique accepted transaction IDs in sixteen
Full pages to its exact initially fixed confirmed frontier. Each then records
one separately bounded post-query Full page. Including that page, retained
decoded representations total **800,703,522 / 808,304,201 bytes** and their local
gzip captures total **106,631,480 / 107,922,683 bytes**. These are decoded JSON
and local compression sizes, **not measured wire bytes or bandwidth**.

This amount of unrelated-chain scanning for five pool events is a scaling
limitation. These uncontrolled-network, small-history observations do not
qualify the declared 10,000-operation/20-Mbit/s/15-minute recovery requirement.
An authenticated completeness-preserving public index or verifiable archive may
reduce acquisition costs; neither is supplied or assumed by this component.

## Integrity and failure checks

- Exact compiled app-template identity is authenticated before patching its
  ten D32 pushes and one VK328 push. Full initial bytecode must match; a
  descriptor cannot self-select another policy merely by hashing it.
- Headers retain expanded parent levels and native hexadecimal blue work;
  the reported cached hash is explicitly cleared before SDK recomputation.
  Every selected transaction ID is recomputed from its full canonical body.
- Scanning stops at one specific confirmed frontier, not at a moving sink.
  Premature empty pages, cycles, removals, missing founding, invalid headers,
  unknown SPK versions and insufficient depth are incomplete/rejected outcomes.
- Current queries cover each discovered input/output, including payouts.
  A nonterminal head must remain unspent. A post-query finite frontier scan
  checks removals/new confirmed head spends. Views remain non-atomic.
- Final source tests: **20/20 pass**. Five additional transport fault cases
  pass with mocked RPC and a requested kernel network namespace: unavailable
  preferred source, both unavailable, wrong network, pruned birth anchor and
  refusal to splice partial source prefixes. Mock consensus is explicit and
  never reported as live chain acceptance.

[CORROBORATION-01.json](CORROBORATION-01.json) compares the independently fetched
public results. It does not rerun native validation, replay, recovery or network
calls. The source child review separately authenticated all34 local decoded/gzip
page identities and the shared logical transcript.

## Retained corrections

The first code test exposed that old generic SDK JSON serialization wrote
`OptionalHeader.parentsByLevel` as `{}`. Those historical saved JSONs cannot be
rehash inputs. This client calls the supported `toExpanded()` before persistence;
a freshly fetched birth header now recomputes correctly after a JSON roundtrip.
SDK `getBlock` blue work is native48-hex, while OptionalHeader exposes a bigint;
both are normalized explicitly. SDK outpoints also require their supported
`toJSON()` rather than enumeration of WASM private storage. First 15/16 and
second 17/18 test failures remain recorded, alongside final passing controls.

Both first live wrappers exited127 before fetch JavaScript because the host Node
path is a CA-mitigation shell wrapper that invokes another absolute ELF path.
The second wrappers select that exact ELF and preserve `--use-openssl-ca` and
read-only system certificates. No TLS, identity, value or state check was relaxed.
Both failed runtime01 records remain; no transaction was broadcast or retried.

Actual `KPX2GN01` founding payload is536 bytes including D, Note168, CM, cipher
and cipher hash. The earlier finite-adapter prose saying no standalone D was
incorrect. The actual accepted bytes/native source remain unchanged and govern
the new parser; this work does not rewrite the historical packet.

## Publication boundary and remaining work

The selected `fetch.json` files retain complete pool bodies, headers, input
contexts, current queries, coverage and hashes of every bulk page. The unrelated
Full captures are preserved locally and intentionally ignored by Git. This is
an explicit export boundary, not an assertion that those raw captures are
downloadable from the repository. No fresh private seed/key or proving material
was read by this lane.

Missing/pruned data never becomes a zero balance. The known trace is already
terminal: it cannot demonstrate a newly recovered unspent liability followed by
a new independent exit. Sustained active-pool incremental catch-up, durable
post-pruning data, RPC observer privacy, independent consensus and full recovery
qualification remain open.

Primary API sources: [FullV2 bounded path and depth](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/rpc/service/src/service.rs#L1367-L1425),
[official header finalize](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/client/src/header.rs#L105-L113),
[compressed parent expansion](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/client/src/parents.rs),
[OptionalHeader getters](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/client/src/optional_header.rs).
Exact source hashes are in [SOURCE-API-PINS.json](SOURCE-API-PINS.json).
