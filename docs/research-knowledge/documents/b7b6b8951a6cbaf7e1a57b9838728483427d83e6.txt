# Capsule API and independent control closure

Production reviewed/tested: `poc/recovery-portability/capsule.py`, SHA256
`88e13b484f9fd6c867a54b58610122ddc09693544f7a9ee20a1cd071737e4f56`.
The independent tests import this production module and invoke its public API
and CLI. They import no author test helpers and reimplement no production
acceptance predicate.

## Resolved interface points

- The externally authenticated `TrustedSelection` fixes instance/program/role,
  descriptor, compact manifest, PK and software inventory identities. The
  independently supplied capsule root selects the historical object index.
  A newly self-consistent capsule cannot replace static selection.
- The index always has five typed CAS references. Fixed `recognition` mode stages
  four small JSON objects and never requires the PK's existence or opens it.
  Fixed `spend_material` mode stages all five. Both statuses explicitly deny
  current-state, spend, native-semantic and selected-node-acceptance authority.
- `StagedCapsule.owned_json` contains owned small bytes; `staged_paths` points
  only to owned read-only copies. `public_receipt()` returns an independent
  sanitized copy. No CAS-provided executable or callback runs.
- Cold admission must pass own-backup metadata through `forbidden_paths` before
  any caller-selected manifest/object/selection read. Sources are checked by
  metadata before content-open and again by FD before content reads. The
  public-only default empty forbidden set does not authorize a cold wrapper to
  omit this guard.
- Capsule checks establish selected bytes and structural containers. The
  installed lifecycle consumer owns complete approved policy, sparse physical
  positions, valid lineage, native semantics, acceptance/current observation
  and actual compact-loader authentication before private witness/backup access.

## Independent execution

Latest controls: **13/13 passed**, 0.082 seconds inside the test process.
Production source remained unchanged. The test source is SHA256
`0a2c44d5e7131722b43473453e85363063d95480b71ae5f932122bf14dc8eddd`.

| Boundary | Independently observed result |
| --- | --- |
| Source/operator/cache loss | Recognition succeeds from the replacement public mirror after preferred mirror removal, with PK absent. Spend-material staging fails when required PK is absent. |
| Mirror corruption/availability | Exact selected replacement history succeeds after corrupt preferred history. All-mirror missing/truncated/same-size-corrupt/appended history fails without a success receipt or zero-balance result. |
| Outside authority | Wrong root fails before any object open. Rehashed object/index cannot replace static descriptor selection. Selected hashes do not waive role/D/VK/PK identity. |
| Currentness/code claims | Historical `SELECTED_NODE_ACCEPTED_HISTORY` text gives no node-acceptance/currentness authority. Added current/spend/executable fields are rejected. |
| Backup aliases | Manifest/history/PK/CLI-selection hardlinks to a synthetic non-seed sentinel are rejected before open when required. Recognition does not open or require the excluded PK alias. |
| Watch measurement | Kernel `IN_OPEN` was first positively calibrated through the same synthetic hardlink, drained, then observed zero production alias opens. This covers subprocess CLI opens as well as Python library access. |
| Owned copy | Staged read-only public bytes survive removal of both source mirrors. Mutating the returned receipt copy does not change the original receipt. |

The exact `--unshare-all` namespace command and source snapshots are retained in
[controls-03/SOURCE-AND-PLAN.json](controls-03/SOURCE-AND-PLAN.json). The child
reported a network namespace inode different from the parent; old operator and
SDK/cache paths were absent. Only two public Python source files and the base
system were mounted. The requested resource limits were one CPU, 1 GiB and zero
swap. No network request, SDK/native execution, actual PK decode/copy, proof,
backup, seed or private witness was used. The 54-byte opaque parameter fixture
is explicitly not an Ark proving key; VK/policy/body fixtures are deliberately
unverified public structure and must never be funded.

The first launcher attempt lacked host user-session bus settings and started no
tests. It is retained as `controls-01`. Restoring only the host user-bus settings
produced the unchanged-source 13-test `controls-02` pass. A second source pass
then added the positive kernel-watch calibration and reran the updated 13-test
suite as `controls-03`. No expected production outcome or implementation check
was weakened; earlier sources, logs and plans remain intact. Counts are not
added together as distinct new controls.

## Unclosed evidence

These are public transport/selection/alias controls. They do not validate the
new matched circuit, actual compact PK, Ark decoding, parameters-ready handshake
to a real owner, actual sparse-tree positions/NFs, financial conservation,
native acceptance, reorg/fresh UTXO handling or owner recovery. The deferred
semantic/current-view and actual-loader families in
[FAULT-MATRIX.json](FAULT-MATRIX.json) require the separately scheduled lifecycle
and owner integration. The existing genuine proof/native jobs must not be
duplicated just to increase a count.

Two directories/processes on this host demonstrate bounded source portability,
not separately operated providers, long-term retention or independent consensus.
The full compact PK remains required for compact proving; it cannot be recreated
from a seed or a new randomized setup if every matching copy disappears. The
explicit ADR0054 trusted-host/release integrity premise remains during use.
