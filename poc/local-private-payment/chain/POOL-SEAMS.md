# Public offline pool seams

These new entry points keep the frozen cached financial runtime separate from
the selected public snapshot pool. They do not change Source57, Runtime68,
the cache admission, transaction checks, or the private controller state.

| Entry point | Host work | Offline pool role |
| --- | --- | --- |
| `confirm_pool.py` | Tor acquisition, exact accepted CASE comparison, payout observations, handoff and CACHE receipt | Unchanged `replay_cached.py` |
| `submit_pool.mjs` | Two fresh input queries, durable stage and transaction reservations, one submit RPC | Calls `preflight_pool.py` |
| `preflight_pool.py` | Public request construction and exported result binding | Unchanged `preflight_cached.py` |
| `pool_bridge.py` | Authenticates selected client, builds public input closure, checks export provenance and result | No new financial implementation |

All existing cached CLI flags remain. The new host entry points also require
`--pool-selection PATH --pool-selection-sha256 HEX`. The selected pool profile
pins its client, supervisor, fixed role entries, static public inputs, OS
closure and parent Runtime68/admission. It also selects the four new host
source files through outer provenance. It does not replace financial authority.

The bridge submits `kpxa-public-offline-role-job/v1` with exactly `schema`,
`role`, `argv`, and `files`. Each file row contains `source`, `sha256`, and
integer `mode` (256 for read-only data, 320 for executable input). Current and
baseline fetches enumerate both primary pages and
`current_view.post_query_delta.pages`, with canonical bounded relative paths.
The pinned cache admission also contributes its initial handoff as a data input.
The pool authenticates the declared file bytes before admission. The bridge
does not add a second gzip read before that admission.

Offline role arguments exclude RPC endpoints, journals, execute flags and
private-directory exclusions. No private controller, backup, seed, invoice,
plan, or private log is an input. The pool role has no network access.

An old role requires its output directory to be absent. The new layout therefore
uses a fresh pool-only parent and lets the role create its `result` child:

- Confirmation: `<confirmation>/pool-replay/result`.
- Preflight: `<submission>/pool-preflight/result`.

The exact absolute path is preserved inside the namespace and on export. Role
inputs and request files remain outside that parent. The selected supervisor
exports regular, single-link files and reserves `POOL-PROVENANCE.json` for its
own report. The bridge binds that report to selection, role, request bytes,
output path, exact stdout hash and `network: none`, then checks the exported
old RESULT or SDK candidate. It creates a fresh instance of the unchanged
public guard after the child exits so historical inode numbers from concurrent
private controller replacements cannot create a false alias rejection.

All native Full, genuine genesis, proof history, value conservation, nullifier,
fee, accepted CASE and current input checks remain in the old selected roles
and host submission path. A pool receipt is local execution provenance. It is
not an external cache attestation, current spend approval, independent chain
authority or proof of cryptographic correctness.

The prepared historical controls compare the retained control02 prefix to its
Source57 full replay and preflight accepted payment2 against its recorded
predecessor. Their scope is public offline byte equivalence. They cannot
authorize spending that already consumed input. Actual activation still
requires the selected genuine pool controls and Root release.

The public HISTORY, CONTEXT, CASE and fetch formats are unchanged. External
verification may continue to use the original Source57 full replay without
running a pool.
