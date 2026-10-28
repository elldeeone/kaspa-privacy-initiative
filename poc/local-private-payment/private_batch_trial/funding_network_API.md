# Explicit new-profile public funding network route

Source and offline controls only. No RPC, mining, funding or transaction/block
submission was performed while implementing these files. Actual activation
remains held until the complete selected native rehearsal and root qualification.
Passing these controls is not financial readiness, independent consensus or
production-safety evidence.

## Reuse

- `bootstrap/miner.mjs` and unchanged `MiningJobs` supply SDK PoW workers, raw
  template preservation, nonce-only mutation checks and once-only block intents.
  The new miner parses the explicit new identity instead of relabelling the
  old domain/selection. Existing source is preserved.
- `collect_funding.mjs` supplies the own-coinbase/maturity1000 algorithm;
  `reconcile_ordinary.mjs` supplies exact output/old-input/DAA-depth observations.
- Generic `acquire.frontier`, `scan`, official SDK header/transaction codecs and
  Tor framing are reused. The old profile parser and old `discover` financial
  codec are never invoked for this new profile.
- The Tor bridge adapts the existing one-session bridge with exactly the two
  Root-admitted read-only wheel archives, `python3 -B -S` and explicit colon
  `PYTHONPATH`. No installed dependency tree, pycache, heavy executable or SDK
  copy is created. Existing ingress/chain files remain unchanged.

Identity is `kpb-three-owner-funding-identity/v1`, with exact trial UUID,
testnet10 genesis, D/ProfileID/pool/service, bootstrap/component/tail hashes and
three distinct owner P2PK scripts/SDK-derived addresses. `financial_readiness`
must remain false: this public identity is not an activation authority.

## CLI

```text
python3 -B funding_network.py OP
  --identity PUBLIC_FILE --identity-sha256 SHA --output FRESH_PUBLIC_DIRECTORY
  [--execute]
```

Default stages the finite namespace and writes `LAUNCH.json`, with **no RPC**.
`--execute` activates the selected operation, including read-only operations.
There is no automatic retry, rebroadcast or operation timeout in the launcher.
The Tor/SDK transport retains its existing bounded connection behavior; an
uncertain write is followed only by observation and read-only reconciliation.

| Operation | Additional inputs | Actual output under `--output` |
| --- | --- | --- |
| `anchor` | None | `RESULTS.json`: `kpb-GEN3-birth-anchor/v1`; fresh confirmed birth header/sink and five IDs. No funding/currentness claim. |
| `mine` / `plan-mining` | `--owner-component 0..2`, optional `--workers`, `--target-sompi` | Mining: `RESULTS.json`, schema `kpb-ordinary-TN10-mining-result/v1`; reward observations. Plan: `RESULTS.json`, schema `kpb-readonly-TN10-mining-template/v1`; one template observation and no submission. |
| `collect` | None | `OWNER-0.json`, `OWNER-1.json`, `OWNER-2.json`, each exact `kpb-own-mature-coinbase-observation/v1`; plus `RESULTS.json` summary. |
| `submit-consolidation` | `--owner-component`, `--case`, `--case-sha256`, selected `--fee-rate-sompi-per-mass` | `RESULTS.json`: `kpb-single-native-network-submission/v1`; RPC acknowledgment/unknown status and exact post-query, never confirmation. |
| `reconcile-ordinary` | Same exact CASE/rate/owner | `RESULTS.json`: `kpb-ordinary-output-readback/v1`; exact output, absent old inputs and DAA20. This is not a full accepted-prefix claim. |
| `submit-genesis` | Exact CASE/rate; `--component-profile`, `--tail` | Same once-only submission schema. Requires new GEN3 public predicates and fresh actual NativeFull first. |
| `confirm` | Exact CASE/rate, `--case-mode genesis` or `consolidation`; `--anchor`, `--anchor-sha256`; GEN3 component/tail when applicable | `RESULTS.json`: `kpb-fresh-accepted-whole-CASE/v1`; retained `pages/*.json.gz`, exact Full accepted transaction/witness/budgets/contexts, SDK/native identity and fresh current view. |

All activated operations also retain `LAUNCH.json`. Public outputs are under the
host directory supplied to `--output`; paths inside a worker's JSON may use
`/out`, which maps to that host directory. Detailed controller stdout/stderr and
plans stay excluded and are never body/hash inputs to the host controller.

`collect` emits exact string amounts/DAA only at the RPC observation boundary,
matching `funding_worker.mature_sources`. All arithmetic uses integer Python
sompi or JavaScript BigInt; booleans, aliases, fractional/negative quantities and
unsafe number coercions refuse.

## Submission and confirmation authority

Before submission or confirmation, the worker directly invokes
`funding_network_gate.py` in the existing public namespace. The gate checks the
whole canonical integer CASE, runs selected actual native normalization/ID/mass
and `validate-transaction` Full/all ScriptEngines, and enforces the exact native
mass/rate fee. GEN3 additionally validates its real new Output proofs, known
20-KAS zero-blind CVs, selected component/tail, three contributions/changes and
exact60-KAS initial state. No imported `accepted:true` or old report can skip
this execution. No PK or signing key is used.

The actual official SDK then reconstructs the whole transaction, recomputes its
ID, compares every canonical field, and performs safe-JSON roundtrip. The
trial/stage and global transaction-ID records are `O_EXCL`/file-and-directory
fsynced **before the first RPC** for a mutation. A fresh controller path or
trial label cannot resend an already reserved transaction. A source query
rechecks exact UTXO contexts and coinbase maturity immediately before the one
`submitTransaction` call. A lost reply never causes another write.

`confirm` uses a fresh generic Full accepted-chain scan from the selected birth
anchor, validates SDK headers and cursor continuity, and retains raw Full pages.
It compares the accepted whole transaction including witness, compute budget,
all supplied contexts and SDK-recomputed ID against the directly validated CASE.
It then queries actual outputs/old-input absence and rechecks the fixed chain
checkpoint for removals/reorg. GEN3 requires the exact live60-KAS initial reserve.
The recorded assumption is the selected validating node; independent consensus
is explicitly not proved. A txid-only or UTXO-only observation cannot substitute
for this confirmation route.

Unknown/incomplete statuses retain the consumed mutation identity and require
read-only reconciliation. They return a nonzero activation status. An RPC
acknowledgment alone does not make the funding head accepted or ready.

Successful ordinary reconciliation also exposes `RESULTS.output`, copied from
the fresh matched output-zero observation: outpoint, decimal `amount_sompi`,
`script_public_key`, decimal `block_daa_score`, `is_coinbase:false` and
`covenant_id:null`. This is the ordinary-source boundary for the GEN3 signer.
Submission and incomplete receipts record whether the sole submit call was
reached in `submission_attempted`. A crash without a receipt remains unknown;
it cannot authorize a second submission.

## Namespace and second-pass review

The public namespace mounts `/etc/ssl/certs` only, explicit read-only Node/SDK
files, selected public sources/parameters, two qualified wheel archives, public
CASE/identity and the owned once-only registry. It exposes no `/etc/ssl/private`,
Original, host home/SSH/config, wallet state, private intent, MPC share or PK.
Source/runtime pins and exact identity are checked before connecting. Source
files are frozen as small public copies; heavy runtime binaries/SDK stay shared.

Source review checked inflation/redirects through exact GEN3 contributions and
own-only consolidation outputs; duplicate spends through live input matching,
NativeFull and permanent once-only reservations; wrong state/profile through
five-ID/tail/CASE binding; unknown writes through one-send/requery behavior; and
dependency loss through fail-closed pre-RPC qualification. These tools add no
admin reserve withdrawal, privacy token, mainnet endpoint or legacy backup path.

Offline controls check identity/schema substitution, real maturity boundaries,
malformed amounts, foreign/duplicate sources, permanent phase/tx replay refusal,
direct gate invocation, one write after an unknown response, and changed source
rejection before submit. Real network-off namespace probes import the new
source/selected SDK, the public native-gate import closure and the two zip-only
Python packages with no private mounts.
Actual mining, new signed financial CASE, NativeFull positive, accepted-chain
acquisition and all terminal payouts still require their real later execution.
