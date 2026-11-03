# Exact live settlement of a prepared private batch

This adapter confirms one prepared new-profile transition relative to its
already admitted locked head. It does not reuse the old GN3 codec or infer
initial backing. It never signs, submits, mines, reads a wallet or clears a
history lock itself. ADR-0077 requires the history owner to launch the selected
adapter directly and consume its fresh result; an imported report is not
settlement authority.

The source implementation must refuse before network access while the genuine
component manifest or outer selection is unselected. A retained Full-page
bundle can be independently checked as evidence, but has no API that emits a
financial settlement result. The only success path starts fresh live acquisition
through the selected readonly Tor/Borsh worker.

## Source reuse

- `chain/wire.mjs`: pinned official SDK, complete header reconstruction,
  canonical transaction bytes/fields and populated Full input contexts.
- `chain/acquire.mjs`: generic fixed confirmed frontier, complete Full-page
  scanning, exact current UTXO queries and post-query reorg/race checks.
- `chain/readonly_borsh_observed_retry_strict_rpc.mjs`: selected readonly
  transport/source closure; five closed methods and no submit method.
- `private-batch-public/native`: selected new-profile body/projection and actual
  Native Full/input-engine checks.
- `private-batch-public/host`: aggregate plus six Output proof cross-check,
  genuine selected R0 receipt verification and native proof encoding.

Do not call old `profile()`, `descriptor()`, `discover()` or old pool replay.
New discovery starts at the exact locked input and follows `KPBAEF01` and
`KPBXEF01` only. The independently verified old/new state and native effects
must agree with every accepted successor. There is no old-profile success
fallback.

## Launch and result contract

The C++ owner authenticates the launcher, interpreter, selection and request,
then directly launches:

```text
python3 -I launch.py --selection FILE --selection-sha256 SHA256
  --request FILE --request-sha256 SHA256 --output FRESH_DIRECTORY
  --exclude-private-directory WHOLE_PRIVATE_ROOT [repeat for each root]
```

The request binds a fresh settlement nonce; history key, attempt and locked
binding; prepared effects/core hash; exact EGRESS core, aggregate-proof,
10,685-byte projection hashes and three sorted NF32 values; raw and canonical
whole FINAL-CANDIDATE CASE hashes; exact old outpoint/state/reserve; and selected
profile, component manifest, outer/image, parameter and R0 receipt identities.
All amounts remain integers in the native CASE; JS acquisition exchanges wide
integers as canonical decimal strings.
The canonical CASE digest uses sorted compact integer JSON **plus one newline**,
matching the new wallet/GEN3 public codec; raw file SHA remains a separate binding.

The C++ caller closes all inherited non-stdio descriptors before `exec`, uses
`/dev/null` for stdin, and captures only the fixed typed stdout/stderr contract.
MASCOT TLS/private-role descriptors must not reach the public process.

The guarded financial success contract is exactly one line:

```text
KPB_SETTLEMENT_VERIFIED_V1 NONCE REQUEST_SHA SELECTION_SHA BINDING_SHA CASE_SHA PROJECTION_SHA EVIDENCE_SHA ACCEPTANCE_ID_SHA
```

Every digest token is canonical lowercase hex32. The detailed public result is
`SETTLEMENT.json`; its SHA is `EVIDENCE_SHA`. The C++ owner checks every expected
identity, reads that exact file with stable descriptor/metadata checks, and
only then may construct an internal one-use settlement capability. It must not
expose a public constructor taking these tokens or an `accepted` Boolean.

Only the direct outer launcher can emit this prefix, after every fresh
acquisition and cryptographic replay check passes. There is no runtime
qualification switch. Its inner/offline commands emit evidence prefixes only
and retain `verify/REPLAY-RESULT.json`; they cannot write the final
`SETTLEMENT.json`. Imported JSON fields, including descriptive verification
Booleans, never authorize C++ settlement.

The source is a candidate for fixed compile-pinned registration. The actual
outer profile remains `selected:false`; no live financial qualification or
history resolution has been performed. Source review is recorded separately
from actual selected-profile integration in [SOURCE-AUDIT.md](SOURCE-AUDIT.md).

Requests use the strict `kpb-live-settlement-request/v2` schema. Version1 is
rejected. The durable policy pins are explicitly joined to actual bytes:

| Request field | Required actual identity |
| --- | --- |
| `native_policy.old_script_public_key_hex37` | CASE input entry script |
| `native_policy.immutable_tail_sha256` | SHA256 of the actual redeem after its114-byte state push |
| `native_policy.native_parameters_sha256` | Raw selected native parameter artifact SHA |
| `final_candidate.selection_sha256` | The same native parameter artifact SHA; distinct from launcher `SELECTION_SHA` |
| `final_candidate.image_hex32` | Selected outer image and actual codec/R0 verifier image |
| `final_candidate.journal_sha256` | Actual104-byte codec and verified R0 journal SHA |
| `final_candidate.native_proof_sha256` | Actual128-byte CASE witness and verified R0 encoding SHA |

All three servers independently run this selected live path. Their agreeing
acceptance identity binds the exact attempt/candidate/projection, selected
verification identities and actual accepting block. Individual acquisition
evidence can contain different observation timestamps/frontiers; those are
retained, not presented as one atomic view. A later private attempt separately
requires agreement on its own fresh exact head.

The outer launcher admits source/tool/data bytes through unchanged guard09,
then builds one independent readonly public snapshot. It executes three sibling
namespaces: network-disabled preflight, readonly Tor acquisition, and
network-disabled SDK/crypto replay. The writable snapshot alias is hidden.
Inner checks emit only non-authoritative evidence prefixes. The direct outer
flow authenticates their exact results, reauthenticates selected inputs,
synchronizes all fresh public evidence files/directories and the parent
directory, then emits the financial prefix. Traversal or synchronization
failure refuses export.
No private filesystem or whole home is mounted. Nested bubblewrap is not used.

## Checks before success

1. Authenticate all source/tool/public input bytes and actual selected manifest
   lineage. Keep private roots and signing/proving keys outside the public role.
2. Derive the candidate projection and journal using the real financial codec;
   match EGRESS, exact NF set, locked context/head and FINAL-CANDIDATE.
3. Acquire fresh complete confirmed Full pages, reconstruct headers with the
   official SDK, find the exact accepted CASE including witness, budget, mass
   and input contexts, and follow the selected pool's accepted successors.
4. Independently rebuild the accepted graph from retained page bytes; reject
   missing/duplicate/truncated pages, removals, conflicting spends, changed
   body/witness/context and mismatched SDK transaction IDs.
5. Run the selected host `cross-check`; run `native-proof` on the genuine R0
   receipt and require its proof128 to equal the accepted native witness; run
   actual Native Full and every input ScriptEngine on each replayed transition.
6. Verify exact current UTXO observations, a post-query confirmed delta and a
   second exact query, with selected-node identity and source/tool provenance.
   Only then write the result and success line.

The retained acquisition also includes the accepted producer of the locked
head, with its SDK-recomputed identity, full CASE and actual Native Full/input
reports under `locked-head-producer/`. For round one this is normally new GEN3.
Its genuine Output/CV/contribution admission remains the wallet GEN3 verifier's
separate obligation; this transition-relative adapter does not infer initial
backing from Native Full alone. `accepted-cases/NNNNN/` retains every payment/Exit
CASE, projection and actual verification reports.

An offline Native Full pass, changed head, independent Exit, txid-only match,
caller flag, stale/cached receipt or different witness cannot succeed. Reorgs
or uncertain acquisition refuse this observation. Previously released NFs are
never removed from history, including after a later reorg of genuinely observed
settlement. The trust scope remains a selected validating-node finite prefix;
there is no independent-consensus or continuous-currentness claim.

Actual qualification remains pending until the exact new selected profile and
adapter pass the complete live path. No source test or supplied-context fixture
can clear a financial lock. Fixed registration, genuine admitted GEN3 backing,
fresh direct launch and all-three durable agreement remain necessary.
