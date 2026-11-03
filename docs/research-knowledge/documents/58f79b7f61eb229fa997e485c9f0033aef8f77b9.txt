# ADR-0067 cached-chain review

2026-10-26 UTC. Working-source static review; activation controls and actual
cached replay remain separate evidence. Only guarded public source was read.
No private STATE, backup, plan, log, event or truth was read or hashed; no
network request, cached replay, proof generation or runtime-author edit occurred.

No confirmed financial safety blocker was found in the reviewed working source.

## Preserved boundaries

- Admission binds the actual first fully verified handoff `73ee6f11...e4d85ba5`,
  exact runtime/source closure and frozen old 57 sources, descriptor/profile,
  selected assets and parameters. Historical SDK scan reuse is explicitly local
  controller trust. The parent reviewer confirmed that the new caller selects
  the cache only from its protected STATE after a successful confirmation,
  with the first handoff explicitly admitted by Root. A public cache receipt or
  `--trusted-local-cache` flag is not an external attestation.
- An untrusted caller takes full SDK verification. The cached financial replay
  still verifies genuine founding Output proofs, every selected whole CASE with
  native Full/all-input checks, complete wallet history, exact amounts and actual
  payout effects. Component-only or cached JSON success flags do not replace
  these checks.
- Every old gzip is read against its admitted whole-byte hash. The final primary
  and final post-query page are trimmed at their authenticated processed frontier;
  previously processed post-query pages are promoted into the reusable prefix.
  New delta requests begin at the old post-query frontier. The new verifier
  checks exact copied-prefix records/fingerprint and scans every new primary and
  post-query header/input edge.
  The frozen full verifier (`ee718b03...b3ac02a1`) runs its same retained-page
  scanner over processed post-query pages before admission: every processed
  header is SDK hashed, every input outpoint is parsed, and watched live-point
  edges must be absent. Unprocessed final tails are trimmed. This does not
  claim full SDK transaction reconstruction for every unrelated transaction;
  selected pool rows retain that check.
- Admission explicitly checks the fresh domain in both Python and JavaScript.
  Local prior receipts must match the selected descriptor/profile, source,
  admission and baseline fetch. The cached verifier additionally checks its
  baseline-cache and trust-scope markers, and copied page paths must be canonical
  relative paths contained by the selected public bundle.
- Cached birth/frontier membership is checked freshly. Delta discovery occurs
  before final reserve/payout UTXO queries, so a previously live cached reserve
  may have been consumed by a newly accepted delta transaction. Post-query
  coverage, removed-chain rejection and final exact UTXO requeries remain.
- Source diffs preserve exact expected-CASE confirmation, native fee/preflight,
  two live input queries, durable global transaction/stage intents and one
  submission RPC. Only sibling cache admission/fetch/SDK calls are added.

## Required execution evidence

The pinned structural controls were independently rerun on a finite guarded
public-source stage: **8/8 passed**. They cover exact mid-page/end cuts, missing
boundaries, removed-page rejection, truncated group arrays and absolute,
parent-traversing or noncanonical copied paths. They do not cover all ADR-0067
admission, tamper, source/domain, overlap/cursor or current-view cases.
`CACHE-SYNTHETIC-INDEPENDENT-01.json` records this bounded result.

An independent exported-function suite also passed **17/17** using tiny public
synthetic transactions/headers, a fake RPC and the real pinned SDK. It covers
gzip/decoded-byte tamper, SDK byte-pin mismatch, overlap/gap/wrong cursor/empty
delta/removals/truncation/bad headers, wrong birth/stale frontier, substituted or
missing live points and final-requery changes. Its positive extends a mid-page
cached prefix to a successor after the old reserve is spent. A separate added
control passed that stitched synthetic result through the original full SDK
verifier and recovered the same two synthetic transaction IDs.
`CACHE-ALGORITHM-INDEPENDENT-01.json` and
`CACHE-SYNTHETIC-SDK-EQUIVALENCE-01.json` retain these results. These tests do not
execute a real cache/network or validate native/component proofs. Admission and
controller provenance controls are a separate parent-review result.

One additional exported-function negative changed a synthetic decoded witness,
recompressed the page and supplied its new correct gzip hash while retaining
the admitted decoded hash. `prepareBase` rejected the changed decoded bytes.
`CACHE-DECODED-BYTES-INDEPENDENT-01.json` retains this explicit byte-tamper check.

The first reviewed runtime manifest `c05a3db5...5cbc42c2` and admission
`ccf75037...ae1f435` were read with exact pins. All nine sibling sources match
the runtime manifest; the admitted actual first handoff has two transactions,
exact accepted CASE equality, the selected trial and fetch `7af4dff3...605e8`.
This checks selection correspondence, not a new cached replay.

A retained read-only acquisition diagnostic reports `WebSocket disconnected`.
The author moved synchronous prefix authentication/copying before connection and
before the fresh live frontier. The reviewed fix changes only
`acquire_cached.mjs` (`419d0f9a...8159ff9a`) and `fetch_cached.mjs`
(`40a47d63...1e8fffda`): live birth/frontier, delta and UTXO checks still follow
copying. A targeted independent synthetic control passed the explicit prepared
prefix through changed-head discovery and the original full SDK verifier.
`CACHE-PREPARED-SDK-EQUIVALENCE-01.json` retains that result. New runtime/admission
pins were verified by the parent review: runtime02
`30da3b8e...bf2e1be1`, admission02 `fd47c3f8...0d3db514`; only the two reviewed
order-fix files differ in the 68-member closure (parent report
`719dca63...659400bf`). A successful actual changed-head comparison remains
required; the first runtime manifest is superseded for this fix.

Before activation, the actual control must extend the admitted first handoff to
the newly accepted successor, rather than demonstrate only a zero-delta replay.
Compare complete history, liabilities, accepted whole CASE and fees with the
retained full result. Negative controls must cover changed gzip/decoded bytes,
absent/forged admission, source/domain/profile/SDK/anchor mismatch, old-page
tails, overlap/gaps, removals/reorgs and changed live outpoints.

The local controller/cache integrity and remote validating-node assumptions
remain explicit. External imports and final independent accounting must use
full validation. No cryptographic, consensus, general privacy, production or
fee-target qualification follows from this review.
