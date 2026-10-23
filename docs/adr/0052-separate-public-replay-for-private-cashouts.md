# ADR-0052: Separate public replay for the private-cashout program

**Status:** Accepted for an unfunded, supplied-context compatibility experiment.
**Date:** 2026-10-23 UTC.

## Problem and source basis

ADR-0049's network recovery client supports Auth484/KPX2. ADR-0050 changes the
authorization, private payout and terminal commitment updates. A signer that
understands the new immutable script cannot by itself reconstruct that history.
Reuse the existing source-reviewed public replay/Merkle machinery and the
source-derived new native policy, following the current Kaspa and mature-protocol
comparison in `research/next-session/privacy-recovery/SOURCES.md`. No note,
ownership, proof primitive or old instance is changed.

## Decision

Create a separate `poc/private-exit-recovery` package and explicit
`kpx3-recovery-descriptor/v1` identity. Approve only the source-derived 24,417-byte
union, including State112 and exactly ten canonical domain32 push locations and
one VK328 push location. Reconstruct and compare the entire immutable program;
never accept a script merely because it contains the expected domain or key.

Import only hash-pinned old public state/tree, amount/context, note and framing
utilities. Do not mutate the old modules or their globals. Independently decode
Auth528 and bind its prior outpoint/state/reserve, fee, public payout and complete
destination script to actual native fields. Insert both sequential nullifiers.
Continuing transitions append two CMs; terminal transitions verify the declared
zero fields and preserve CM count/root while still inserting both nullifiers.
Preserve exact reserve accounting, script versions, covenant metadata and
current-head/competing-successor rejection.

The first input is explicitly `kpx3-supplied-context/v1`, classified
`OFFLINE_SUPPLIED_CONTEXT`, from the seven genuine-proof mainline native bodies.
Check all parent links, supplied contexts, public hashes, sparse-tree updates,
fees and payouts. Missing links, duplicated spends, changed destinations,
invalid terminal fields and conflicting successors must reject. Existing exact
native/proof results may be reused by byte/hash identity; a public-only parser
does not establish hidden ownership without proof validation.

## Evidence boundary

Return `complete:false` and `accepted_chain_backing:false`. Supplied contexts,
public development secrets and development setup remain assumptions. No network
headers, confirmations, availability or independent consensus are fabricated.
Do not add an RPC or broadcast path, read a seed or proving key, or change a
funded pool. The old fetcher and wallet do not accept this new descriptor. New
network discovery and separately owned private proving/signing remain subsequent
integration work; passing this experiment cannot close those product gates.
