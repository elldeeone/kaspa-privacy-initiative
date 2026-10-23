# ADR-0044: Loading one authenticated development proving key

**Status:** Accepted for an isolated offline performance experiment.
**Date:** 2026-10-23 UTC.

## Context

The genuine primary proof passed both checked host verification and the actual
native covenant. The retained checked compressed-key run took198.12 seconds
including loading/proving and peaked at5.41GiB. It does not qualify the4GiB
wallet limit or the CPU-laptop latency requirements. Arkworks already enables
parallel point validation, but compressed decoding visits points sequentially.
[Source inspection](../../research/next-session/private-integration/proof-loading/LOADING-OPTIONS.md)
distinguishes supported trusted-input APIs from unmeasured speed hypotheses.

## Decision

Build a separate selected-development prover for exactly the already checked
new key. Compile independently selected digests for its typed selection, complete
PK bytes/length, native VK, domain and circuit/library sources. There is no
caller-selected expected hash, alternate key or generic unchecked flag.

Read the PK into an owned immutable buffer; verify its exact complete length and
compiled SHA256 before calling the official compressed trusted-input decoder on
that same buffer. Reject trailing data, drop encoded bytes before proving and
fully check the extracted VK against the compiled native key. Keep all untrusted
proof/VK canonical, subgroup, nonidentity and arity checks unchanged. Native
verification remains unchanged. The supported unchecked PK decoder is private to
this authenticated identity boundary.

The byte authority is the independently frozen originating setup and completed
checked baseline, not an adjacent self-provided digest. An invalid authority pin
rejects; it never selects a replacement key. Hash equality does not prove setup
honesty, trapdoor erasure or circuit security. Those development assumptions
remain explicit and unreviewed.

Freeze source, binary, inputs and resource plan before one loader-only
measurement. Report read/hash/decode/VK/proving phases separately; no speedup is
assumed. Later genuine fork proofs may use the same reviewed helper after that
measurement. Do not change the baseline, key bytes, circuit, native policy or
closed source/result packets. An uncompressed cache is a separate prospective
artifact with its own provenance, hash and memory review; it is not selected by
this decision.

## Limits

This is a public synthetic DO_NOT_FUND instance, not a production loader. Root
and independent reviewers acknowledged the exact owned-buffer/compiled-pin
boundary before execution. The encoded buffer increases temporary memory and
compressed square roots remain. No R8, privacy, testnet, setup ceremony or GPU
claim follows from this optimization experiment.
