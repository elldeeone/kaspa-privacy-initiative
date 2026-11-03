# ADR-0045: Authenticated uncompressed development-key cache

**Status:** Accepted for a separate offline performance experiment.
**Date:** 2026-10-23 UTC.

## Context

ADR-0044's completed loader-only run takes 156.38 seconds, including 155.27
seconds in compressed point decoding. Its hash-before-decode boundary passes,
but skipping repeated validity checks leaves sequential square roots. Two
genuine competing-spend proofs spend about 24 seconds in proving and checked
verification after about 158 seconds loading. Their whole-process memory still
exceeds 4 GiB. The official Arkworks uncompressed format avoids those square
roots without changing the proof relation or verification key.

## Decision

Use a new package and binary, preserving the closed compressed-loader packet.
Convert exactly the already authenticated and checked originating development
PK with official `serialize_uncompressed`. Write a new file outside Git with
restrictive permissions; flush/fsync, retain the complete hash/length and record
originating compressed-key/source/selection identity. Never overwrite the source
key. This is a representation cache, not another setup or ceremony.

Before selecting a runtime loader, independently review the converter and its
provenance and rehash the complete derived file. Compile the selected exact cache
identity into a new binary. An unselected build refuses cache loading. No
caller-supplied expected hash, alternate-key selection or generic unchecked flag
is exposed. Read exactly the selected cache into one owned immutable buffer,
authenticate all bytes before official trusted-input uncompressed decoding of
that same buffer, reject trailing data, drop encoded bytes before proving and
fully check the extracted fixed native VK. Untrusted proof/VK and native checks
remain unchanged.

Freeze and measure conversion, loader-only and genuine proof stages separately.
Measure a four-core resource profile only after a useful cache-backed proof.
Keep CPU, wall, peak memory, swap and page-cache conditions explicit. Neither a
faster isolated load nor a 14-core proof qualifies a four-core wallet.

## Limits

The source-predicted cache is 2,012,802,352 bytes. Encoded plus decoded objects
temporarily increase memory; no 4 GiB claim is assumed. Cache and PK stay outside
Git. Independent artifact identity does not prove setup honesty, trapdoor erasure
or cryptographic correctness. No privacy, fee, network or testnet conclusion
follows from this performance experiment. A future fresh-domain testnet key
requires its own originating setup and identity; the public fixture's key is
never silently reused for it.
