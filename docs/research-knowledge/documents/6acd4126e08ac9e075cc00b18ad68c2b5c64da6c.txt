# Selected development uncompressed cache

ADR0045. This is a new version, preserving the completed compressed-loader
source, binary and evidence. It uses only official Arkworks0.6 serialization
and decoding. The original new-development PK, fixed VK, domain and payment
source identities remain unchanged; no setup or native policy changes.

1. `convert ORIGINAL_SELECTION NEW_CACHE NEW_OUT` authenticates the exact
   originating compressed PK with the reviewed same-owned-buffer full-hash
   loader, then uses `serialize_uncompressed`. It creates the cache without
   overwrite, flushes/fsyncs file and parent, streams a complete SHA256 from
   that file, and fsyncs public provenance. The provenance is evidence, not
   authority to select a cache.
2. The loader initially has `selected:false` compiled in and refuses runtime.
   Root independently hashes the cache and provenance and selects their
   exact identities. Only then are new compiled cache pins installed and a
   new selected loader binary frozen. The original converter source/binary
   stage is preserved before this selection-only delta.
3. `kpi-selected-development-prover-cache loader-only CACHE_FILE NEW_OUT`
   or `... prove CACHE_FILE FIXTURE_JSON NEW_OUT` reads the entire expected
   cache into one owned buffer, hashes it before the only private official
   uncompressed trusted-input decoder, requires exhaustion, drops the
   encoded buffer and fully checks the extracted fixed VK. Original checked
   proof/VK verification remains unchanged. No caller-supplied expected hash,
   alternate key, generic unchecked switch or metadata-sidecar authority.

The same strict DO_NOT_FUND fixture schema is used. It is not a funded
testnet trial parser. A fresh trial needs its own source/domain/setup and
explicit artifact authority. The selected development cache cannot serve
that trial. During fresh setup the same official uncompressed serialization
can be used directly while the newly generated PK is resident, avoiding
this development conversion's one-time compressed decode.

Build/test with Rust1.95 and the exact lock, offline, into a private target:

```sh
CARGO_TARGET_DIR=/absolute/private/cache-prover-target \
 cargo +1.95.0 build --release --locked --offline --jobs 4 \
 --manifest-path poc/selected-development-prover-cache/Cargo.toml --bins
CARGO_TARGET_DIR=/absolute/private/cache-prover-target \
 cargo +1.95.0 test --release --locked --offline --jobs 4 \
 --manifest-path poc/selected-development-prover-cache/Cargo.toml
```

The original 1,006,401,200-byte key and predicted 2,012,802,352-byte cache
remain outside Git. An owned cache buffer plus decoded PK temporarily
needs about four GB plus allocator/process overhead. Generous initial
14CPU/18GiB/swap0 bounds are a research allocation, not a four-core/4GiB
qualification. Read/hash/decode/VK/prove phases and external resources are
measured separately. No speed claim before actual measurement. Conversion
and all later stages are distinct frozen outputs; failures are retained.
