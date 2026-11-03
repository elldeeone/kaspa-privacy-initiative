# One selected development prover

This is a separate loader/prover for exactly the new KPX2 development PK
already loaded by the fully checked baseline. It is synthetic `DO_NOT_FUND`
research. It does not replace the baseline, generate setup, accept another
key, verify native transactions, fund anything, or communicate with a node.

The expected typed selection digest, full PK length/hash, fixed VK328,
domain and payment source hashes are compiled into this program. The
selection file's exact digest is checked before JSON parsing. Its key path
is authenticated by that root-selected digest; an adjacent self-provided
manifest cannot change authority.

The key is read into one owned buffer. Its exact length and entire SHA256
must match before the only private unchecked decoder runs on that same
immutable buffer. It uses Arkworks0.6's supported trusted-input compressed
API, requires complete consumption, drops the encoded buffer, and checks
the extracted VK using the original fully checked library plus exact fixed
VK equality. All submitted proof/VK validation remains unchanged. There is
no generic unchecked flag or caller-provided expected key hash.

Compressed point square roots remain sequential; no speedup is claimed
before a measured result. The owned encoded buffer temporarily adds about
one GB. No 4 GiB wallet or R8 performance qualification is claimed.

From the repository root, build into a private target outside Git:

```sh
CARGO_TARGET_DIR=/absolute/private/selected-prover-target \
  cargo +1.95.0 build --release --locked --offline \
  --manifest-path poc/selected-development-prover/Cargo.toml --jobs 4
CARGO_TARGET_DIR=/absolute/private/selected-prover-target \
  cargo +1.95.0 test --release --locked --offline \
  --manifest-path poc/selected-development-prover/Cargo.toml --jobs 4
```

The unit tests use only tiny authentication inputs and the public VK and
metadata. They never load the full PK or run a proof. Runtime is separately
reviewed and released after source/binary/input freeze:

```text
kpi-selected-development-prover loader-only SELECTION_JSON NEW_OUTPUT_DIR
kpi-selected-development-prover prove SELECTION_JSON FIXTURE_JSON NEW_OUTPUT_DIR
```

`prove` uses the same strict JSON fixture schema as the frozen lifecycle
runner. Each output directory must be absent. Genuine proof bytes are
fsynced before the additional final fixed-VK check; failure reports and
already saved candidates remain in their own stage. Source bytes, selected
key and old evidence are never overwritten.

`report.json` separates metadata read/authentication, owned PK read, full
SHA256, compressed decode, encoded-buffer drop, checked VK extraction,
proving plus the library's internal verification, candidate fsync,
additional verification and final PK drop. CPU seconds/RSS/swap and owned
process cleanup must be measured by the external runner. Reported proving
time includes the original library's own verification. Disk/page-cache
conditions and changed concurrency prevent an unconditional causal speed
claim from a single comparison.

The exact PK is one fresh local development setup. Parameter honesty,
trapdoor erasure, accepted chain backing, privacy and recipient recoverability
are not established by this loader or by a passing proof. Full-key hash
authentication is essential: matching only the embedded VK does not
authenticate the A/B/H/L vectors.

See [source review and options](../../research/next-session/private-integration/proof-loading/LOADING-OPTIONS.md).
