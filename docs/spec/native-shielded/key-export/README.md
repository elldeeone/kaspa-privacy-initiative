# Reproduce the portable-key capture

The [key specification](../key-identity.md) defines the actual portable capsule.
This retained helper/patch is a diagnostic exporter, not a new verifier or native
key importer. Source authority and exact crate/file hashes are in
[the source audit](../../../../research/native-shielded-key-identity-sources-2026-11-04.md).

Read/check the committed public capsule without changing any file:

```sh
python3 docs/spec/native-shielded/key-export/check_capsule.py
```

The feature-gated [patch](diagnostic-export.patch) exposes read-only actual
parameters/VK/CS/domain data in **copied** Orchard/Halo2 sources. It also checks
the upstream compatibility scalar's historical derivation. It never changes
the original interop crate, its lockfile or dependency source cache. The
helper constructs no new proof: it re-verifies the three existing synthetic
complete bundles and checks their old diagnostic identity remains unchanged.

`Cargo.toml.in`, `Cargo.lock` and `main.rs` retain the exact helper. Source inputs
and official-crate/source comparisons have separate hash manifests. Reproduce:

```sh
python3 docs/spec/native-shielded/key-export/reproduce.py
```

Requires Rust 1.95.0, Python 3.12+, `patch` and Cargo dependency access or exact
cached dependencies. It checks the original Orchard commit and official locked
Halo2 archive checksum, stages fresh copies under ignored `.local`, checks patch
input hashes, applies only the diagnostic patch and builds a separate helper.
Capsule and provenance must match byte for byte. The helper re-verifies the
three existing public bundles without constructing proofs. The final rerun
succeeded; original package/cache and key diagnostics stayed unchanged.

The description text is provenance, not the portable encoding. The complete
canonical capsule and captured fixed scalar are normative draft data. Decoder
success is not proof soundness, key import, deployment approval or activation.
