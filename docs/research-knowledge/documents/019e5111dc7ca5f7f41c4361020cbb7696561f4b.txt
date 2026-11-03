# Public view and local omissions

This packet publishes the selected prover's source/lock, public typed
selection and VK, prospective plan, exact build/source snapshots, tiny-test
logs, loader-only report, resource records and cleanup. The unused first
controller/freeze remains preserved. `PUBLIC-FILES.txt` is the exact owner
allowlist; `MANIFEST.json` hashes every allowed file except those two index
files themselves.

The 1,006,401,200-byte proving key, compiled executable and all Cargo caches
remain local. Their paths, sizes and original hashes are retained as
provenance, not silently rewritten. Consequently original full runtime
manifests cannot all be rehashed from Git alone. No source or data file in
the allowlist is a generated software executable.

The CLI can be rebuilt and its six tiny tests run with the commands in
[its README](../../../../../poc/selected-development-prover/README.md).
Those tests need no full PK. Repeating the exact loader requires the
separately retained root-selected PK bytes; source or VK alone cannot
regenerate that random setup. A fresh setup would require a fresh explicit
selection and does not reproduce this instance. There is no automatic pin
replacement or fallback key path.

Build snapshots preserve original README bytes and their original relative
link context. They are source subsets, not separate documentation trees.
The manifest maps the archived selected-prover README to its original
package path; its research-note link resolves in that original repository
context. Historical snapshot bytes are not edited to repair archive-relative
navigation.

The exact original metadata and full PK SHA authenticate this one fresh
development artifact after its retained checked baseline. Neither local
parameter honesty nor trapdoor erasure is proved. Passing this loader does
not establish accepted backing, privacy, wallet readiness, native runtime
acceptance or general cryptographic correctness.
