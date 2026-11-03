# Current capacity cold source build

`coldbuild.py` authenticates the current HTTPS-restored 19-file source and
selected ELF, restores only 148 current Cargo.lock-pinned registry dependencies
from the immutable old public software archive, and compiles in a networkless
namespace with fresh Cargo state. `inside.py` is the fixed precompile check.

Run under a systemd user service with CPUQuota=400%, MemoryMax=6G and
MemorySwapMax=0. Arguments are the current HTTPS `assets` directory, the old
public `software-bundle.tar.zst`, its authenticated `SOFTWARE-BUNDLE.json`, and
a fresh output outside Git. No PK, backup, witness, proof, or wallet is an input.

See `research/next-session/independent-payments/current-profile-coldbuild/`
for selection, design, provenance and the retained result. Exact ELF equality
is required; a rebuilt mismatch never becomes selected software.
