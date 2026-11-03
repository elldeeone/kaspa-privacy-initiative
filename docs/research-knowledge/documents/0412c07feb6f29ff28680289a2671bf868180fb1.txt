# Public packet and omissions

`PUBLIC-FILES.txt` is the exact owner allowlist for the new cache package and
this experiment. `MANIFEST.json` hashes its files except the two index files
themselves. It includes source/locks/public pins, both source stages,
conversion provenance, root selection, tests, resource logs, telemetry,
cleanup and the genuine public synthetic proof/Auth/VK.

Both large parameter formats, compiled executables and Cargo caches remain
local and are excluded from Git. Their original hashes and paths remain
recorded. Full original manifests therefore cannot all be rehashed from Git
alone. The converter's `/out/selected-development.uncompressed.pk` namespace
path maps to the local cache path recorded in ROOT-CACHE-SELECTION.json.

The prior compressed-loader package, binary and sealed packet are preserved.
The UNSELECTED cache source and both converter-stage binaries are also
preserved before the selection-only delta. Root's independently selected
cache identity is compiled into the selected new prover, rather than read
from a caller-provided sidecar.

Build and tiny-test instructions are in the new package README. Those tests
need no parameter file. Exact conversion or proof repetition requires the
retained originating PK or cache. A fresh random setup does not reproduce
the selected artifact; it requires its own instance and explicit authority.
Proof verification alone needs no PK: the unchanged payment library can
parse Authorization484 and check Proof128 under the published fixed VK328.

All witnesses and keys used here are deliberately public synthetic research
data, not a funded trial. No key/cache/setup erasure, accepted backing,
privacy, laptop readiness or general cryptographic-correctness claim follows
from these passing checks.
