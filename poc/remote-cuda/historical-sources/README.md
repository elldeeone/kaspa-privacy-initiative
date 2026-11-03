# Historical source qualification for fixed proof packages

The fixed lifecycle and recovery binaries predate the depth-four profile. Their
original source identity tables must not be compared with newer protocol source
and then silently repinned. Both original `package-identity.json` files, binary
archives, policies, program images, inputs and proof expectations remain unchanged.

The two archives here contain exactly the public source/input files listed by
those original tables: 54 lifecycle files and 109 recovery files. Each file
matches its original SHA-256. The [manifest](manifest.json) identifies archive
hashes and exact Git revisions used to recover eight older source versions.
Other selected files already matched their original hashes.

`historical_sources.py` independently pins each original identity file and source
archive, checks the complete allowlist and every file hash, and provides a
temporary source root. Package restoration still checks every selected source
hash, original binary archive and policy. Default `restore` continues to reject
current-source drift before creating an output directory.

Use `restore-historical NEW_PACKAGE` only for explicit historical replay or its
fixed-image preparation recipe. Its output labels the source binding historical.
It does not claim the old binaries implement the current protocol. A new current
binary/profile still needs its own build and qualifications.

The tests exercise both original packages, changed selected source, changed
identity/archive and unchanged default rejection. No setup, proof generation,
provider action or deployment is part of this source-replay repair.
