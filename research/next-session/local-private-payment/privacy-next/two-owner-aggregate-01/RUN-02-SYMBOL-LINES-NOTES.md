# Run02 symbol-row decoding fix: source preparation

The selected run01 preflight stopped on the 645,386,729-byte `.sym`: its full
Buffer could be read with the earlier 1GiB guard cap, but converting that whole
Buffer to one JavaScript string exceeded Node's `0x1fffffe8` string limit.
The failure preceded the first C++ witness generation or R1CS check. Preserve
run01 and its failed source/record unchanged.

New `run-check-symbol-lines-02.mjs` derives from immutable large-symbols source
`6a3c84ef737cab6b46e1efd5723e6e93df5bd1807e36e2e04d1061736e910e83`.
Its only semantic change is scanning the already guarded Buffer for LF and
converting one complete row at a time. Remove CR only when immediately followed
by that LF, exactly matching the old `split(/\r?\n/)` boundary. Final rows
without LF and empty rows are still visited; the existing row regex, wire
bounds, private-alias rejection, name/order tests and all 29 R1CS criteria are
unchanged. No truncation, early exit, alias filter or guard bypass was added.

The new variant selects fresh `run-02`, records that identity and exposes only
check mode. Its prepare/case-generation CLI is unavailable. Root must copy the
exact selected existing29 input files, HANDOFF, selectors and five compiled
assets to that new identity, then select the new source/copy evidence before
checking. No recompilation, new owner, key, signature, generated fixture or
changed relation is needed or authorized by this note. The original preparation
functions remain unreachable from this variant's CLI.

The driver still requires the same selected CASE/COMPILED hashes, full ordinary
and CPP0 R1CS byte identity, zero outer outputs, 2091 exact public input symbols,
private-owner/child-out35 exclusion and actual public witness equality. All29
rows still require actual R1CS results. Same-state replay is an explicit expected
acceptance; no privacy/native/output-validity/recovery/fee claim follows.

The 1GiB Buffer cap remains; only whole-file string materialization is removed.
The8GiB RAM/3GiB scratch/30CPU-minute selected envelope remains. Root must account
for preserved run01 plus copied run02 and later positive witnesses. Nothing in
this patch edits the live financial runtime or its safety checks.

Pins:

- New source26145B: `38d9221e841567cdf61e0c0781a21ba05ec0814001f7dc13392f0fc3777f8f6e`.
- Exact base-to-new diff3577B: `09bf6fa62e8468d715b8c845351534b563c704bc594fffe7cd13505798393588`.

The independent wrapper reviewer owns one separately pinned pure Buffer/parser
control execution. Those small public-text controls import no driver, checker,
cryptographic runtime or compiled generator; their result is separate from an
actual run02 R1CS result. This author has executed no variant, WTNS generation,
R1CS check, compiler or runtime import. Source-only notes authorize no run.
