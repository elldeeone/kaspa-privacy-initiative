# Terminal public materializer source archive

[SOURCE-TO-COPY.json](SOURCE-TO-COPY.json) authenticates exact copies of the
[reviewed operator](materializer.py) and [source review](REVIEW.json). Its source
SHA is `d7cb421164a760b1bce41296e918e5feecf430d54e0af13059aa47ab00af3de7`.
This is source provenance, not an actual terminal HTTPS/unpack/replay result.

The operator joins Root's selected terminal INDEX to actual whole-object
transport receipts before copying explicitly selected public objects. It keeps
all fetch-relative page paths, uses only the newly fetched strict-unpacked63
software and codec, and separately authenticates the fetched `eaf2fd95…` closed
replay bootstrap. It does not fall back to an earlier payload store or mount an
owner, witness, proving key or shared R0 service.

The existing replay packet uses six inputs under `data/inputs/`, all original
relative main/post-query page paths under `data/`, and exact terminal H/C
expectations. Frozen replay passes explicit prefix `/data`; the earlier
owner-restore `fetch.parent` relocation workaround is unnecessary on this route.

These are Forge-side operational sources with the declared host guard. That
guard is not a downloaded-client dependency. Independent verification can use
the unchanged generic transport and standalone authenticated replay bootstrap
with its own private-directory exclusions. Root must first finish the actual
terminal scans/accounting, finite audit, upload observation and public selection.
The actual fresh HTTPS replay remains a separate execution gate.
