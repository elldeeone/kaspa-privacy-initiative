# Fresh selected-HMAC proof experiment

Isolated ADR-0048 performance measurement for the exact-SHA/selected-HMAC
relation. The CLI accepts only the pinned public primary fixture and a fresh
output directory. It has no proving-key or matrix-loading interface.

Generate one fresh OsRng setup, keep that PK resident, make one genuine proof,
run the unchanged checked verifier plus an additional check, then serialize
the fresh PK with official uncompressed encoding. Source pins and actual query
lengths identify this new matrix construction. A raw matrix digest is not claimed.

The 4 CPU / 16 GiB operational allowance does not change the qualification
limits: whole-process peak at most 4 GiB and warm proof at most 10 seconds.
One observation is not p95, a whole wallet, native adoption or a security audit.
The funded TN10 trial, earlier candidates and all failed measurements remain
unchanged. Keys, executables and Cargo caches stay outside Git.
