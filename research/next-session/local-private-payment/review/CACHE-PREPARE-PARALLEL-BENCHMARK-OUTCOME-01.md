# Public-217 preparation benchmark outcome

One selected run completed on 2026-10-26. Six independent, unchanged helper09
invocations prepared the selected 217-page corpus in **127.244 seconds**. The
historical serial preparation took **716.642 seconds**. This is an **unpaired
comparison** from different host-load moments, not a controlled speedup claim.

All 217 prepared records, the fingerprint and graph metadata matched. After
timing, all 217 golden and new files were freshly read through unchanged
helper09, checked against expected SHA/length and compared byte for byte.
The golden came from successful preparation before a failed acquisition; it
is preparation evidence, not accepted financial state.

Preparation plus post-verification took 792.640 seconds. The full outer command
took 850.614 seconds. Linux waited-descendant CPU was 822.187 user + 640.936
system seconds, including source preflight and post-verification. The parent
Node process used 5.739 CPU seconds in preparation; that excludes helpers.
No aggregate simultaneous-RSS claim is made.

No RPC, financial admission, live adoption or automatic retry occurred. The
Root-selected new full acquisition diagnostic remains serial. Existing
`cache.mjs`, `public.mjs`, runtime68 and admissionfd47 were not changed.

Evidence:

- `cache-prepare-parallel-benchmark-01/RESULT.json` — SHA256
  `073e9e0449d90e26e23c9157d98d29c27bb8ceacac2136198cb4340d43550d59`.
- `cache-prepare-parallel-benchmark-01/OUTER-COMPLETION.json` — SHA256
  `e682f080098904c163e91ad2cf9e7850f11c7ade55ec89fdcd6e1908510fe4c2`.
- Exact selection `79b9b0d48efd321514f6c5f5a6113a429146e3b9323ab19b5a015e7c317a585b`;
  execution proposal `faca70992c41b0a231bcd6bfcd674db7e0d2032e95ec226f6badf67a85534284`;
  Root GO `ad8c37be373cfb889a320985c808906737ebac23e8ae7264c548cb74d2b9a26d`.

Original corpus/output paths remain retained. A future fetch change requires a
separate source/profile decision; this result cannot substitute for cache
admission, accepted-history verification or native financial replay.
