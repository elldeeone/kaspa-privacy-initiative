# ADR-0048: Selected real/dummy HMAC circuit experiment

**Status:** Accepted for a separate offline equivalence/cost experiment.
**Date:** 2026-10-23 UTC.

The exact-SHA Ch/Maj candidate has a genuine four-worker proof at 11.17 seconds
and 4.009258 GiB whole-process peak. Both unchanged limits fail. Preserve that
first result. The active confirmed testnet trial and its matrices are unchanged.

In a new variant, select the real/dummy HMAC key and exact padded inner message
before computing one HMAC per input. Preserve the original real 76-byte and dummy
73-byte messages, tags, domain, commitment/seed, position/slot and HMAC output.
Both inner streams including the 64-byte keyed prefix occupy three SHA blocks;
their padding bit locations and final bit lengths differ and must be selected
exactly. Use established SHA compression from its standard IV without adding a
second finalization. Keep the outer HMAC and all canonical dummy/real constraints.
No hash, wire format, authority, value rule, requirement or native policy changes.

Independently review exact padding, Boolean selection and real/dummy known
answers before one frozen full synthesis measurement at two CPU / 3 GiB. If
satisfied and equivalent, a separately reviewed fresh setup and genuine checked
proof may measure four-worker latency/whole memory using the unchanged targets.
Never load an old PK into new matrices. Keep all failures, distinguish a single
observation from p95 and do not adopt the candidate in a funded instance. Fresh
keys, caches and executables stay outside Git. This is circuit implementation
research, not a cryptographic audit or proof of security.
