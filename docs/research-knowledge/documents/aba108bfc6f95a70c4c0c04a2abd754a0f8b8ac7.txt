# Private scratch and fixed-size retained owner records

The fixed-width MPC handoff left signature JSON and full local records under
the host-bound `/owner` directory. Their decimal strings still affected file
length. This repair changes storage paths and framing, preserving all decoded
owner data and existing financial, signature and observer checks.

Signature inputs, raw/normalized witnesses, matrix/mapping artifacts, the
immediate owner-aux request and full JSON record now use a unique directory
on the existing namespace-local `/tmp` tmpfs. Pay and Exit consumers retain
those paths until their child tools finish. No new storage subsystem or key
is introduced.

The later one-colluder role needs the complete record. It therefore receives
`OWNER-LOCAL-RECORD-V2.bin`: exactly 32,768 bytes, with a 16-byte magic, owner
and private JSON length as u64LE, the unchanged canonical full JSON, and zero
padding. The fieldwise public schema maximum is 9,823 JSON bytes; its derivation
is in `PUBLIC-SCHEMA-BOUND.json`. This is a structural bound, not a sampled
private record or a financial witness. The decoder rejects wrong size/owner,
noncanonical or duplicate JSON fields, malformed/range-invalid fields and
nonzero padding. It has no bare-JSON fallback or public private-content hash.
The wrapper is persisted only after the existing owner-aux checks succeed.

Completed checks:

- Five focused schema/framing methods passed, including all three owner roles,
  full-field roundtrips, the public maximum, variable decimal widths,
  malformed framing, aliases, ranges, duplicates, padding and legacy refusal.
- The existing public known-seed colluder namespace test passed in isolation
  and after canonical installation. Actual CF decryption and NF/tuple joins
  remained intact; both rounds retained six joint candidates and three creator
  assignments. Its unused full-schema fields are explicitly public structural
  placeholders; it makes no financial witness claim.
- The actual stock signature generator and Node normalizer ran with the new
  private paths. Their 10,049-variable witness bytes exactly matched the
  prior qualified public seed00..1f control03 reference. Returned paths stayed
  under `/tmp`, and the host `/owner` directory stayed empty. This is a real
  normalizer smoke check, not a new AuthExit proof.
- A narrow source scan found no additional signature/decimal-dependent length
  in the reviewed successful lifecycle `/owner` writes. Exit private requests
  use pipes; retained candidates contain fixed-width projection/proof/statement
  hex. Invoice, handoff, record and study-truth shapes are fixed; auxiliary
  receipt dimensions depend on public source/role/context. This does not
  qualify broader timing, cohort or privileged-host privacy.

An initial public colluder test stopped during source setup because dynamic
support files were absent from its isolated copy. An initial normalizer smoke
stopped before its typed result because the copy lacked the public tree module.
Both negatives remain recorded; only unchanged support dependencies were
added. No raw normalizer diagnostic, actual Original/private record or blocked
corrupt-server recorder was read or invoked.

Before-change sources and their metadata exposure remain tied to checkpoint
`b1a7df20c30c178a8c81a4f66d1ce89287f121d5`; the exact functional patch and
before/after identities are retained here. Frozen studies and active Source05
were not modified. Runtime ELFs, full witnesses, proving parameters, actual
private records and raw logs are excluded from this evidence directory.
