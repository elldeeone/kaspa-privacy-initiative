# Fixed-width owner file evidence

ADR0081 removes value-dependent decimal file length from the selected local
owner intake path. `KPB_OWNER_FR32V2` stores a fixed header and canonical Fr32LE
values. Each financial owner supplies 2,635,409 values in exactly 84,333,120
bytes. No text fallback, compression or private-content hash is published.
The network remains the existing TLS/V2/DDNNT protocol; the financial relation,
D/Profile and proving keys are unchanged.

Completed checks:

- The original 31 public controls compared the same old/new Fr vectors and
  checked malformed headers, aliases at P/P+1, role/count/size, permissions,
  links, EOF and deterministic file drift. Three complete public files used
  the actual financial count. Two selected public templates changed from
  133/285 bytes to 128/128 bytes; this is a file-size-only control.
- The installed canonical Rust writer and current C++ control passed the
  same 31 checks. Seventeen additional checks exercised the actual current
  public receipt and metadata functions, selected producer and versioned
  caller leaves. The unchanged outer path checker was stubbed only for
  preselected public test Paths; the routing test states this boundary.
- The canonical Cargo binary and shared writer fixture example compiled;
  the writer unit control passed. Cargo already contained the required
  `auth` dependency alias. Only the standalone candidate needed that alias
  added to its own manifest.
- A genuine three-party tiny MPC proof used two isolated clients, each
  mounting only its own new binary file. All parties returned the same
  128-byte proof. The independent verifier accepted public statement 128 and
  rejected 129. This tests the actual new reader with the existing protocol,
  field/group MAC checks and proof verification; its inputs were public 3/5.

The first tiny attempt refused a stale nested launcher source pin before
starting any role. Its typed refusal is retained. A fresh identity succeeded
without weakening checks. The final canonical producer was built from the
canonical crate sources; a final help-label correction names the binary V2
leaf and its selected ELF identity is recorded separately. Earlier candidate
artifacts and text snapshots remain local or in historical source evidence.

The reader's ancestor checks assume the selected flat, read-only `/owner`
namespace. They do not claim protection against races in attacker-writable
ancestor directories. No controller opened or hashed an actual owner input,
Original, TLS private key or raw MPC diagnostic.

The exact pre-control ADR bytes remain in `ADR0081-PRECONTROL.md`, matching
freeze04's a808f2a8… identity. `SOURCE-SELECTION.json` records final sources and
public proof/VK identities. Archived control sources refer to their original
selected Source05 context and compiled artifact dependencies; they are not
an independent reproducible-build claim. Full-size fixtures, runtime ELFs,
proving parameters, private records and raw logs are excluded.

This is bounded functional and metadata evidence. It is not a full financial
proof, native settlement rehearsal, payment privacy qualification or audit.
