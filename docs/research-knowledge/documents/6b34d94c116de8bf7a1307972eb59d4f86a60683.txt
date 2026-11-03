# Financial assignment qualification

`gate_main.cpp` is restricted to the fixed public, unfunded fixture. It opens
three previously initialized journals in a distinct **UNREGISTERED** epoch. It
has no journal initialization, reset, registration, settlement or funding path.
The production registered-service driver is not implemented here.

The actual path is:

1. Admit the stock compressed proving key, all matrix rows, selected trace,
   exact owner layout, native tail and independently derived prefix recipe.
2. Acquire the all-three durable LOCK before any owner listener exists. Each
   isolated owner reads only its own local auxiliary file and uses the existing
   TLS/V2 authenticated masked-input protocol.
3. Construct the complete authenticated assignment, retain all 33,896 private
   trace assertions, and add the 276 context byte checks. The fixed fresh
   qualification validates exactly 13,127,204 residuals before PREPARED.
4. Create the whole aggregate proof, independently verify it, and complete
   all-three durable EGRESS before the release object exposes core/proof bytes.

`run_financial.py` uses one kernel-sealed public PK memfd. Standard Unix
`SCM_RIGHTS` passes references to that same inode into the three isolated
servers. Each server independently checks seals, canonical decoded hashes,
stock frames, every curve point, VK and matrix bindings. Bubblewrap 0.11.1
cannot bind an anonymous memfd with `--ro-bind-fd`; the failed public control is
retained. No plaintext PK or trace dump is needed.

The controller never opens or hashes owner input bodies, TLS private-key
bodies or raw MPC logs. It reads only selected public source/parameters and
typed public stages/results. Only the fixed known-unfunded owner paths are
accepted by this launcher. No result from this component qualifies payment
privacy, an accepted deposit, native settlement, or a production service.

Build with `build_financial.py --vendor-root PATH --output FRESH_DIR --jobs 2`.
The build freezes the recursive financial/history/packed/trace source closure,
the decoder and the selected standard SoftSpoken vendor artifacts. Actual
execution requires the separately coordinated RAM/CPU window.

ADR0081 selects only `KPB_OWNER_FR32V2` owner files: a 16-byte magic, owner
and count as u64 little endian, then canonical Fr32LE values. Every financial
owner file has exactly 84,333,120 bytes. The selected leaf is
`OWNER-PRIVATE-INPUT-V2.bin`; the producer receipt is version2. There is no
text fallback, compression or public private-content hash. Historical text
controls remain under `controls/historical/` and frozen evidence.

Only an isolated owner/client reads its file. The controller checks metadata.
The client requires the unchanged V2 contract and exactly 2,635,409 values,
checks Fr<P before conversion and checks the opened FD again after EOF.
Ancestor path checks assume the selected flat, read-only `/owner` mount;
they do not promise resistance to races in attacker-writable ancestors.

The active C++ control takes two arguments: a public fixture directory and a
fresh malformed-fixture directory. Generate its fixtures with the relation's
`export_owner_fr32_public_fixture` example (same Rust writer used by
`owner_aux`), then run `owner_file_format_test PUBLIC_FIXTURES FRESH_CASES`.
Build this test with the same vendor include/defines and core link closure as
the financial client, replacing only its main translation unit. The controls
compare the retained V1 grammar to V2, check malformed files and parse all
three real-count public fixtures; they read no wallet/private record.
