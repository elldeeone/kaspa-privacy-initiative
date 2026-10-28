# Owner-local authorization component

This active source continues the preserved October 27
[NativeAuthSpend specification](../../../research/next-session/local-private-payment/source-checkpoint-2026-10-27/native-authority/SPEC-03.md).
The original source and failed build remain preserved. The Rust predicate repair
adds only the two saved `ark_ff::AdditiveGroup` imports; the 21 frozen control
expectations are unchanged.

`harness/build_gate.py` and `harness/run_gate-03.py` take explicit fresh runtime
paths. `harness/prepare_execution.py` selects the command paths and freezes the
active public source without starting a compiler or a runtime. The build can
move the identified regenerable Cargo cache by anchored, no-replace rename;
it never copies/hashes that cache or modifies the failed build logs.

Before any owner or verifier JavaScript executes,
`harness/authenticate_js.py` compares every installed dependency file with its
exact pinned npm archive in a namespace containing public source/tools only.
It runs no install scripts or JavaScript. Archive root names may differ, but
each archive must have a single top directory and its exact archive/file bytes,
package identity and complete installed file set remain checked.

This component checks actual Native-style, signature and link matrix rows. It
does not supply a complete private payment batch, setup, MPC prover, delivered
output, accepted native transition, recovery or independent Exit. Those remain
separate integration work. Original runtime records and large generated files
remain outside Git.
