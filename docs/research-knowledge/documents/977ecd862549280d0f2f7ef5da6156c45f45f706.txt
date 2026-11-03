# Complete compact native policy screen

ADR-0056 authorizes this separate unfunded source/byte experiment. It does not
change the current Auth528 profile, circuits, parameters, wallet or trial.

`policy.rs` emits the complete common program, including ADMIT, revealing exits,
all native indexed-NF checks, compact/wide CM subtree paths, terminal omission,
self binding and two public placeholder VKs. `baseline_policy.rs` preserves the
reviewed old source verbatim for emitted-byte conformance. The stdin-only Rust
binary emits public bytes; it has no signing, proving or network operation.

The exact Auth528/wire format is in
`research/next-session/private-change/fees/WHOLE-EMITTER-SPEC-01.md`.
Read [OBLIGATIONS.md](OBLIGATIONS.md) before interpreting any result: private
ownership, note conservation, array distinctness and role-bound circuits remain
unimplemented for this profile. Every native runtime case must reject.

`fixture.py` constructs only public synthetic trees and invalid zeroProof128.
No note secrets, owner keys, prover files, setup, RPC or funds are used.
