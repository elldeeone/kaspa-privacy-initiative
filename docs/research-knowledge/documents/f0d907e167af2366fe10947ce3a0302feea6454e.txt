# Compiled static VK optimization: independent source review

Ruling: no material acceptance weakening found in the proposed isolated route,
conditional on checked host prevalidation of the exact immutable key before
guest build and an independently selected image identity. This source review
does not qualify a new fixture, execute a guest, verify a receipt or authorize
native settlement.

Reviewed in sibling `proof` worktree:

| Source | SHA-256 |
|---|---|
| `poc/two-v6-binding/common/src/compiled.rs` | `e9a0a279e84c0c3730155dbe356e9960b9431635893699910d6cdf758489c76e` |
| `poc/two-v6-binding/common/src/lib.rs` | `452448ba2bf69fbcae7ced74e89c79a06306050761d90eec5d9ef395282f782c` |
| `poc/two-v6-binding/common/Cargo.toml` | `5c266c04be35ed71fb0cf15bac5b9c8dd9866aaf1f6f68eb8f5902a5641b2799` |

The inspected source still names the original rehearsal as a source-review
placeholder. The intended later development key/domain must be frozen and
prevalidated before any resulting guest build. A new development instance
cannot qualify the old instance's missing same-anchor pair.

## Why the narrow optimization preserves the intended checks

1. `compiled.rs:19` exposes no untrusted key decoder. Its private zero-argument
   function uses only `include_bytes!` and fixed key/domain constants. On the
   ordinary host it calls the unchanged fully checked key path. In the guest it
   skips repeated static subgroup validation only after checking fixed byte
   length/hash; full consumption, byte-identical canonical re-encoding, three
   IC points and nonidentity conditions remain checked.
2. The alternate dynamic `ConfiguredResearchGate::with_trusted_key` constructor
   remains checked. The optimization is a separate `CompiledResearchGate` type
   behind `compiled-research-instance`, with no default feature enabling it.
   Witness bytes cannot select its key, key digest or domain.
3. `compiled.rs:80` removes the redundant `checked_proof` prepass, but still calls
   the unchanged accelerated `Verifier::verify_inputs` for every submitted
   proof. That helper enforces exact 128-byte proof length, checked
   curve/subgroup decoding, full consumption, canonical roundtrip, nonidentity
   A/B/C and exact public input arity before its pairing equation. Submitted
   points do not enter the unchecked static-key path.
4. `compiled.rs:91` reuses the same `Witness::parse_for`, `check_binding`, public
   projection serialization and journal constructor as the reviewed host gate.
   It neither substitutes a verifier-pair-only journal nor omits the complete
   public P binding, hidden bijections or multiplicity rules.

The precise precondition matters: image pinning by itself does not prove that
embedded key points were validated. Retain the host canonical/subgroup/arity/
nonidentity preflight result for the exact key bytes, plus key/source/lock/tool/
ELF/program/image identities before execution. The unchecked decoder must never
be generalized to supplied witness or caller bytes.

## Focused remaining qualification controls

For the newly frozen public development pair, compare generic and compiled
research gates: identical positive P/J, altered genuine authorization reaching
`invalid proof`, and malformed/identity submitted proofs rejected by the
compiled route. Error categories may differ because one redundant decoder is
removed; acceptance must not. Independently recompute all P/J bytes under the
externally frozen new domain/VK identity before interpreting guest output.

These are bounded compatibility and code-path checks. Accepted historical roots,
current spentness, reserve binding, receipt verification, native settlement,
recovery and privacy remain separate gates.

## Frozen development configuration follow-up

The engineer subsequently replaced the placeholder with root-selected fresh
public-test domain
`d47cb91ef9ac74dda71c7db1519381526c3dfac5f525b904f744b97a7df713bd` and VK SHA-256
`2a9acd1639fb7b454384c65fb317a139695f5a2cbb3ebd941dd13b5f6045a2f4`.
The updated module SHA-256 is
`58f2bd2786c6deff8915459ba334ffde5382dd15e04a9101f835b98858970c26`.
This reviewer independently compared compiled key bytes and host P/J pins with
the public fixture: all are byte-identical to the externally selected versions.

The new host source contains the requested focused equivalence control: generic
and compiled positive P/J equality, both-count mutation reaching actual
`invalid proof` on both routes, and malformed/identity submitted-proof rejection.
It additionally specifies exact native errors for all nine declared guest
mutations. This reviewer independently executed the already-built host test
binary: both tests passed in 0.02 seconds, without another build. The binary
SHA-256 is
`d347950782fb1a8cb2a380093bf5702d4f62dec75e146911d2bf1527bc6cb3d4`.
Exact stdout is retained in `compiled-host-equivalence-test.log`.

This independently confirms the generic/compiled host acceptance equivalence on
the fresh genuine proof pair and the focused negative controls. It does not
execute the guest's static unchecked-decode branch; its exact-key host-validation
precondition and later guest image/receipt identity remain essential.

The complete independently recounted P/J/input identities are recorded in
`DEVELOPMENT-PROJECTION-REVIEW.md` and
`public-development-fixture-recount.json`.
