# Public two-actor producer recovery interface

This is an additive setup interface. Source freeze02 and its nine files remain
unchanged. `public_backup.py` writes the exact existing compact-batch seed-backup
schema for one known-public unsafe setup actor per process. It binds the backup
to that actor's already published initial and payment invoices before writing,
requires a fresh nonsymlink output outside Git, creates it with mode0600, and
round-trips the established backup parser. It prints neither backup bytes nor a
seed/hash. The backup itself has no actor label, output role, position map or
witness. This is setup only: no PK/prover, spend witness, native validation,
chain funding or currentness is created. Never fund these public seeds.

The recovery wallet receives one original backup and public authenticated
history; it must derive ownership without an actor label or an operator-selected
claim position. The development fixture is under
`/home/luke/projects/kpi-intensive-2026-10-22/adr59-public-two-actor-01/`:

| File | Public role | SHA256 |
| --- | --- | --- |
| `prestate.json` | Complete positioned public S0, R0 and constructed Q0 | `82ae8087adf61fd65cf20a539d10f446ee31f0f224aec5fcd87b99f0d62a08be` |
| `actor-0.json` | Initial public note/CF and invoice1 | `32d1a088eade3fb4a7118928ac617569bec955c72048427f0d0118ab26267ac4` |
| `actor-1.json` | Initial public note/CF and invoice1 | `4dad6e0038f091c7cfece1a4e4be0f316f70ff19d365737468d560b7a63fc628` |

S0 has CM cursor2, two deliveries at positions0/1, indexed NF sentinel m1,
R0=4,000,000,000 integer sompi. Constructed Q0 is
`976583fb0f7ed5a8670820df0f891065e2c895bae635f78092122f69cc2fcb8d:0`.
It is not an accepted UTXO, GN, deposit or backing claim.

`public_fixture.snapshot_record` exports exactly `{cm_cursor,deliveries,
nullifiers}`; each delivery has `{position,cm_hex32,cipher_hex264}` and each NF
record has `{value_hex32,next_value_hex32,next_index}`. `parse_snapshot` rebuilds
the public trees and checks the exact selected state112. A successful child
exports only `COMPONENT.json`, `SUCCESSOR.json` and public proof/report files.
The successor contains this complete public snapshot, reserve, state and the
canonical virtual body ID:0; it is not a native acceptance certificate. The
recovery lane must consume the eventual actual wrapper body/context and
independently selected current head, image and policy, rather than these
successor bookkeeping booleans.

Both crosspay requests are **net1,000,000,000 sompi plus a separately selected
positive exit credit**. The exact credit and F0/F1 wait for the actual new W
image/body quote; no amount default is used. Each call creates a positive sender
change. After both calls, each actor should recognize three historical own
claims: original2B spent, incoming invoice and sender change still actionable.
The producer selects its original own index0/value2B claim from a full own scan;
it does not require that this is its only owned claim. This fixture-specific
selection is not a general wallet claim-selection policy.

The selected child profile is `poc/shared-settlement-proof/child-profile.json`,
SHA256 `492a0981ad04891ea68243f2c8221976f436501acf940e42211bb8773744fbdd`,
child D `d55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb`.
Its manifest SHA is
`d6f0e2bbafab39a72106ef0a0ebd6483362a858926117721a8be5aa37a459011`.
The actual W guest image is selected separately by the runtime lane. Recovery
must not substitute an old domain/native program or infer acceptance from a
matching child profile.

A two-real-input same-backup noappend exit remains conditional on actual
relation/proof/native validation. If it is qualified, the existing KPX3PAY
derivation may anchor to the deterministic minimum consumed position, but the
payout nativePK must differ from **both** real input nativePKs. Do not silently
invent a retry/derivation rule. Otherwise retain four single-note exits.

This fixture tests new wrapper/recovery mechanics. Both actors already know
their own crosspayments, so a participant measurement may have zero unknown
third-party economic targets. Neither the setup nor two successful proofs would
establish anonymity or independent real-world demand.
