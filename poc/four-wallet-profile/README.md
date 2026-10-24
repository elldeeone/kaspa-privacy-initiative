# Four-wallet testnet financial profile

ADR0060 source clones and one externally selected financial profile. The
profile is reusable across fresh trial identities; it is not a current head,
funding authorization or statement of cryptographic/privacy qualification.
No source under the earlier capacity/shared-settlement packages is modified.

The exact wire fields are in `selection.schema.json`. Python callers use
`selection.load(raw_bytes, externally_selected_sha256)` and obtain an immutable
`Financial` object. Important attributes are `domain`, `wrapper_domain`, `vk`,
`child_template_tail`, `w_tail`, `image_id`, `parameter_manifest_sha256`,
`pk_sha256`, `pk_bytes`, `build_identity_sha256`, `prover_sha256`, `codec_sha256`,
`private_budget`, `aggregate_budget`, `profile_sha256` and `executables`.
`document` is a deeply immutable view of the full parsed object.

The Python loader is authoritative for strict raw number types and cross-field
hash/metadata checks. JSON Schema documents structure; it is not a substitute
for the loader. The caller authenticates public paths against its backup before
reading them. `load_path` supplies basic public-only path/symlink checks and
does not have the owner's backup-alias context. Never let an untrusted capsule
choose this code, an executable, the expected profile hash or funding authority.

The source generator derives only the reviewed identity/path/selection changes
from exact historical Git preimages. Its map and complete unselected preimages
are retained under the current research phase. Both prover roles initially
reject before parameter access. Only compact2 is set up and selected; wide32
remains unselected. The virtual child tail has one fresh compact key and one
all-zero328-byte `UNSELECTED_WIDE_VIRTUAL_ONLY` slot. The guest accepts exactly
two compact mode2 children. Actual GN2 always funds the R0 W, never this virtual
template; zero key bytes never become a financial verifier.

Execution order after root/source review is: build unselected prover; construct
public unsafe shape requests outside Git; synthesize/finalize/check the new
matrix; fresh compact setup; install public pins and rebuild; derive virtual
tail/child profile; compile and independently identify the guest; build/derive
actual W; review the new complete-input meter bound; finalize the public
financial profile. Quotes, owner backup reads and genuine proofs follow that
selection. Root schedules CPU/RAM and GPU work separately.

`test_selection.py` exercises public structural fixtures. These are not valid
curve keys or financial programs and are never accepted as financial trial
artifacts. They test identity, immutable results, canonical types, complete
field sets, coherent hash tampering, real/oracle W metadata, role/key slots and
public path refusal before reads. They generate no proof or setup.
