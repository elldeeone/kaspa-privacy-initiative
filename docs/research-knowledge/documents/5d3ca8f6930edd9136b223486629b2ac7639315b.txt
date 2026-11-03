# Native terminal permission claim cost

ADR0039 offline probe of unchanged vProgs `f9b84a8` permission/delegate emitters
through native `01b532e` Full validation. Only supplied public synthetic UTXOs;
no funding, broadcasts, proofs, private-note exit or continuing permission root.
All deterministic keys in source are public test vectors: DO NOT FUND.

`prepare NEW_DIR` emits native Borsh transaction/context bytes and a prospective
case manifest without executing the script engine or Full validator. `run
FROZEN_DIR EXPECTED_MANIFEST_SHA NEW_DIR` requires the independently selected
manifest, checks canonical identities, executes official Full and meters every
input. Frozen manifests, failures and original preparation remain separate.

The positive uses a 60M liability, 50M permission rent and an existing 100M
external P2PK fee coin, returning its change. Only 60M is claim principal;
external capital and returned rent do not meet the claim-funded target. The
source forbids paying a positive fee from those protocol inputs. Normal tree
minimum depth1/count1→0 is selected; continuing roots are correctness-blocked.

Dependency bridge: byte arrays cross the official emitter's upstream native
`9fdbaf1b` and selected Full native `01b532e`; no cross-revision Rust types.
No SDK host/guest/prove/CUDA feature is enabled. Cargo.lock pins both revisions.
Build offline with Rust1.95 and `cargo build --release --locked --offline --jobs6`.
Use a private CARGO_HOME/CARGO_TARGET_DIR. The task-local cache had the exact9fdb
Git object but no master ref; a local-only `refs/remotes/origin/master` was set
to the exact upstream-locked9fdb commit before offline lock resolution. No
upstream sources, global cache, or remote refs were modified.

Full consensus, metered input programs, source-adapted policy quotes, supplied
UTXO lookup and real relay/inclusion are distinct. Full alone cannot establish
global spentness or accepted ancestry of supplied roots. This probe is neither
a user lifecycle nor a privacy qualification.
