# Actual owner integration: source and issued-scope review

Status: **source and actual issued-scope metadata ACK; execution not rerun here**.
Base `a6fcdf1edd904dbe1bb395285230649b6c40d44c`. No material source blocker found
in the reviewed integration. This file is supplemental to the sealed 24-path
fault packet; none of that packet was changed.

This pass read public source, the small public compact-role manifest and
issued operational/selection metadata. Private plans/configuration were inspected
only for mount/path provenance and were neither hashed nor published. No actual
PK, backup, witness, prepared private output or owner map was read or hashed.
No SDK/native/proof/network execution or old transport-control rerun occurred. The Rust parameter/native financial review
and root's execution authorization remain separately owned.

## Private-input order

Both [launcher](../../../../../poc/compact-batch-lifecycle/run_owner.py) and
[owner](../../../../../poc/compact-batch-lifecycle/owner.py) first apply the
own-backup metadata/inode guard to caller-selected public input paths. This
includes selection, descriptor, history, manifest, PK, prover and optional public
invoices before reads, hashes or copies. Fixed installed public sources/helpers
are also in the guard. Symlink components, nonregular files and an own-backup
inode alias are rejected. Metadata/stat is distinguished from backup contents.

The owner then checks independently supplied role/D/descriptor/manifest/VK/build
and prover selection, reconstructs/validates all supplied public history, and
starts the selected prover with an empty witness pipe. It requires exact READY
equality for event, role, arity, manifest SHA, D, VK SHA and build identity before
the first `receiver.backup` call. It constructs the private action only afterward
and serializes a witness into the pipe only after the actual-body quote passes.
The child inherits that data FD only; no executable-FD runtime is introduced.

The inspected Rust coupling supports this order: `parameters::load(role, path)`
selects the compiled manifest before PK access, authenticates complete owned
length/SHA before decode, exhausts input and compares extracted VK/dimensions,
then emits READY before opening the inherited witness reader. This is a source
ordering observation, not a newly executed loader or cryptographic test.

Ordinary selected ELF hashes/read-only mounts and the explicit ADR0054 trusted
host/release-owner immutability premise remain. No hostile same-inode writer
protection is asserted.

## Static authority and restored public handoff

The [portability controller](../../../../../poc/recovery-portability/integration.py)
keeps owner selection and the selected prover outside the capsule. The capsule's
software inventory inventories installed source/expected ELF identities; it does
not select an executable or import. Before owner launch, installed source hashes
are compared against that selected inventory.

After public retrieval, the owner receives restored descriptor, history,
parameter manifest and compact PK paths. Its selection and executable remain
the independently installed/controller-selected inputs. Original operator/cache
paths are passed as explicit absence probes, not mounted as data sources. The
full source-directory, configuration and operational path map are not client
inputs. Only the compact PK is needed for the compact owner; the wide PK is not
mounted by this launcher.

The materials client deliberately shares the controller's loopback network so
it can retrieve exact public objects from the fallback HTTP server. This is
same-host source portability, not network isolation or separate providers. The
owner namespace separately uses `--unshare-all`, including network isolation.
The two evidence levels must not be conflated.

## Namespace and private-output boundary

The owner launcher constructs a new namespace and fresh output for every call.
Its source specifies individual read-only public software/input files, one
read-only PK, the selected prover, and **one own backup** at `/own-backup.json`.
It mounts the dedicated client-output child directory writable; the parent
controller, configuration, source inventory/operational plan, other backups,
profiles, owner maps and previous private outputs are not mounted. Compact mode
rejects a public invoice roster; the initial wide payer may receive the intended
public recipient invoices, never the private backup/owner join.

The actual issued plans were subsequently inspected as metadata only. The
retrieval client has exactly five individual read-only system/code/selection/CA
mounts plus its dedicated writable output; it mounts no backup, prover, original
PK/source/cache, controller or mirror filesystem. It intentionally shares the
controller loopback network. The restored descriptor/history/manifest/PK path
roles match the expected owned-stage destinations. The public materials outcome
reports the exact selected compact PK length/digest and no private-input/proof
or currentness claim.

The issued first-owner plan has **24 read-only mounts and one writable dedicated
client-output mount**. It has exactly one own backup, a direct read-only restored
compact-PK file, four public JSON input snapshots, and the selected prover.
No invoice roster, second backup/profile, owner map, previous private output,
original source/cache or controller parent is mounted. Network isolation is
requested by `--unshare-all` with no `--share-net`; four explicit absence probes
include the original repository and original compact PK path.

All eight mounted public source snapshots were read/hash-checked against their
recorded identities and the reviewed installed source. The copied public owner
selection equals the external controller selection. Its role/D/manifest/VK/build
match this review, and its selected prover SHA is
`1662fcd9a5b90b8658e07aed2250a4c9c11d2390e80d7addae717090d63fb94d`.
The mounted prover path matches that external controller choice, not a capsule
path. The public descriptor/history/manifest snapshot sizes match the restored
capsule receipt metadata; their body bytes were not read/replayed by this
reviewer. The owner itself authenticates those public identities and exact
history before backup access.

The prepared entry reads the already issued command; it need not regenerate a
launcher or create a second proof. Requested limits are14 CPU,20 GiB and zero
swap. This ACK covers issued source/mount metadata and pre-read source ordering,
not a newly observed proof, actual kernel run, PK validity or financial result.
Root's public-canary/resource and execution-release conditions remain separate.
No private command/configuration/backup paths, plans or their digests are exposed
by this summary.

## Initialized GN, sparse state and supplied-context scope

[Preparation](../../../../../poc/compact-batch-lifecycle/prepare.py) creates an
ordinary synthetic funding/GN body and public descriptor/history. It does not
read owner backup bytes. `history.validate_genesis` explicitly checks the full
536-byte GN payload, D, note commitment/value, cipher hash, singleton roots,
actual emitted complete program, reserve output, founding point and ordinary
input/change structure. Ordinary-input native Full alone is not used as a
substitute for those bootstrap checks.

[History replay](../../../../../poc/compact-batch-lifecycle/history.py) applies
SDK normalization and native Full/all-input-engine checks to every supplied
body, including genesis, then reconstructs exact predecessor/state/reserve,
sequential NFs, ordered CM/cipher range and native outputs. Private records link
to the prior output's exact amount/script and the explicit input0 outpoint.

The sparse adapter uses aligned physical `start+i` positions. Starting at n1,
wide32 begins at32 and ends at n64; positions1..31 remain CM_EMPTY. Receiver
recognition derives each real NF from `delivery.position`, not a dense receipt
list ordinal. Subsequent compact appends preserve those gaps and physical cursor.

The history consumer accepts only
`SYNTHETIC_NATIVE_VALID_CONTEXTS_NOT_ACCEPTED`. Replay and owner outputs keep
accepted-chain/currentness false and label supplied synthetic context. This
pipeline cannot turn the capsule's historical flags into a live current balance
or spend authorization. A future live decision still requires separately joined
fresh selected-node evidence.

## Exact public compact manifest observed

File: `research/next-session/compact-batch/prover/parameters-compact2-01/public-parameters.json`.
It is canonical compact JSON with no trailing newline; SHA256
`f27a806928b5c2409d4e4c5428a75deabef6ecf9601b60889667e90363f26043`.

- Role `compact2`, output arity2, program `AUTH528_COMPACT_BATCH/v1`, Auth `KPX4AU01`.
- D `35ee940cae12aec848a773738de04feaef80c17798a686f1d5aa808179584fd6`.
- Declared public PK length1,307,894,256 bytes; its blob was not opened here.
- VK SHA `bf033abd75237c3f04f4b8ca19ef93c115b192d04eb8360b8d5060ccdb9bed78`.
- Build identity `8c6a5ab16aab7212cccaf6125f39363d94c854b824bd89ff1eb633f0bad7590a`.

The manifest identity observation does not independently approve setup honesty,
Rust relation correctness, the selected executable or native financial behavior.
Those are the parent's separate adversarial/release checks.

## Source identities

| Source | SHA256 |
| --- | --- |
| `owner.py` | `8d6a0bfedc9072039ad6a8d126af78ef2222274d8aa14b493c15968c6c2b1a49` |
| `run_owner.py` | `c620788d4f694ea25f4876c49a4f853d39224eef83e91501ad819796c2cc5185` |
| `prepare.py` | `d5ba604b3f18e45b0a92186702df990ff7ef5fb36063a8d52066d316ed01f916` |
| `history.py` | `b24f5712d16b75e5d1c33e6021e7f3e06e3bf180926af00f5ee01a09e1060202` |
| `primitives.py` | `184463d416a8e3c5605ce929bf2cead378c00e82d3827d30c83f8a6e19de5986` |
| `receiver.py` | `9733a7c97baaef3b91c70766007173c41d770e6f260fb7f0bf3116ad95c0665b` |
| `native_runtime.py` | `dac6d42987a9419864c967773677a033c143028053f33f5f6ad506739ef005af` |
| `integration.py` | `98d266b065e28e59677e0e039b3e858af40fd4be750102efa70e4188b4bd3413` |
| prover `src/main.rs` (ordering coupling only) | `707e3918036b448ca988670c4ca7ac7bfae57fded318396fbd2f0fea59e00ec8` |
| prover `src/parameters.rs` (ordering coupling only) | `d0558a12fc0882923758f5d521d6450879bc2ee8284d8bee153d1efa42e03acf` |
