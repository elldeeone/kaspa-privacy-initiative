# Selected public outer-proof stages

`outer.py` stages or runs one externally selected CPU/GPU operation. It never
creates background units or schedules a GPU. Root owns the execution queue.

```text
python3 -B outer.py execute|prove|compress|verify|native-proof
  --selection PUBLIC_JOB.json --selection-sha256 SHA256
  --output FRESH_PATH_OUTSIDE_GIT
  --exclude-private-directory /var/tmp/kpi-owner-private-lifecycle-01/private
  --exclude-private-directory EACH_RETAINED_OLD_PRIVATE_PARENT
  [--execute]
```

Without `--execute`, this only stages selected bytes and writes `STAGE.json`.
Root should review that file before releasing a real CPU/GPU operation.
`--execute` launches the stage immediately after preparation; it does not reuse
an older staging directory. GPU devices are exposed only for `prove` and
`compress`. The host uses the new `execute/prove PROGRAM PROJECTION OUTPUT` CLI.

The externally SHA-selected job is an exact object with fields:

* `schema`: `owner-private-lifecycle-outer-job/v1`.
* `domain_hex32`: `be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480`.
* `component_profile_sha256` and `image_id_hex32`: externally selected identities.
* `files`: exactly `host`, `program`, `journal`, plus `projection` for
  execute/prove or `receipt` for compress/verify/native-proof. Each value has
  exactly `path` and `sha256`.

The selection and its external SHA are authority supplied by the trusted
controller, never selected by a receipt or untrusted coordinator. The selected
host itself pins the real program/image/component and rejects development mode
and unresolved receipt assumptions. Verify reports lack an explicit image field;
for that operation the runner reports that it did not independently compare an
image report. Successful verification still uses the selected host's compiled
image identity and the externally selected exact journal.

Whole private parents are checked before the first selected-file read. The guard
tracks only private directory/file metadata, keeps inode exclusions monotonically,
and rejects private paths, symlinks, multiple links, nonregular files, replaced
files and mutations. All current lifecycle material and every extant historical
root-guard directory must be covered. Public copies are single-link files.

The unchanged historical helper is authenticated by SHA256
`da559335c0e071d15b7daee5cd4d256776295c934d5db569c1e13c3d2bf83195`.
Its public staging, minimal Bubblewrap command, process/resource accounting,
worker selectors and established compression constants are reused. The new read
boundary applies the stronger whole-parent guard. The worker namespace has no
host home, repository, wallet, proving key or network access. Scratch is fresh;
only public selected host/program/worker/input files are mounted read-only.

Compression authenticates **all bytes** of all four existing public assets using
streaming SHA256, then mounts those selected originals read-only. Metadata is
checked before and after the worker. Filesystem/host administration remain
trusted; this is not a malicious-host result.

Expected journals are exactly 104 bytes; mixed projections are 10,973 bytes.
Journal domain/component/projection-hash joins are checked before execution.
Produced journals are compared with the external expected bytes for every
operation except verify, whose host produces a verification report only.
The compression host report omits its journal hash; that operation still must
produce the exact externally selected journal file. The result records that
the additional report-hash comparison was absent for compression.

`RESULT.json` and `PROCESS-RESOURCES.json` retain the stage outcome and actual
process/device observations. No stage result establishes accepted backing,
native script acceptance, chain confirmation, recovery availability or privacy.
The included real-namespace test uses explicitly public synthetic executables;
it is isolation evidence, not genuine RISC Zero execution or proving.
