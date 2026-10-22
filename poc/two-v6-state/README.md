# Public two-v6 state assertion

**NONFUNDABLE synthetic experiment.** This separate guest verifies the unchanged
two-v6 pair relation, authenticates the common historical anchor against a
declared prior history root, applies four sequential indexed-NF insertions,
four CM appends and two odd-prefix history appends, and derives the successor
state and positive reserve after the aggregate fee.

It commits a new **336-byte journal** under a new image. The original P1088/J42
gate, images and receipts remain separate. The predecessor outpoint, state and
reserve in the guest input are declarations. Actual native context must
reconstruct the expected journal; this experiment does not authenticate accepted
genesis/history, backing, recipient spendability or independent owner exits.
The development inner proving key was discarded. Do not fund this instance.

The source/design authority is
[RFC-0018](../../docs/rfc/0018-paired-native-settlement-experiment.md), with the
core assumptions and framing in [common/README.md](common/README.md).

## Fixed statement

- Guest input: 11,219 bytes; predecessor/successor state: 105 bytes each,
  separate state discriminator `0x07`.
- Journal: `KPI2V6S1 || u16le(1) || SHA256(P) || pool_id || prior_outpoint
  || prior_state || next_state || u64le(R) || u64le(R')`.
- Pool ID: `ca2c2ab5087bc62965db817ed821a3898b255d06c789e7c20491afad88ca7756`.
- Selected image: `e9d7bd51e12b253c5cb7839d6854cf30d387dea95aff4e853feb47eb6d0edcf9`.
- Wrapped program SHA256:
  `d1336290bd4b8555edea9c5d7dd56aa4883f1d185b0a4aca9b08105b0537097a`.
- The same two public development proofs and fixed domain/VK are reused from
  [two-v6-binding](../two-v6-binding/README.md). Submitted proofs retain checked,
  canonical, subgroup and nonidentity validation. Only the exact immutable key
  uses the previously reviewed guest optimization, after fully checked host
  preflight and source/key/image selection.

Both independent public contexts use the genuine count-3 anchor. The current
context transitions n=3→7, while the historical context transitions n=5→9.
Both transition m=2→6 and R=1,700,000,000→1,620,000,000 integer sompi. Four
records retain their complete CM/ciphertext pairing and multiplicity. Public NF
sorting stays raw lexicographic; indexed-set comparison stays little-endian
numeric. Intermediate odd-prefix history roots are not settled reserve states.

## Recheck without proving

The independent fixture oracle lives in the integrated `public_state_oracle.py`;
its source hash and all expected bytes are pinned in
[public-fixtures/manifest.json](public-fixtures/manifest.json). The core does
not invoke that oracle or trust its verdict.

```sh
cargo test --locked --offline --release \
  --manifest-path poc/two-v6-state/host/Cargo.toml
cargo test --locked --offline --release \
  --manifest-path poc/two-v6-state/host/Cargo.toml -p kpi-two-v6-state
```

The host commands are `validate-key`, `wrap`, `host-check`, `check-target`,
`execute`, `prove` and `verify`; the latter commands select one of the two fixed
public contexts. Runtime execute/prove requires the compiled selected program
identity and explicit IPC worker, with development mode absent. Outputs must use
fresh directories. `wrap` derives an image and never declares it independently
trusted. The checked-key preflight precedes guest compilation.

`compress_state_retained` accepts only the independently selected historical
state Succinct claim, an externally expected receipt SHA256 and a fresh output
directory. It uses direct receipt compression, without guest execution.
`verify_state_compressed` performs software verification only, including the
exact successful claim/J336, Groth16 profile, no unresolved assumptions and
negative controls. Compression assets and tool versions remain task-local.

## Evidence

Build, selected-host, execution and genuine Succinct evidence are under
[evidence](evidence). Both genuine guest contexts and all 18 controls passed:
16 reason-specific semantic rejections, plus valid declared outpoint/reserve
changes producing independently expected changed journals. The authenticated
already-spent NF control rejects specifically at `NullifierOrder(0)`.

The historical receipt was compressed directly to Groth16 and independently
verified. The separate native checker accepted it in one synthetic transaction
context and rejected 22 exact controls; see [RESULTS.md](RESULTS.md). The public,
secret-free selected raw/wrapped guest is retained under [programs](programs).
Compiled host/prover binaries and multi-gigabyte official assets remain in the
task-local target, referenced by exact hashes rather than copied into this kit.

The original preselection host was replaced before an archive instruction
arrived. It was reproduced byte-for-byte from the exact frozen source/pin and
labelled **post-overwrite reconstruction**. Original freeze records remain
unchanged; [the archive map](evidence/build-archive/stage-archive-map.json) records
the separate original/preselection and selected artifact identities.

Passing these checks is evidence about these public inputs and implementations.
It does not establish cryptographic correctness, anonymity, native backing,
permissionless exits, a funded covenant or readiness for a testnet trial.
