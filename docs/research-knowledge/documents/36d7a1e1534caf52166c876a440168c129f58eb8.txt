# Serial checker source boundary

`check-serial.mjs` derives the selected Snarkjs 0.7.6
`src/wtns_check.js`, SHA256
`e150b29d1628a47e598ab7e85a46561f501c602d9599ad60b4923b5d6af4b456`.
Its upstream license remains in the copied file. The original constraint
loop and linear-combination evaluation/parsing are unchanged.

The explicit differences are source-module paths rebased to the selected
`tools` closure; `singleThread: true` passed to both `readR1csFd` and
`getCurveFromR`; and file/curve handles tracked, awaited and terminated in
`finally`. Added witness format preconditions require field width/count match
the selected R1CS, exact section byte length, and raw constant wire zero encode
integer one exactly before evaluation. These state the R1CS input contract;
no malformed-witness attack run or claim against existing financial code is
made. The installed upstream package is unchanged. No global cache or
module monkeypatch is used. Selected `r1csfile` header options forward
`singleThread`; selected Snarkjs curves and ffjavascript honor that argument.
Circomlibjs `buildBabyjub` and `buildPoseidon` also request single-thread mode.

The fixture has 49 result rows: 46 owner-input cases, two positive-witness
derived-limb mutations, and one checked SHA relation containing four padding
length vectors. The four SHA vectors share one actual R1CS check; they are
not four independent proofs or four independently checked witnesses.
The recipe marks mandatory actual-check rows. A generation-only rejection
cannot satisfy those rows; it remains a distinct observation for nine
degenerate point/zero-signature controls. Rejection of an overlapping negative
does not establish isolated coverage of one named constraint.

The owner subprocesses overlap while constructing a common fictional anchor.
Both exit before any witness check. This is fixture construction and a
signing-key handoff boundary test, not asynchronous-wallet/liveness evidence.
The child signing seeds are never returned or persisted; overwriting their
buffers does not establish host-memory erasure. The plain prover sees the
complete owner/NF/output/value map and all other proving material.

The selected `blake-hash` archive bundles a Linux x64 NAPI addon. Its normal
loader tries that binary first and falls back to JS on load failure. Its
117,680-byte binary SHA256 is
`7ad88c48b10b72df6c910a5cce06f93eb1aba70800850582cface0038abe004f`.
This is an unreviewed dependency binary, bound by the selected archive; no
source compilation or runtime loading occurred during preparation.

Source and JSON inspection only has occurred. No Node syntax/import check,
key generation, signature, compiler, witness, constraint check, setup,
Groth16/native/privacy proof or actual KAS operation was run. Root must review
the exact frozen source and dependencies before execution. Existing financial
profiles, 2% fee failure, active retry failure and model closure are unchanged.
