# Local private-payment verification

Research implementation selected by ADR-0066 and ../SPEC.json. Native KAS is the
asset. This directory provides no wallet secrets, network submission, funding or
mainnet interface. Passing checks are bounded implementation evidence.

- `common` parses the KPXA one-Spend/two-Output public projection, verifies the
  indexed NF insertion and two CM appends, strict component proofs and CV balance,
  then emits the profile/domain/projection-bound journal104.
- `guest` runs that predicate in genuine RISC Zero 3.0.3. Its selected image is
  separate from every earlier aggregate image. Development receipts are refused.
- `host` cross-checks the independent Arkworks verifier, executes/proves the guest,
  verifies receipts and converts a verified Groth16 receipt to native proof128.
- `native` emits and reconstructs the actual dual-mode policy. Mixed payments
  verify the selected outer image. Direct full-note exits verify Exit152/G16
  directly; they do not require the outer prover or another owner.
- `native_case.py` constructs canonical supplied-context transactions and replaces
  only the financial proof slot. The default zero proof is invalid. Codec and
  mass reports explicitly confer no VM, backing or chain authority.

The public component profile selects fresh Spend/Output/Exit keys for the new
circuit-bound domain. `outer-selection.json` separately selects the compiled
program and image. The setup uses local OS entropy and has no independent setup
ceremony. Previous notes/pools/keys are not migrated.

`../execution/outer.py` stages pinned public-only R0 jobs in a network-isolated
namespace. `../execution/native.py` stages Native Full validation plus every
input ScriptEngine, with pinned component/image/VK, exact projection/journal,
explicit selected budget and fee rate. The actual fee must cover the selected
native mass quote. A direct-exit job mounts no outer prover, host or program.
Both launchers require every retained private parent as metadata-only exclusions.

The public frame fixtures in `common/tests/fixtures` intentionally contain invalid
CV/proof bytes. They test independent framing/tree/effects agreement and rejection
controls; they are never financial or Native Full evidence. Genuine supplied-
context execution, actual testnet confirmation, privacy qualification and
production safety remain distinct evidence boundaries.
