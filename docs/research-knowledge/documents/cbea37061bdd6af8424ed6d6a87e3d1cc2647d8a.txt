Public-proof checker for the independent-payment settlement experiment.

`public_g16.verify(role, auth528, proof128)` authenticates the unchanged selected B05 ELF, copies it into a sealed executable memfd, and invokes its strict `verify` command with sealed public inputs. The old compiled manifest supplies the role VK. No request-provided VK, proving key or owner witness is accepted. A missing/wrong checker raises `CheckerUnavailable`; it is never reported as an invalid proof.

```sh
python3 -B poc/shared-settlement-verifier/public_g16.py compact2 AUTH528 PROOF128
python3 -B poc/shared-settlement-verifier/run_controls.py NEW_OUTPUT_DIRECTORY
```

The default binary is the existing outside-Git selected-owner-build05 executable. `--binary` may relocate those exact bytes; its expected whole SHA256 remains fixed. There is no new Rust build or proof generation. Linux sealed memfds are required.

This adapter establishes the selected private relation's cryptographic predicate. It does not establish NF absence, correct public root updates, a combined native settlement, backing or chain currentness. The public transcript consumer must check those separate duties. All checked fixtures are known public `DO_NOT_FUND` controls, never actual owner inputs.
