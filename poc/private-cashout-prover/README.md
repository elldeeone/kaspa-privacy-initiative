# Private owner-local cashout prover

ADR-0053 source template. It is **unselected**: setup rejects before reading a
shape or using randomness, and the cold client rejects before opening parameters
or a witness. The public template retains the historical AA domain literal;
only a fresh private trial source clone replaces it and installs reviewed trial
authority. No old/AA/S7 parameter file can be selected here.

The unchanged Auth528 circuit/SHA source is reused. The new private parser has
no fixture generator, witness serializer or witness logging. The original AA
package and evidence remain immutable.

The separate setup executable creates one fresh public parameter artifact,
serializes official Arkworks 0.6 uncompressed bytes outside Git and retains the
key for the three local rehearsal proofs. A transparent wrapper measures the
generator's actual finalized constraint shape without adding constraints or
synthesizing a second time. Its temporary CS retention costs measured RAM.

```text
kpi-private-cashout-setup session PRIVATE_SHAPE_JSON NEW_SETUP_DIR NEW_PUBLIC_PK
kpi-private-cashout-prover loader-only PUBLIC_PK NEW_PUBLIC_REPORT_DIR
kpi-private-cashout-prover prove PUBLIC_PK WITNESS_FD NEW_PRIVATE_OUTPUT_DIR
kpi-private-cashout-prover verify AUTH528_FILE PROOF128_FILE
```

After fresh setup, root selects the canonical public parameter manifest. The
cold client embeds its exact manifest/VK pins. It checks source/build identity,
complete owned parameter length/SHA256, official trusted-input decoding with
full exhaustion, checked extracted VK and actual query lengths. There is no
runtime expected-hash, manifest override or alternate-key switch.

`prove` emits `parameters-ready` only after all authentication, before opening
or reading the private FD. The wallet executes authenticated immutable software
bytes and matches readiness identities before reading its own seed backup.
It then sends exactly one `kpx3-private-action-witness/v1` request. A verified
proof produces only proof128/Auth528/VK328 and public provenance in a new private
directory. Fixed error codes and a fixed panic hook exclude private payloads,
paths and witness hashes. The process stops after one owner proof; it offers no
network service.

Mirrors can distribute public parameters without receiving owner witnesses.
Parameter/data availability, selected-node assertions and single-party setup
honesty remain assumptions. Neither loader tests nor a successful testnet
cashout establishes cryptographic security, general financial privacy, p95 or
fee qualification.
