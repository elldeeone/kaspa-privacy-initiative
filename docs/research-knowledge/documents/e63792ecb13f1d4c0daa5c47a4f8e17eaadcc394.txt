# W6 focused fix review

Date: 2026-10-18. Separate AI reviewer: `/root/crypto_composition_review`.

**W6 CLOSED for the reviewed offline saved-receipt profile.** The shared decoder enforces deserialize/serialize byte equality, both identified file-loading paths use it, and an independent public-only runtime regression accepted the original real CREDIT receipt while rejecting all three retained trailing-data aliases.

This is same-model/platform/host/backend source and CPU/runtime review, not external audit, a native total verifier/R13 proof, or full lifecycle/restore completion. No private inputs/backups or GPU were used.

## Reviewed exact inputs

The two source changes, documentation and author's bounded regression report were frozen under `canonical-receipt-inputs` with hashes in its manifest:

```text
9190d7290ac023e48e740bc51801c98d1a359e20b66e6ad1a40ebe20db96806d  wallet-host/src/proof.rs
bd22b18e2ca3cc4c6ea5786e5615968d85e7f5365668e4080917f96a320db678  wallet-host/src/history.rs
d389677f21682f0deec8bbf38e3f4d6c2600a50a9431469d8145e7406722dead  WALLET.md
eb16f8f73ec0ab26caa28cd0111d34d5a3e079d67f7d217a25eed4e6cba733a1  supplied receipt-codec regression report
```

Source paths are under `poc/private-payment/`. The actual rebuilt verifier binary was copied as a public artifact into that snapshot and hashed:

```text
a7bcf2acb7a8c31eeec1765417d5a7dc2948d6e36ec351926f83e9948a9258e5
```

That hash matched the author's regression report. The earlier counterexamples and their accepting source/binary identities remain preserved unchanged as historical evidence.

## Source disposition

`proof::decode_receipt(raw)` retains the existing bincode configuration, decodes a typed Receipt, serializes that same object with the selected writer, and requires exact equality to the original raw bytes before returning it. Thus no fixed-int/varint format migration was accidentally introduced.

`history::load_receipt` retains its raw SHA-256 pin check and then calls this shared decoder. The saved-file `"verify"` branch in `proof::run` now calls the same decoder before its existing verification controls. There is no duplicate permissive decode left in those two reviewed entry paths. The prover's own serialization, cryptographic verification predicates, current-state policy and frozen guest relation/image are unchanged.

The standalone fixture `verify` command still intentionally reads its local preparation witness to check case identities; I inspected that branch's call to the shared decoder without invoking it on private data. The public `verify-history` path exercises the same decoder through history loading and needs no private case input.

WALLET.md now accurately identifies canonical receipt framing and distinguishes public evidence verification from the private fixture-preparation check. Host-envelope rejection still belongs to this bounded harness language and does not become a total native ordinary-verifier invalidity proof.

## Independent public regression

I ran the rebuilt actual `verify-history` binary under `bwrap --unshare-all` with only public history/receipts/binary/system libraries mounted, network isolated, stdin `/dev/null` and PATH-only environment. Results are retained in `canonical-public-runtime/reviewer-report.json`.

| Case | Result |
| --- | --- |
| Original real 223,684-byte CREDIT receipt | Accepted; private/reserve remain 1000 synthetic sompi. |
| Original plus one zero byte | Rejected: `noncanonical receipt envelope`. |
| Original plus 32 bytes of 0xff | Rejected: `noncanonical receipt envelope`. |
| Original concatenated with a second full receipt | Rejected: `noncanonical receipt envelope`. |

For every alias, the control deliberately recomputed both its receipt digest and synthetic history pin, ensuring rejection came from the canonical envelope guard rather than an unchanged checksum. The original genuine receipt was unchanged:

```text
2f43a8b38919d68a53500911e8eac36d09ea187b4cb08ddcece32328dab81442
```

These runtime outcomes exactly match the supplied regression's intended results. I did not mutate or delete the original alias artifacts that demonstrated the pre-fix behavior.

## Remaining posture

W5 is closed by the separately reviewed unique-name copy fix. W6 is closed by this canonical decoder. W3 remains the documented nonblocking typed-helper precondition on validated paths. The first-credit public verification/admission and supplied isolated restore are supported by earlier reports; the complete three/four-receipt lifecycle and final restored-spend runtime controls remain pending.

External audit, native deposit authority/bootstrap/ordering, proved ordinary outer verification, refunds/payouts, terminal native drain and independently operated R16 remain unqualified. All reviewer writes stayed in this task folder; no repository edits, private-data access, funds, broadcasts, GPU activity, infrastructure changes, commits or pushes were involved.
