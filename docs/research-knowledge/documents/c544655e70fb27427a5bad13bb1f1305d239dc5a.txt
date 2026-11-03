# ADR59 native wrapper and public body codec

This new package emits an unfunded receipt-verifying W template and independently
reconstructs its **424-byte journal / 8301-byte financial projection**. It opens
no private witness, backup or PK and executes no native VM itself. Runtime image
bytes must come from an independently selected compiled guest, not a request's
adjacent metadata. The compiled child profile is fixed separately.

Commands consume one strict JSON request on stdin:

```text
{"operation":"emit","state_hex112":"...","outer_image_hex32":"..."}
{"operation":"body","case":{"transaction":{...},"entries":[...]}}
```

The actual W always verifies the full standard RISC Zero compressed receipt
claim. Its compact private fallback uses the same child domain/original
positioned nullifiers and supports the reviewed no-append full-note cashout.
Source reuse does not establish actual W acceptance, currentness or recovery;
genuine receipt and direct-fallback validation remain separate gates.

`emit-oracle` emits a **distinct UNSAFE, DO NOT FUND hash-oracle template** for
public byte-codec diagnostics only. Its marker, immutable tail and P2SH identity
differ from W. A caller can choose its expected journal hash, so an oracle
acceptance proves no private authorization or financial security. It cannot be
selected as W, a funding target or a deployed financial profile. The actual W
contains no selectable oracle bypass.

The host [native gate](../shared-settlement/native_gate.py) first compares Python
and Rust codecs, then separately tests the actual W's zero-proof final-G16 seam
and unsafe oracle's unchanged-hash body mutations. Only a later genuine outer
receipt/native Full path can establish the bounded W financial experiment.
Supplied contexts still establish no accepted-chain backing or current head.
