# Selected recipient V2 result

**27/27 checks passed in the first separately frozen V2 run.** This experiment
separates the stable encrypted-delivery key from each note's incoming field.
The receiver restores from an older seed backup, validates genuine sealed-box
receipts and reconstructs owner-controlled current witnesses. The experiment
does not confirm a native withdrawal or prove a private payment/backing history.

[ADR0042](../../../../docs/adr/0042-separate-delivery-and-note-receive-fields.md)
and the independently reviewed [V2 contract snapshot](V2-CONTRACT-SNAPSHOT.md)
select the prospective change. All original V1 source files and the [V1 run](REPORT.md)
remain byte-identical; nine frozen members also have exact copies in `source-v1/`.
V1's 25-pass result and its stable-incoming privacy failure are retained.

## Change and scope

`incoming_i = HMAC-SHA256(seed, "KPX1DRV\0" || "INCOMING" || D || u64LE(i))`.
This opaque note field is distinct for fresh invoice indices. The unchanged
domain-stable crypto_box delivery key is appended to a new Invoice208 with
magic `KPX2IN01`. The sender seals to **invoice.deliveryPK**, not note.incoming.

Note168, receipt plaintext216, ciphertext264, CM/NF formulas, native state and
Auth484 widths remain unchanged. Native admission/revealing openings contain
Note168 only, never the full invoice or deliveryPK. The full-invoice validation
API compares all208bytes against receiver derivation. Receipt216 omits deliveryPK;
receipt recovery checks its owned fields and decrypts under the derived key,
without pretending to reconstruct the sender's purported full invoice.

For distinct indices, this removes the V1 shared-incoming equality channel
between public note openings. It does not establish financial privacy. Invoice
directories and participating senders still see a shared deliveryPK, know their
counterparty, and can recognize invoices/notes they observed. Reuse, orphaned
disclosures, amount/timing/funding leakage and the existing privacy gates remain.

## Verification

The [eight-member pre-run manifest](PRE-RUN-MANIFEST-V2-01.json), SHA256
`60939f80ad7ce8f0587e107f973a9f22d1cca41f34d1dc45f616aa48aa05cca9`,
pins the V2 source/tests, unchanged Rust bridge source/lock and exact contract
snapshot. The runner verified every source hash before and after execution.
The existing binary hash stayed
`6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff`;
no rebuild or V1 semantic rerun was needed.

All original25 meaningful methods ran under the new derivation. Methods26–27
add substituted deliveryPK/full-invoice rejection, encryption to the wrong
note incoming field, strict old-invoice magic/length rejection, consistent V1
note rejection under V2 derivation and wrong external recipient-profile pins.
The test checks the actual Note168/Receipt216 exclude the stable deliveryPK.
All four pre-run independently reviewed witness guards remain enforced.

As before, later reused invoices receive no automatic new credit, every owned
positive position retains its liability/authority, and unsolicited reuse cannot
freeze earlier funds. Current spent NFs, missing archive data, wrong state,
malformed receipts and intermediate-root witnesses remain checked. The
[machine result](v2-attempt-01/results.json) and [test log](v2-attempt-01/tests.log)
record27methods, zero failures and zero errors.

Restored Bob again discovers positions0 and2, totaling360,000,000sompi, with
two independently reconstructed current witness sets. Alice's foreign receipt
is not credited. No service or exit-authorization input exists in the reference.
Both witnesses refer to the same static supplied snapshot and are not sequential
native transactions. The acceptance/archive pin is explicitly synthetic and
out-of-band; actual accepted backing, public-data durability and chain recovery
have not been established by this check.

## Frozen artifacts

| Artifact | SHA256 |
| --- | --- |
| [Public wire](v2-attempt-01/public-wire.json) | `b0281edaf4b43bca3685a4f097d2f9c38b29e99c5db0767a7286e539b6c1065d` |
| [Invoice directory](v2-attempt-01/invoice-directory.json) | `59183f1a1c9f1319a0b28a6314559793f2611acdcecbb9bfb53a8a8ae07016e4` |
| [Synthetic truth](v2-attempt-01/synthetic-truth.json) | `ddcfc23d090c007d15bfcbd8c51ca28bc19b6b5f53f63443eceae13c71f0da49` |
| [Cross-language known answer](v2-attempt-01/known-answer.json) | `5d262c459b6834b865a2ec758d5bcbcdc8f1fe172271cd3d379ddd9fb9a74ffd` |
| [Current witnesses](v2-attempt-01/reconstructed-witnesses.json) | `9571fcdd3d179d7ceda75c047cb3ecb0901af3bb3159b2a624227b76a456dcf8` |

The known answer includes the selected D, public synthetic seed, index7,
position0, derived credentials, Invoice208, receipt216, CM and NF. It was sent
to the proof/native workstreams for an independent language/integration check;
the recipient result itself is not such a cross-language result. Truth/debug
development secrets are explicitly separated from observer wire data. All are
DO_NOT_FUND fixtures, not deployable wallet material.

The V2 run used network isolation, a2CPU/2GiB cap and swap disabled. Actual
use was1.28s wall,1.29s CPU and34.0MiB max process RSS. Resource use and clean unit termination are retained in
[the resource record](v2-run-01-resources.txt) and [cleanup](CLEANUP.json).
No additional GPU work is needed for deterministic parsing/scanning.

The protocol still uses interactive one-time invoices. An authenticated profile
pin is needed because receipt216 magic does not distinguish V1/V2 by itself.
A seed plus accepted history cannot reconstruct orphan-only disclosure or
guarantee fresh issuance indices after rollback. Passing this suite demonstrates
tested reference behavior, not cryptographic correctness, production safety,
independent testnet recovery or the complete private-payment lifecycle.
