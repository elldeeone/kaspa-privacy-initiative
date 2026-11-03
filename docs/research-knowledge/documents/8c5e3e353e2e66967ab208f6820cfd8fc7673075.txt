# Private change owner wallet (ADR0055)

This new client extends the closed private-cashout wallet without editing it.
Fresh instance/prover selections are deliberately **unset**. It cannot read a
real backup through the CLI until root selects the new domain, public manifest,
VK, build and cold prover. Source controls are not a live-trial qualification.

The accepted [contract](../../research/next-session/private-change/CONTRACT.md)
and [ADR0055](../../docs/adr/0055-recoverable-private-change-and-repeated-spending.md)
define this implementation. The existing circuit, native helper, public replay,
V2 receiver and fixed wire formats remain unchanged.

`change_wallet.py` reads one strict JSON object on stdin, schema
`kpx3-private-change-owner-request/v1`:

| Operation | Additional owner intent |
| --- | --- |
| `recover` | None |
| `prepare-partial-cashout` | `payout_sompi`: exact JSON integer, at least10M |
| `prepare-private-payment` | `payment_sompi`: exact JSON integer, at least60M; `recipient_invoice_path`: exactly208 binary bytes |
| `prepare-full-cashout` | None |

Common identity/backup/fetch/crypto/output fields and preparing-only public-PK,
local-prover, keyless-native-helper and fee-rate paths match the prior client.
No request accepts an input position, saved note/index map, witness, operator
profile, private recipient key, precomputed action or entropy/slot override.
The largest recognized actionable claim is selected, with position tie-break;
this is not aggregation or complete general coin selection.

Before caller-selected public file reads or hashes, metadata rejects symlinks
and own-backup inode aliases, including hardlinks. Public replay then checks
current accepted state. Preparing authenticates the local prover and its whole
public parameter blob/VK before backup bytes; its witness pipe stays empty
through quotes. The namespace and trusted host protect other private files;
the alias guard does not discover arbitrary secret copies.

Partial cashout fixes requestedP; positive own change is `V-P-fee`. Payment
fixes privateT; own change is `V-T-fee`, either zero or at least60M. Full cashout
has `P=V-fee`. Reserve always becomes `R-P-fee`. Requested value is never lowered
and subfloor change is never donated to fees.

Private payment first constructs a public-data sizing candidate with opaque
dummy output commitments/ciphers and exact current NF updates. It has **no
private witness field or serialization method** and is not a valid private
action. Its bytes, counterfactual NFs/Auth and quote remain private diagnostics.
After fee discovery, the client constructs legal real receipts and re-quotes
exact actual material. Any fee increase discards/rebuilds it. Only the selected
ActualCandidate may write a witness to the waiting local prover; proof
substitution must preserve the actual whole-body/context/rate quote identity
and pass Full/all engines. Cashouts retain the legal-material quote path.

Positive self-change uses an OS-random full-u64 V2 index, rejecting known own
historical indices/receive tuples, spent included, and the current recipient
tuple. The index, receive fields, rho and independent private input/output
permutations stay fixed through one prepare's quotes. Every changed plaintext
gets a fresh established SalsaBox seal. Own change is decrypted/rederived and
CM-checked locally. A fresh invocation samples anew. Dummy HMAC uses its actual
input slot; both NF insertions and CM appends follow Auth order.

Recovery decrypts the embedded index from retained ciphertext and rederives it
from the original backup; it needs no counter, lookahead or receipt map. Every
valid duplicate-positive claim retains owner authority. Known-history checks
cannot exclude unseen pending/orphan/concurrent invoices; freshness is
probabilistic over64 bits, not global uniqueness. Authenticated external
recipient derivation and valid public-key/encryption behavior remain assumptions;
Invoice.parse is not curve validation or a possession proof.

Public stdout/RESULTS and quote.json contain only final accepted native effects
and proof/software identities. Private payment/change values, receipt/index/slot
or payout associations, invoice/path data and witness hashes are excluded.
`OWNER-RECOVERY.json`, all native-sizing/native-actual diagnostic files and
operational paths are private and must never be recursively exported. The
client neither broadcasts nor automatically reveals notes.

The [source review](../../research/next-session/private-change/SOURCES.md)
records mature-protocol reuse and rejected map/counter assumptions. This PoC
retains selected-node/history availability, local public-parameter availability,
trusted-host/readonly-source/release-inode and encrypted-delivery assumptions.
Private change alone is not financial-privacy, fee, production or p95 evidence.
