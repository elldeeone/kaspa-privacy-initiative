# Selected invoice V2 supplement

**Status:** root-selected prospective experiment after independent adversary
and privacy review, recorded in
[ADR-0042](../../../docs/adr/0042-separate-delivery-and-note-receive-fields.md).
This supplements the V1
[note/state contract](NOTE-STATE-CONTRACT.md); it does not rewrite V1 source,
freezes, 25-pass recipient result or privacy observations. Runtime/source freeze
for V2 is separate. Public synthetic DO_NOT_FUND credentials only.

## Exact difference

Keep root seed q, the selected D, derivation prefix, all existing roles and
native scalar rejection unchanged. Add the exact eight-byte role `b"INCOMING"`:

```text
incoming_i = HMAC-SHA256(q,
    b"KPX1DRV\0" || b"INCOMING" || D || u64LE(i))
delivery_secret = derive(b"DELIVERY", 0)             # unchanged
deliveryPK = crypto_box::SecretKey(delivery_secret).public_key()
O_i = SHA256(OWNER_TAG || D || s_i || incoming_i)
```

The note's incoming field is an opaque 32-byte PRF output, **not** a sealed-box
encryption key. The sender encrypts to the separate invoice deliveryPK.

| Invoice208 field | Offset / size |
| --- | --- |
| exact magic `b"KPX2IN01"` | 0 / 8 |
| selected D | 8 / 32 |
| unsigned u64LE index i | 40 / 8 |
| O_i | 48 / 32 |
| incoming_i | 80 / 32 |
| K_i | 112 / 32 |
| canonical x-only native PK_i | 144 / 32 |
| crypto_box deliveryPK | 176 / 32 |

This is V1's field positions plus deliveryPK at offset 176, with a new invoice
magic. O's bytes change because incoming changes. Reject old magic, wrong
length/trailing data, wrong D/profile and invalid supported key encodings;
never silently reinterpret Invoice176 as V2.

**Unchanged widths/formulas:** Note168 field order, receipt plaintext216 and
its `b"KPX1RC01"` magic, ciphertext264, State112, Auth484, private/reveal/native
field offsets, CM/NF hash tags, HMAC inputs and capacity/value rules. Receipts
carry i and Note168, not deliveryPK. The V2 profile/manifest authenticates the
invoice/derivation version because receipt magic alone does not distinguish it.
Native ADMIT and reveal publish **Note168 only**, never Invoice208/deliveryPK.
Genuine circuits continue treating incoming as opaque bytes; no new crypto
primitive or curve gadget is introduced.

## Construction and acceptance

1. Receiver derives s_i, k_i, native key, incoming_i and domain-stable deliveryPK
   from its pre-payment backup and produces the invoice. Sender authenticates
   the intended public invoice/profile before constructing the output.
2. Sender chooses V/rho, binds the invoice O/incoming/K/native PK into CM and
   seals the exact receipt216 to **invoice.deliveryPK**, never note.incoming_i.
   Sender output proof still does not know receiver s/k/native secret.
3. Receiver decrypts with domain-stable delivery_secret before learning i,
   rederives the V2 fields, and checks receipt/version/profile/domain, exact
   note/CM/position, amount and current unspentness. It must not parse incoming_i
   as a crypto_box public key or accept a sender-chosen authority commitment.
   Invoice validation compares all 208 bytes with the derived invoice. Receipt
   validation has no deliveryPK field: successful decryption and field/CM
   equality establish an owned usable receipt, not reconstruction of the
   sender's purported invoice or encryption choices.
4. Retain the V1 reuse-without-freeze policy and every positive liability.
   An unsolicited duplicate may change privacy classification; it cannot revoke
   existing ownership or user-controlled access. Restore uses an explicitly
   authenticated complete record/archive oracle, not a chain-acceptance claim.

## Scoped effect and remaining leakage

For distinct fresh indices, public ADMIT/reveal openings no longer contain the
same stable incoming/delivery key. This removes that **specific equality
channel**, conditional on HMAC behavior and correct construction. Absence of
byte equality is not a proof of sender, receiver or amount privacy.

Invoice holders/directories still see the same deliveryPK and may associate
multiple invoices with one recipient. Reusing i repeats derived O/incoming/K/
native PK and k; disclosure of k can expose matching positioned NFs. Public
ingress values, funding ancestry, timing, eventual revealing exits and known
counterparty information remain observations. Rejected/orphaned disclosures
are not erased by rollback or restoration. The adopted 21.0977% price-prior
failure and all ordinary financial-privacy targets remain unchanged.

Use a separately frozen V2 control set: fresh indices, reused index, same key
at distinct CM positions, wrong deliveryPK, encryption to incoming_i, wrong
index/profile/version, malformed receipt and later duplicate after valid credit.
Preserve V1 outputs. Passing parsing/derivation or equality controls does not
qualify privacy, durable data availability, accepted backing or a funded exit.
