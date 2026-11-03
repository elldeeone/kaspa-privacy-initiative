# Selected-HMAC method and checks

This isolated variant preserves both original nullifier formulas:

```text
real  = HMAC-SHA256(k,  NF_TAG || D || CM   || u32LE(position))
dummy = HMAC-SHA256(dk, DMY_TAG|| D || seed || slot_u8)
```

The existing constrained Boolean flag selects the key, tag, CM/seed and exact
padded trailer before hashing. HMAC uses the same padded key in its inner and
outer SHA-256 calls, following [RFC2104 section2](https://www.rfc-editor.org/rfc/rfc2104#section-2).
The original real message is76bytes and dummy message73bytes.

SHA-256 padding encodes the length of the complete inner stream, including the
64-byte ipad key block. This follows [FIPS180-4 section5.1.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
The full inner streams are140/137bytes, hence1120/1096bits. Both pad to192bytes:

| Inner last-block field | Real | Dummy |
| --- | --- | --- |
| Bytes0–7 | CM tail8 | seed tail8 |
| Bytes8–11 | positionLE4 | slot,80,00,00 |
| Byte12 | 80 | 00 |
| Bytes13–55 | zero | zero |
| Bytes56–63 | 0000000000000460 | 0000000000000448 |

Padding and length bytes are constants or Boolean selections. No padding bytes
are accepted as independent witnesses. A crate-private helper initializes the
standard SHA IV, compresses exactly these three blocks and serializes the state.
It does not finalize again. The outer96-byte hash uses normal finalization.
The prior reviewed Ch/Maj compression body is unchanged.

The two Boolean cases therefore compute the identical original selected result.
Unselected original HMAC outputs had no active public equality obligation.
Canonical inactive note/secret/path fields, flag Booleanity, target nonzero and
cross-slot distinctness remain enforced. Removing the inactive hash computation
does not remove these checks. Full circuit source after the nullifier seam is
unchanged, as recorded in the independent source ACK.

The14 passing cheap tests include:

1. Eight complete192-byte inner comparisons and original HMAC reference checks:
   both fixed slots, dummy, and real positions0,0x3412cdab,0xffffffff. The latter
   exercise all four little-endian bytes at helper level; circuit position bounds
   remain unchanged. Constraint shape is identical for witness flag values.
2. Four corrupted marker/length cases, checked as unsatisfied against the
   original HMAC digest; two invalid numeric2 selector assignments rejected by
   existing Booleanity; six invalid block lengths rejected before compression.
3. The unchanged64 Boolean allocation/value cases,15 SHA message lengths and
   eight baseline hash/wire/domain checks.

These checks provide evidence about this implementation change. They do not
establish cryptographic correctness, native acceptance, privacy qualification,
proof latency, total prover RAM or safe funded use. Existing parameter sets
cannot be reused because the matrices changed.
