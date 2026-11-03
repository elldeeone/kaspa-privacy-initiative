# Local-payment component relations

ADR-0066 research only. The standalone package/binary is
`kpi-local-private-payment-relation`; Rust import is
`kpi_local_private_payment_relation`. Default features provide host proving;
public verifiers use `default-features = false`.

The fresh compiled domain is SHA256, without newline, of
`KaspaPrivacyInitiative/local-native-kas-payment/1x2/v1/2026-10-25`:
`b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c`.
Spend200 uses `KPXASP01`, Output168 `KPXAOU01`, Exit152 `KPXAEX01`.
All three statements bind exact SHA256 bytes inside their relation using two
128-bit digest limbs. The fresh role keys are independently selected. Note168,
established KPX1 note/key/owner/positioned-HMAC-NF/tree algorithms, Pedersen
generator tables, canonical curve codecs, depth16, 60,000,000-sompi note floor,
10,000,000-sompi payout floor and MAX=2,870,000,000,000,000,000 are retained.
This source does not select, migrate or modify an old pool, seed, key or backup.

Spend proves hidden ownership, note membership, original NF and CV opening.
Output proves Note168 commitment, range and CV opening while binding CFhash.
Exit proves ownership, membership, original NF and exact integer
`note.value = payout + fee`, without a CV blinding. Complete statement effects
are bound; the caller still authenticates current state, reserve, NF insertion,
output append paths and actual native effects. Component proofs do not establish
current backing, settlement, privacy or independent data availability.

The CLI provides `public-info`, `commit`, `balance`, `shape ROLE`,
`setup ROLE FRESH_DIRECTORY`, `verify-spend|verify-output|verify-exit` and
`prove-spend|prove-output|prove-exit`. `balance` uses JSON schema
`kpxa-public-value-balance/v1`, arrays `input_cv_hex64`, `output_cv_hex64`, decimal
string `fee_sompi`, and canonical `delta_hex32`. It accepts up to64 inputs/outputs;
the local-payment policy separately enforces exactly1/2. `commit` uses schema
`kpxa-private-value-commitment/v1`, decimal string `value_sompi`, and
`blind_hex32`. Group balance alone is not integer conservation or proof validation.

Proof CLI flags are `--pk`, `--pk-sha256`, `--manifest`, `--manifest-sha256`
and public `--statement` hex. Verify flags are `--vk` hex328,
`--statement` hex200/168/152 and `--proof` hex128. Private witness JSON remains
stdin-only, strict object syntax with exact fields, lower-case fixed-width hex,
no duplicates, no extra fields and no private diagnostics. Schemas are
`kpxa-local-private-spend-witness/v1`,
`kpxa-local-private-output-witness/v1`,
`kpxa-local-private-exit-witness/v1`; field geometry is inherited unchanged.
The Spend/Exit fields are `note_hex168`, `s_hex32`, `k_hex32`, `position` u32,
and16 `cm_path_hex` siblings; Spend additionally requires `blind_hex32`.
Output requires only `note_hex168` and `blind_hex32`. Exit rejects blinding.

Parameter schema is `kpxa-local-private-parameters/v1`. External selection of
the complete manifest hash and complete PK hash precedes decoding. The CLI also
checks source, domain, role, curve tables and executable before reading stdin.
The selected local worker executable uses immutable mode0500 and exact-byte pins.
Library `keys::load` checks source/domain/role/curve/PK/manifest, while executable
identity is the CLI caller's additional responsibility. Whole-byte pins authorize
the inherited unchecked trusted-PK decode; a witness or embedded VK cannot
authorize setup parameters.

Fresh Groth16 setup uses private OS RNG entropy, never the public Pedersen seed.
This is a local research trusted setup without an independently administered
ceremony; toxic-waste destruction and dependency correctness remain assumptions.
Passing tests do not prove cryptographic correctness, composed privacy or
production safety. PKs and executables belong outside Git; source provenance is
recorded in `ORIGIN-01.json`.
