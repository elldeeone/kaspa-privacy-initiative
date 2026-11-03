# Candidate C recipient V2 and offline recovery reference

This isolated experiment tests deterministic recipient acceptance and witness
reconstruction. It does not replay a public ledger, authorize a withdrawal,
broadcast a transaction or prove accepted native KAS backing. It imports none
of the old wallet CLI, S7, DRAIN, replay or recovery-v2 paths.

Python uses only its standard library. The small Rust bridge calls the pinned
`secp256k1 =0.29.1` and `crypto_box =0.9.1` implementations. Real sealed boxes
protect receipt integrity/confidentiality for the intended recipient; they do
not authenticate a sender. Successful decryption does not imply spendability.

## Deterministic one-time interactive invoice

The backup is a 32-byte receiver seed saved before payment. With 32-byte domain
`D`, 8-byte role and invoice `i`, derive:

```text
HMAC-SHA256(seed, "KPX1DRV\0" || role8 || D || u64LE(i))
roles: "OWNSEC\0\0", "KSECRET\0", "INCOMING", "DELIVERY", "NATIVE\0\0"
```

`s` and `k` use the actual invoice index. The native role appends `u32LE(retry)`
starting at zero; reject invalid secp256k1 scalars rather than reducing modulo
the group order. `DELIVERY` always uses index zero, so the domain-stable delivery
secret decrypts a receipt before the receiver learns its encrypted invoice
index. There is no public invoice-index tag or unbounded restore lookahead.

V2 preserves the complete V1 source/evidence and changes only the receiver
descriptor/discovery separation. The 208-byte invoice is:

```text
"KPX2IN01" || D32 || index_u64LE || O32 || incoming32 || K32 || nativePK32 || deliveryPK32
O = SHA256("KPX1OWN\0" || D || s || incoming)
K = SHA256("KPX1KEY\0" || D || k)
```

`incoming` is the opaque per-invoice HMAC output using role `INCOMING` and the
actual invoice index. `deliveryPK` is the domain-stable crypto_box public key
of the separate delivery secret. `nativePK` is the 32-byte x-only secp256k1
public key. The sender gets these public fields,
adds integer sompi `V` and 32-byte `rho`, and constructs the candidate note:

```text
CM = SHA256("KPX1NOT\0" || D || O || incoming || u64LE(V) || rho || K || nativePK)
NF = HMAC-SHA256(k, "KPX1NF\0\0" || D || CM || u32LE(position))
```

The 216-byte sealed plaintext is `"KPX1RC01" || D || index || note_fields168`;
crypto_box seals to `deliveryPK` and adds its standard 48 bytes, yielding a
264-byte ciphertext. Neither Note168 nor Receipt216 carries `deliveryPK`. The
sender never receives `s`, `k` or the native signing secret from this API.

This is an interactive one-time invoice experiment, not an asynchronous private
address design. Domain-stable `deliveryPK` links invoices observed by directory
observers and participating senders. The separate per-invoice `incoming` removes
the earlier shared-incoming equality channel between distinct revealing
openings. Participating invoice holders can still recognize matching openings;
reused indices, metadata observers, orphan-only published secrets, pruning,
archive censorship and complete privacy remain open.

## Acceptance and recovery boundaries

Before normal credit, the receiver decrypts and strictly parses fixed lengths,
range-checks integer sompi, regenerates the whole invoice from the seed/index,
matches O/incoming/K/nativePK/domain, checks the accepted CM position and derives
its exact positioned NF against the current authenticated spent set.

The full Invoice208 has a separate strict validation API that compares every
field, including deliveryPK, against deterministic receiver derivation. Because
Receipt216 deliberately omits deliveryPK, receipt restoration verifies its owned
note fields and decrypts under the retained delivery secret; it cannot reconstruct
some sender-purported full invoice. A receipt encrypted to a substituted delivery
key cannot be decrypted or credited by the receiver. No sender identity is proved.

The earliest canonical valid position for an invoice receives normal credit.
Later reuse gets no automatic new credit and flags privacy contamination.
Every correctly derived positive position still has its own liability and owner
authority. In particular, an unsolicited later duplicate cannot retroactively
freeze an earlier note. An owner can still act on duplicate positions while
accepting their disclosed privacy risk; no admin permission is introduced.

Recovery consumes a complete ordered public ciphertext archive and full current
CM/indexed-NF data. The expected state and archive digest are an explicit
**synthetic acceptance/data oracle**, not independently verified chain consensus.
The archive digest is an out-of-band test pin. A CM root alone does not bind or
recover ciphertexts; the combined operation must authenticate actual delivery
hashes, and real durable publication/availability still needs qualification.

The reference reconstructs depth-16 CM and depth-17 NF paths, authenticates the
current predecessor, updates it, then constructs the append path against the
intermediate NF root. New integration counters use `n <=65535`, `m <=2*n+1`
including the sentinel; no old parity or `m <=n` assumption is inherited.

There is no service or withdrawal-authorization input. Constructing a witness
after a synthetic service-off point proves only local recoverability from the
provided data. The native signer/validator must still authorize the transaction
and bind payout, fee, predecessor and immutable policy; confirmation on testnet
and recovery after real pruning/reorg/service loss are not demonstrated here.

## Checks

After the shared contract and source/test manifest are reviewed and frozen:

```sh
CARGO_BUILD_JOBS=2 cargo build --offline --locked --manifest-path ../bridge/Cargo.toml
KPX_RECIPIENT_CRYPTO=/absolute/path/to/kpi-future-recipient-crypto python3 -B -m unittest -v test_recipient.py
```

The new runner and 27 checks are frozen/run separately from the retained V1
25-check run. The shared Rust bridge needs no source change or rebuild.
The test runner stores only public synthetic fixtures marked `DO_NOT_FUND`.
Receiver secrets use subprocess stdin, never command arguments. This is not a
production wallet; Python process memory is not zeroized.
