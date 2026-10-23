# Keyless private-action native helper and TN10 transport

This new package follows ADR0053 with the ordinary executable launch amendment
in ADR0054. Earlier native/recovery packages and funded instances are unchanged.

The Rust helper reads one strict public JSON request on stdin. Its modes are
`genesis`, `quote`, and `verify`; the exact contract is
[API-02.md](../../research/next-session/private-service-loss/native/API-02.md).
It accepts no seed, native signing secret, private circuit witness, PK or prover.

- `genesis` recomputes NoteCM, singleton State112 and GN536 under the requested
  domain, and instantiates only the approved 24,417-byte program with ten domain
  operands and one VK328 operand. It does not sign a funding transaction.
- `quote` assembles Auth528/cipher528/update3344 with zero sig65 and zero proof128.
  All public native checks must reach the exact expected Groth16 decode failure.
  The result explicitly remains unverified. The caller converges its authorized
  integer fee before generating its private proof.
- `verify` substitutes only the proof128 relative to the bound quote. Its quote
  ID covers the entire normalized transaction, every actual UTXO context field
  and rate. Full and all input engines must accept. A version1 txid alone omits
  witnesses and cannot bind that substitution.

The helper directly links the existing official native APIs, which validate
supplied contexts at arbitrary approved domain/VK instances. It does not check
chain inclusion or freshness. The wallet authenticates public history/parameters
and performs private ownership/payout derivation locally.

`adapter.mjs` is a separate finite TN10 transport fork. It recognizes only the
fresh private-recovery profile and four stages: founding, private-payment,
bob-private-exit and charlie-private-exit. It checks the complete approved
program, P/R' stage shape, exact actual input contexts and lossless SDK encoding.
The durable, exclusive stage/txid intent files and fsync-before-submit block are
unchanged. Only root submits. Observation rejects related spends discovered
after current output queries while allowing unrelated activity. Views remain
point-in-time, selected-node observations rather than independent consensus.

`native_safe.py` requires all five input-context fields, including explicit
`covenant_id:null`. Known input DAA must match the final local check. Prospective
DAA metadata is replaced only with actual accepted context and revalidated as
the integration contract permits; body/Auth/proof/amounts remain unchanged.

The active runtime uses ordinary reviewed files in dedicated0700 directories,
selected executables0500, read-only sandbox mounts, a fixed clean environment
and a SHA check before each launch. Host/release immutability during operations
is an explicit trust assumption; it does not defend against a malicious host
or inode writer. No special executable-FD/loader path or system policy change
is part of the active workflow.

[Component results](../../research/next-session/private-service-loss/native/RESULTS.md)
record nine helper methods and 31 SDK/mock checks. They use old public AA
supplied-context proofs only to test this new API wrapper. Actual fresh-CAF
proof/chain compatibility belongs to the subsequent local and TN10 rehearsal.
No existing privacy, fee, resource or production qualification is changed.
