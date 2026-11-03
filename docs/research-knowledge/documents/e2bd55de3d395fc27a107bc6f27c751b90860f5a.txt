# P1 recovery-authority supplement, 2026-10-18

**The candidate recovery signature profile passes five published Ed25519
vectors and rejects 134 negative cases.** Independent libsodium signing and
detached verification reproduce the five standard cases and nine exact CREDIT
tuples. This qualifies native-library interoperability on public data only.
It is not a wallet proof, native recovery contract or independent composition
review. No wallet, funding or transaction submission occurred.

## Concrete P1 progress

[RFC-0004](../../docs/rfc/0004-private-payment-suite-and-encoding.md) now specifies
the proposed private witness/journal bytes, canonical signature validation,
exact CREDIT signing bytes and the funding-descriptor/self-ID issue. The
[source inspection](../../research/private-payment-recovery-binding-2026-10-18.md)
pins why the shared deposit script alone cannot authenticate the recovery key.
The original [Orchard GPU receipt](RESULTS.md) and its archive remain unchanged.

The candidate native checker uses ed25519-dalek 2.2.0 with curve25519-dalek 4.1.3
and its own Cargo lock. It checks exact lengths, canonical point recompression,
non-small-order/torsion-free A and R, canonical S, then established strict plain
Ed25519 verification. Legacy, batch and hazmat features are disabled.
Compiled verifier/signature source matches the Ed25519 release; compiled curve
source matches its own separate 4.1.3 release commit
`5312a0311ec40df95be953eacfa8a11b9a34bc54`. The later curve file in the
Ed25519 release checkout is not substituted for the version actually compiled.

| Check | Result |
| --- | --- |
| All five RFC 8032 plain-Ed25519 vectors | Exact derived public keys, deterministic signatures and verification match |
| Changed message/key/R/S, wrong lengths, scalar at/above order | Reject |
| All eight torsion points as key and R | 16 cases reject |
| Three noncanonical aliases | Library key decoding succeeds, candidate canonical validation rejects |
| Seven mixed-order points as key and R | 14 cases reject |
| Total negative signature/profile cases | 134 reject |
| Independent CREDIT bytes and signatures | Nine match Python construction, Rust and libsodium |
| Independent negative detached signature checks | All 134 reject |

CREDIT message bytes are the raw ASCII tag `KPI/credit-recovery/v1`, G_hash32
and intent_id32. The Python checker independently hashes the retained golden
intent bytes and builds the tuple, then derives/signs/verifies with libsodium.
The source intents are unrelated structural fixtures of several kinds, not
valid credits; these signatures establish no actual deposit or payment.
All seeds/keys are published RFC test data and must never be funded.

The independent backend is the existing system libsodium 1.0.18, SHA-256
`f9fdc530581d9c0978097c3838d12e33b12d7496106699c796635e97a0407421`.
No library installation or host upgrade occurs. Its point-validation API is
not used/qualified; independent signing/verification agreement is separate
from qualification of the new candidate point policy. No result here is an
independent human review or assurance about the full new composition.

## Reproduce

```bash
cargo build --locked --release --manifest-path poc/private-payment/recovery-auth-vectors/Cargo.toml
poc/private-payment/recovery-auth-vectors/target/release/kpi-recovery-auth-vectors \
  poc/private-payment/vectors/rfc8032-ed25519.json \
  poc/private-payment/vectors/intent-golden.json NEW_AUTH_RESULTS
python3 poc/private-payment/check_recovery_interop.py \
  /usr/lib/x86_64-linux-gnu/libsodium.so.23 \
  poc/private-payment/vectors/rfc8032-ed25519.json \
  poc/private-payment/vectors/intent-golden.json NEW_AUTH_RESULTS NEW_INTEROP_REPORT.json
```

Use the actual local library path on other machines; its identity/version is
reported. Re-extract standards data with `extract_recovery_vectors.py
RFC8032_TEXT NEW_JSON`; the source hash and all five record lengths are checked.
Only standard library crypto APIs perform signing/verification; Python ctypes
is a local ABI bridge, not a crypto implementation.

## Adversarial self-review and remaining gates

Malformed point/scalar encodings and key/domain/intent substitutions are
explicit negative cases. Signature validity alone does not establish backing,
pending state or single consumption. No reserve outpoint can be spent by these
tools. They have no signing/broadcast capability for native KAS and receive
only public test keys. No user witness is sent to another party.

The proposed witness format derives recipient keys, rho and dependent
randomness rather than trusting caller-supplied intermediates; real-note
membership cannot be omitted by a separate dummy flag. This is a review
specification, not tested constraint code. Exact native descriptor/rent/refund
bytes, bootstrap identities and public-authorization consistency remain open.
The shared delegate-entry script does not itself bind the recovery key; a
later host field is insufficient. No direct owner withdrawal bypass is added.
Missing review/native proof/data still stops acceptance rather than enabling
refund or credit. No same-key signature can override credited/pending/paid
state. Actual double-spend, credit/refund race, restored duplicate payout and
terminal reserve enforcement still require P2–P5, not this primitive checker.

Subsequent status: the owner-selected [AI design review](REVIEW-RESULTS.md)
clears the bounded unfunded offline implementation gate after four corrections.
External audit remains unavailable. The candidate native registration requires
actual source/script/proof qualification; node lane-proof compatibility also
remains unresolved. These signature tests do not justify funding or native
acceptance. The sealed supplement archive below is unchanged.

The [supplement manifest](evidence/2026-10-18-recovery-authority.json) indexes
the [public supplement archive](evidence/2026-10-18-recovery-authority.tar.gz).
It retains exact source/lock identities, RFC data, native/independent reports,
negative cases, tuple bytes, checker source and the current review documents.
It does not modify or replace the earlier GPU evidence archive.
