# Adversarial review of the unfunded interoperability package

**Date:** 4 November 2026 (Australia/Sydney).
**Classification:** internal AI implementation second pass, not independent
cryptography/consensus review or an audit. Scope is this package's exact source,
locked dependencies and synthetic vectors.

| Question | Implemented check and actual remaining boundary |
| --- | --- |
| Can an invalid proof pass because only a fixture hash matched? | Actual fixed-version Halo2 verification runs on decoded bundles. Canonical public-input changes, wrong circuit key and corrupted proof fail in Halo2. Artifact hashes are separate tests. This does not prove cryptographic soundness. |
| Can proof validity bypass authorization or steal a payout? | Both ordered spend signatures and the aggregate binding signature verify the exact complete modeled-effects digest. Economic/delivery mutations retain the original proof but fail signatures. A changed binding signature fails separately. Ordinary signatures/scripts/covenants are **not executed**; no native payout is possible here. |
| Can duplicate inputs or modular arithmetic inflate value? | Canonical bounded public signed balance, integer-sompi native sums/fees and duplicate supplied outpoints reject deterministically. Upstream hidden notes remain `u64`. Authentic zero genesis/backing induction, real funding lookup and invariant adoption remain outside this package; an arbitrary supplied input value is not proven backing. |
| Can the same note be consumed twice or dummy markers ignored? | Every published marker, including padding, is checked against the supplied current spent set and for within-bundle uniqueness. Context does not namespace spentness by active verifier. The package has no durable state store: calling it twice with the same old supplied context can succeed twice. Actual atomic acceptance/undo remains a native consensus obligation. |
| Can a stale proof/cache or fork manufacture accepted ancestry? | Genuine cryptographic validity does not override current supplied anchor/domain/spentness/pool checks. Context mismatch rejects. No header authentication, root provenance, full replay, cache, actual reorg or state persistence is implemented. No native acceptance claim follows. |
| Are malformed points, flags or lengths treated as proof failures? | Parsing separately rejects unknown profile/version/flags/tags, malformed canonical fields, identity rk/epk, noncanonical proof size, bounded lengths and trailing bytes. Identity cv and zero NF parse when upstream permits, then altered statements fail cryptographically. Tests report the layer that rejected. |
| Can a sender make malformed delivery look spendable? | Standard upstream recipient decryption reconstructs a positive note; ciphertext corruption is rejected by recipient checks. Signatures also bind delivery bytes. The Action circuit does not itself prove correct encryption. This is no general wallet/I-14 qualification. |
| What information is published? | All vectors, synthetic keys/seeds, public balance/fees/ordinary effects and ciphertexts are public by design. No live wallet/backup/private truth was imported. This package provides no network anonymity, funding unlinkability, amount-privacy measurement or full-drainage privacy result. |
| What if dependencies or services disappear? | Lockfile/source revisions and exact artifact fingerprints permit local reproduction with the required toolchain/dependencies available. No prover/RPC service is used. A checkout/lockfile alone does not guarantee permanent dependency availability, independent archive retention or user recovery. |
| Does the key identity select a new trust mechanism? | Code fixes repaired V2; input cannot choose another verification key. Independent key constructions and fresh processes match the recorded diagnostic SHA-256. Rust Debug is not a portable key format; no native consensus key encoding or activation is allocated. |

Review found and corrected two implementation hazards before completion:

1. BLAKE2b personalization must be at most 16 bytes; both domains are now fixed
   to exactly 16 and independently reproduced in Python.
2. Counting duplicate supplied outpoints would make arithmetic-only funding
   totals misleading. Duplicate outpoints now reject; authentic funding and
   ordinary authorization still require actual native integration.

The source-only RFC review is retained unchanged. This owner-authorized next
package adds local genuine proof evidence, not native backing, consensus
implementation, independent security approval or privacy qualification. The
[receipt](VERIFICATION.json) and [README](README.md) state the exact checks.
