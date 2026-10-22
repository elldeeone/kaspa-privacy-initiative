# Retained public v6 proof: guest compatibility result

**The exact retained public proof verified inside the guest.** This closes a
measured one-bundle guest-execution prerequisite. No outer receipt was generated
for this diagnostic and no native chain acceptance or privacy result follows.

| Measurement | Result |
| --- | --- |
| Expected, independently selected program image | `1f3b9b1785a11268432ffdd484b83ce5025315e23fc3aa9cf74e3c06e56026de` |
| Public input | Exactly 875 bytes, fixed retained rehearsal row 6 |
| Guest user cycles | 84,842,708 |
| Segments | 182 at po2=19, one at po2=18 |
| Executor wall time | 1.8631 seconds |
| Service wall / CPU time | 1.963 / 2.260 seconds |
| Systemd memory peak display / swap | 61.4M / 0B |
| Journal | Exact 40-byte `KPI1V6J1 || SHA256(bundle)` |
| Guest qualification | Accepted source plus all five declared rejections |

Trailing and truncated input, wrong domain, and changed ciphertext fail with
their exact expected guest rejection. A changed authorization count reaches
the actual pairing equation and fails as `invalid proof`; resource or IPC errors
are not accepted as negative evidence. Native controls additionally reject
identity A/B/C, malformed points, wrong arity, profile/range and ciphertext-order
changes, and require actual pairing rejection after incrementing the first
public scalar.

The static key's checked decode plus explicit validity check consumes
49,369,732 cycles before submitted-proof decoding. Submitted-proof decoding,
conversion/input multiplication and the pairing then account for roughly
9.55M, 1.52M and 24.40M cycles. This measured cost motivated a **separate**
two-proof image with independently prevalidated immutable parameters; this
baseline image, input, code and evidence remain unchanged.

The exact key/proof/input boundary is qualified for this source bundle. This is
not general decoder acceptance equivalence across Arkworks versions. The
original rehearsal still has no retained compatible same-anchor, disjoint-NF
pair. See [execution qualification](evidence/execution-qualification.json),
[build freeze](evidence/build-freeze.json), and the separate
[two-proof package](../two-v6-binding/README.md).
