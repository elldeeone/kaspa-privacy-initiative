# HTTPS retrieval source review

Read-only review of `poc/recovery-portability/https_mirror.py`, SHA256
`0e86c705c0abbf2dd30748872825d97f2f436eb815fdd5388427dcebeabd354c`,
composed with frozen capsule core `88e13b48…`. No requests or tests were run by
this reviewer for the HTTPS wrapper; the independent count remains thirteen
local public capsule API/CLI controls.

No material source blocker found in the reviewed transport boundary:

- It fetches the externally selected index digest first, validates static
  descriptor/manifest/PK/software identities, and stages/checks all four small
  JSON objects before any PK network request. Recognition never requests PK.
- Initial URLs require HTTPS unless an explicit literal-loopback HTTP test
  option is selected. Userinfo, fragments and initial queries are rejected.
  Redirects are bounded, checked again and cannot downgrade HTTPS. TLS uses the
  default validating SSL context; this remains host CA/runtime trust.
- Selected lengths and whole SHA256 are checked while streaming owned public
  files; a corrupt/missing source falls back only to the same exact object.
  The fresh owned cache is then passed through the frozen capsule verifier.
- Public errors/receipts contain fixed categories and expected public identities,
  without redirect/signed URLs, query strings, credentials or actual unexpected
  object digests. Retrieval success does not assert currentness or a spend.
- The cold caller still supplies backup metadata for alias protection before
  public reads. Actual PK decoding/VK/dimensions and private-input ordering remain
  the selected loader/owner consumer's responsibility.

The author retained eight real HTTP loopback transport controls and a targeted
two-case resource-warning cleanup rerun, counted as zero new independent cases.
Their result receipts explicitly exclude actual PK, private backup, native/proof,
external TLS and independent provider exercise. HTTP loopback success is not a
TLS handshake/CA-rejection test, a real external artifact retrieval, separate
hosting or durable retention. Those remain unqualified. The tests were not
repeated in this lane, and no source change was requested.
