# Actual selected role-PK loader review

**Loader gate ACK for root-released first synthetic genuine canary proofs.**
No owner backup/witness, PK bytes, proving/native runtime or network was used
by this reviewer. Source/public reports only, 2026-10-23 UTC.

Selected B05 owner ELF SHA256:
`1662fcd9a5b90b8658e07aed2250a4c9c11d2390e80d7addae717090d63fb94d`.
Its source freeze is
`e97a2342e93e46b5ce2c3ecd5cfc0cfcf014a78985bcbf686563ec11eab0602b`;
the relation/runtime build identity remains the reviewed
`8c6a5ab16aab7212cccaf6125f39363d94c854b824bd89ff1eb633f0bad7590a`.
Parameter selection pin bytes change independently of that identity and are
bound by the installed role manifests and measured ELF.

The exact executed public harness is
`prover/readiness-01/CONTROL-SOURCE.py` SHA256
`acc66953bd0bbdedf617adf5520607d32da3f659c781265fbf7f58bb5cdca6e4`.
For both actual full role PKs it compares the complete READY dictionary to exact
role/arity, raw canonical manifest SHA, D, VK hash and compiled build identity.
The parent closes the otherwise-empty witness pipe only after that comparison.
The child must then reject empty private input, emit no stderr and produce no
proof. This establishes an observed readiness boundary without owner material.

Seven further executed cases reject missing compact/wide PKs, both cross-role
file lengths, same-length corrupted compact bytes, truncation and trailing bytes.
All retain all158 offered public canary bytes, return the expected fixed code
without READY, and create no output. The same-length corruption is a separate
public copy; the good PK was not modified. Role crossing here exercises length
rejection, not a fictitious same-length wrong-role decoder result.

Wrong domain/VK/dimensions and authenticated trailing/exhaustion controls use
the separate eight tiny-parameter unit controls against the same loader seam.
They are not described as full-size actual-key controls. Full exact-byte PK
authentication, owned decoding, canonical VK/query checks and selected-manifest
validation retain their reviewed source checks.

The report's original combined flag incorrectly included unpublished public
canary values. After the harness source was retained, the report description was
split into private owner inputs/hashes/paths not published and the public control
canary definition published. This is an additive metadata description correction;
all nine executed rows/outcomes and executed harness bytes remain unchanged.
No test or parameter operation was rerun for that correction.
Normalized `prover/readiness-01/report.json` SHA256 is
`e3a26b91da9e45af29f57dbc54e6ce71f01d42c6bf0f29beb9182275ff8f87bc`;
the retained source description SHA256 is
`05d580be3b08fb60dcfa74578ababb11697c3297afdbf3ea9d04e142a026d14f`.

This gate establishes neither actual recipient recovery nor native financial
acceptance. It does not audit development setup, prove cryptographic correctness,
make supplied context current, confirm payouts or establish privacy/retention.
Actual fresh owner namespaces, every recipient's own reconstruction, native
boundary negatives, complete fees and separate mirror/cache-loss evidence remain.
