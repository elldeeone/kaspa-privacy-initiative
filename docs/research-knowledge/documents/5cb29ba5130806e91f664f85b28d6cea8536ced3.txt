# Frozen receipt to canonical native proof

This small SDK software verifier/converter reuses the already qualified vProgs
checked G1/G2 conversion. It turns a genuine 256-byte SDK Groth16 seal into the
canonical Ark0.6 128-byte proof, with the fixed official 424-byte outer key and
five LE public scalars. There is no proving or native VM feature.

The CLI requires the independently selected new image, exact J336 file, claim
digest and receipt SHA before any receipt decode. It contains no historical
image or journal pin and never selects the expected statement from a receipt.
Actual fresh conversion passed after the coordinator froze the tuple and receipt.
Receipt SHA `e13eaa36d1149bfe873938acf829a9e47d93a6a8014eb61fdad9cb09c6e273f2`
verified against image `e21ab79e3aebdaba0355680d6a17bf0142bf0b3b5bbb687a6f2726499282a0d3`,
J336 SHA `699697f07565d28faad6e45b9e6daa0a09dbcea3f475d51880a75289f7e49b57`
and independently derived claim `88f54f54030b2fc884c777a872262679fa15bffca8e613a0f6d40f7d90e92aaa`.
Canonical native128 SHA is `ef70b661190742b88a6030ca5b102bd680d9eb8996bab57f9f4493df44fed811`.
The [report](evidence/fresh-profile-01/report.json) and runtime metadata preserve
software-only scope; actual new native execution belongs to a separate owner.
The build passed two defensive tests. Runtime peak memory is unknown because
this short service emitted no resource event; observed caps were1CPU/2GiB/zero swap.
The source-only build record is historical and remains unchanged.

`extract RECEIPT EXPECTED_IMAGE EXPECTED_J336 EXPECTED_CLAIM EXPECTED_RECEIPT_SHA NEW_OUTPUT`

SDK verification and checked conversion are separate from actual native opcode,
transaction, chain, backing or exit evidence. See `NOTICE` for the established
witness/claim mapping sources. No funding, network or proof generation occurs.
