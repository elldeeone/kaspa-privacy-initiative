# Encoding follow-up 03: isolate the canonical Fq bound

2026-10-26. Prospective source-only addendum frozen before changing the harness.
No new execution is selected by this file. RUN-SPEC-02
`63fb586a2b75943c9821771617445d8f3ce4cfdd4564d131012723d7042fd69c`
and all forty existing expected outcomes remain unchanged.

The preceding encoding run passed thirteen positives and twenty-seven actual
constraint rejections. Its existing q/q+1 alias controls failed first at byte
equality, so those recorded verdicts did not isolate the canonical-bound check.
Keep that scope and its original evidence unchanged:

* Result9355 bytes SHA `5e5357de2214bfcf8c75dc4a7b7bb55019a429396cf9b6fc072af02b5e33f190`.
* Execution4991 bytes SHA `342b0413304fa371b848a492150a13c64e3b1a555284e8ef8f6352f78e933970`.
* Audit6653 bytes SHA `4d16b973c8276b79746af457c2b052fc36e7bdfd112a68d7f6067d38cf087fd3`.

Add exactly two field-only G1 controls after the original G1 controls. Use x=q
and x=q+1, respectively, y=2, and public x bytes encoding that SAME original
integer, with its correct zero sign flag. Feed the four original64-bit limbs
and public bytes directly to `frontend.NewWitness`, without reduction or a
host point decoder. Both new expectations are **UNSATISFIED**.

For these assignments each limb is below2^64, every public byte is below256,
the public x bytes exactly match the private original x integer, y=2 has the
correct positive sign and the coordinate tuple is nonzero. Therefore limb
width, byte width/equality, sign and nonidentity checks cannot explain the
required failures. The canonical x<=q−1 comparison is the deliberately false
predicate. Retain actual constraint IDs/residuals, and confirm they identify
this bound; parser, hint, process, or unrelated byte failures do not qualify.

Keep the encoder byte-identical at
`f98f77b58d6aa855ac664a58062954d81561ca67e036ff66678ee75d36f0ddf1`.
Keep the original forty control definitions/verdicts byte-identical. Append a
small helper and change only the group control provider, spec identity and
descriptive first comment. Preserve the exact old harness e1a185… source before
authoring its prospective successor. Avoid moving existing circuit/compiler
code; the two compiled systems must retain their exact identities:

| Shape | Constraints | Serialized bytes | SHA256 |
| --- | ---: | ---: | --- |
| G1 | 1637 | 337768 | `ce45410fdf41dc2dd3a98702a40c8601bd2ba31c718cbdc37bd82c8d0f540608` |
| G2 | 3287 | 666869 | `e3021ddd4a6ff0fd24146b569686a0306d33dfdcc460916e4013df39ae4f22f5` |

There will be forty-two expected outcomes if later execution is authorized:
the unchanged thirteen positives and twenty-seven negatives, plus two targeted
canonical-bound negatives. Require zero compiled commitments and the same
typed actual R1CS failure classification. Stop and retain any unexpected
outcome or changed compiled shape; do not change an expected verdict to pass.

Root and independent source review precede any compile. Root must coordinate
memory headroom; no compile is authorized while it is uncertain. Any later run
uses fresh output/scope/binary identity, the existing offline pinned toolchain
and closed namespace. This remains encoding-only: no curve/subgroup/Groth16,
setup, proof generation, financial/privacy change or Original access.
