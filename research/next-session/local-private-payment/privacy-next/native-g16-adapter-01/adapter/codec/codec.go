// Package codec constrains the selected Arkworks 0.6 BN254 proof encoding.
// It supplies no on-curve, subgroup, Groth16, state, or financial verification.
package codec

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/emulated"
)

type Fq = emulated.Element[emulated.BN254Fp]

type Encoder struct {
	api      frontend.API
	fp       *emulated.Field[emulated.BN254Fp]
	halfBits []frontend.Variable
}

func New(api frontend.API) (*Encoder, error) {
	fp, err := emulated.NewField[emulated.BN254Fp](api)
	if err != nil {
		return nil, err
	}
	var params emulated.BN254Fp
	q := params.Modulus()
	half := new(big.Int).Rsh(new(big.Int).Sub(q, big.NewInt(1)), 1)
	halfBits := make([]frontend.Variable, q.BitLen())
	for i := range halfBits {
		halfBits[i] = half.Bit(i)
	}
	return &Encoder{api: api, fp: fp, halfBits: halfBits}, nil
}

// AssertCanonical constrains ORIGINAL witness limbs before IsZero, Neg,
// Reduce, or ToBitsCanonical can normalize their integer representation.
// AssertIsInRange also reaches gnark's original per-limb width constraints.
func (e *Encoder) AssertCanonical(elements ...*Fq) {
	for _, element := range elements {
		e.fp.AssertIsInRange(element)
	}
}

func (e *Encoder) negative(yBits []frontend.Variable) frontend.Variable {
	// Ark sign is y > (q-1)/2, not parity. Compare canonical Fq bit vectors,
	// never a whole Fq integer reduced into the native outer scalar field.
	return cmp.IsLessBinary(e.api, e.halfBits, yBits)
}

func (e *Encoder) bindCoefficient(xBits []frontend.Variable, negative frontend.Variable, encoded []frontend.Variable) {
	padded := make([]frontend.Variable, 256)
	for i := range padded {
		padded[i] = 0
	}
	copy(padded, xBits)
	e.api.AssertIsBoolean(negative)
	for i := 0; i < 32; i++ {
		// A frontend.Variable permits direct 256/-1 adversarial assignments.
		// The constraint, not a host uint8 conversion, must reject them.
		bits.ToBinary(e.api, encoded[i], bits.WithNbDigits(8))
		want := bits.FromBinary(e.api, padded[8*i:8*(i+1)])
		if i == 31 {
			// Canonical Fq uses at most 254 payload bits. Bit6 is therefore
			// zero and bit7 is the Ark negative-y flag; infinity is forbidden.
			want = e.api.Add(want, e.api.Mul(128, negative))
		}
		e.api.AssertIsEqual(encoded[i], want)
	}
}

func (e *Encoder) bindG1Canonical(x, y *Fq, encoded []frontend.Variable) {
	xBits, yBits := e.fp.ToBitsCanonical(x), e.fp.ToBitsCanonical(y)
	e.api.AssertIsEqual(e.api.And(e.fp.IsZero(x), e.fp.IsZero(y)), 0)
	e.bindCoefficient(xBits, e.negative(yBits), encoded)
}

func (e *Encoder) bindG2Canonical(x0, x1, y0, y1 *Fq, encoded []frontend.Variable) {
	x0Bits, x1Bits := e.fp.ToBitsCanonical(x0), e.fp.ToBitsCanonical(x1)
	y0Bits, y1Bits := e.fp.ToBitsCanonical(y0), e.fp.ToBitsCanonical(y1)
	xZero := e.api.And(e.fp.IsZero(x0), e.fp.IsZero(x1))
	yZero := e.api.And(e.fp.IsZero(y0), e.fp.IsZero(y1))
	e.api.AssertIsEqual(e.api.And(xZero, yZero), 0)
	// Ark Fq2 integer ordering checks c1 first. A tie y1 == -y1 is
	// possible only at y1=0 in this odd prime field, then c0 decides.
	sign := e.api.Select(e.fp.IsZero(y1), e.negative(y0Bits), e.negative(y1Bits))
	e.bindCoefficient(x0Bits, 0, encoded[:32]) // B.c0 has NO flags.
	e.bindCoefficient(x1Bits, sign, encoded[32:])
}

// BindG1 binds a nonidentity coordinate pair to exactly 32 public Ark bytes.
// The caller still needs the separate on-curve/subgroup verification.
func (e *Encoder) BindG1(x, y *Fq, encoded []frontend.Variable) error {
	if len(encoded) != 32 {
		return fmt.Errorf("G1 codec shape: got %d bytes, want 32", len(encoded))
	}
	e.AssertCanonical(x, y)
	e.bindG1Canonical(x, y, encoded)
	return nil
}

// BindG2 binds nonidentity Fq2 coordinates in c0,c1 wire order. It does not
// perform a twist/subgroup check and accepts no precomputed pairing lines.
func (e *Encoder) BindG2(x0, x1, y0, y1 *Fq, encoded []frontend.Variable) error {
	if len(encoded) != 64 {
		return fmt.Errorf("G2 codec shape: got %d bytes, want 64", len(encoded))
	}
	e.AssertCanonical(x0, x1, y0, y1)
	e.bindG2Canonical(x0, x1, y0, y1, encoded)
	return nil
}

// BindProof is the shared A32|B64|C32 composition for a later full verifier.
// Every original coordinate is constrained before any point is normalized.
// This function itself does not verify a Groth16 proof.
func (e *Encoder) BindProof(ax, ay, bx0, bx1, by0, by1, cx, cy *Fq, encoded []frontend.Variable) error {
	if len(encoded) != 128 {
		return fmt.Errorf("proof codec shape: got %d bytes, want 128", len(encoded))
	}
	e.AssertCanonical(ax, ay, bx0, bx1, by0, by1, cx, cy)
	e.bindG1Canonical(ax, ay, encoded[:32])
	e.bindG2Canonical(bx0, bx1, by0, by1, encoded[32:96])
	e.bindG1Canonical(cx, cy, encoded[96:])
	return nil
}
