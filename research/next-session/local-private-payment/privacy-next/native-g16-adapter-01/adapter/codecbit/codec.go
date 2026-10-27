// Package codecbit is a standalone encoding reference using ordinary bit
// constraints. It supplies no curve, subgroup, Groth16 or financial validation.
package codecbit

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
)

const modulusDecimal = "21888242871839275222246405745257275088696311157297823662689037894645226208583"

// Fq is the ORIGINAL four-limb witness representation, not a modular-field
// object. Its fixed arrays are visible to frontend.NewWitness without reduction.
type Fq struct {
	Limbs [4]frontend.Variable
}

func Modulus() *big.Int {
	q, ok := new(big.Int).SetString(modulusDecimal, 10)
	if !ok {
		panic("invalid fixed BN254 Fq modulus")
	}
	return q
}

type Encoder struct {
	api       frontend.API
	limitBits []frontend.Variable
	halfBits  []frontend.Variable
	canonical map[*Fq][]frontend.Variable
}

func New(api frontend.API) (*Encoder, error) {
	limit := new(big.Int).Sub(Modulus(), big.NewInt(1))
	half := new(big.Int).Rsh(new(big.Int).Set(limit), 1)
	e := &Encoder{api: api, limitBits: make([]frontend.Variable, 256), halfBits: make([]frontend.Variable, 256), canonical: make(map[*Fq][]frontend.Variable)}
	for i := range e.limitBits {
		e.limitBits[i], e.halfBits[i] = limit.Bit(i), half.Bit(i)
	}
	return e, nil
}

func (e *Encoder) AssertCanonical(elements ...*Fq) {
	for _, element := range elements {
		if _, exists := e.canonical[element]; exists {
			continue
		}
		original := make([]frontend.Variable, 0, 256)
		for _, limb := range element.Limbs {
			// Every ORIGINAL limb equals its 64 Boolean bits. An oversized
			// limb cannot be silently carried, truncated or reduced.
			original = append(original, bits.ToBinary(e.api, limb, bits.WithNbDigits(64))...)
		}
		// Compare all 256 bits against q-1, not one native-Fr packing. The
		// constant-bound comparator follows ordinary Boolean constraints.
		e.api.AssertIsEqual(cmp.IsLessBinary(e.api, e.limitBits, original), 0)
		e.canonical[element] = original
	}
}

func (e *Encoder) zero(element *Fq) frontend.Variable {
	out := frontend.Variable(1)
	for _, limb := range element.Limbs {
		// Each limb is already constrained to 64 bits, so native IsZero
		// cannot alias a whole-Fq value modulo native Fr.
		out = e.api.Mul(out, e.api.IsZero(limb))
	}
	return out
}

func (e *Encoder) negative(element *Fq) frontend.Variable {
	return cmp.IsLessBinary(e.api, e.halfBits, e.canonical[element])
}

func (e *Encoder) bindCoefficient(x *Fq, negative frontend.Variable, encoded []frontend.Variable) {
	xBits := e.canonical[x]
	e.api.AssertIsBoolean(negative)
	for i := 0; i < 32; i++ {
		bits.ToBinary(e.api, encoded[i], bits.WithNbDigits(8))
		want := bits.FromBinary(e.api, xBits[8*i:8*(i+1)])
		if i == 31 {
			// Canonical x<=q-1 forces payload bits254/255 to zero.
			want = e.api.Add(want, e.api.Mul(128, negative))
		}
		e.api.AssertIsEqual(encoded[i], want)
	}
}

func (e *Encoder) bindG1Canonical(x, y *Fq, encoded []frontend.Variable) {
	e.api.AssertIsEqual(e.api.And(e.zero(x), e.zero(y)), 0)
	e.bindCoefficient(x, e.negative(y), encoded)
}

func (e *Encoder) bindG2Canonical(x0, x1, y0, y1 *Fq, encoded []frontend.Variable) {
	xZero, yZero := e.api.And(e.zero(x0), e.zero(x1)), e.api.And(e.zero(y0), e.zero(y1))
	e.api.AssertIsEqual(e.api.And(xZero, yZero), 0)
	sign := e.api.Select(e.zero(y1), e.negative(y0), e.negative(y1))
	e.bindCoefficient(x0, 0, encoded[:32])
	e.bindCoefficient(x1, sign, encoded[32:])
}

func (e *Encoder) BindG1(x, y *Fq, encoded []frontend.Variable) error {
	if len(encoded) != 32 {
		return fmt.Errorf("G1 codec shape: got %d bytes, want 32", len(encoded))
	}
	e.AssertCanonical(x, y)
	e.bindG1Canonical(x, y, encoded)
	return nil
}

func (e *Encoder) BindG2(x0, x1, y0, y1 *Fq, encoded []frontend.Variable) error {
	if len(encoded) != 64 {
		return fmt.Errorf("G2 codec shape: got %d bytes, want 64", len(encoded))
	}
	e.AssertCanonical(x0, x1, y0, y1)
	e.bindG2Canonical(x0, x1, y0, y1, encoded)
	return nil
}

// BindProof composes the native A|B|C byte layout only. It does not verify the
// points, pairings, statements, or any commitment/proof protocol.
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
