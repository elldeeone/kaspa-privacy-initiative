// Forty original controls plus two matched noncanonical-bound controls.
// It reads no fixture files, invokes no setup/prover, and imports no recursive
// Groth16 or Groth16 backend package. Arbitrary field controls are not points.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"

	codec "kpi.local/nativeg16adapter/codecbit"
)

const runSpecSHA = "d23ed94375c72910cf6bbfc733fa34d481002afcf5ca5d95d87c1e7c6641d264"
const codecContractSHA = "b98f0164d4fc3c6f81e67ee76f27af221846086f4ef345c6365e007e4764dcae"

type g1Circuit struct {
	X, Y    codec.Fq
	Encoded [32]frontend.Variable `gnark:",public"`
}

func (c *g1Circuit) Define(api frontend.API) error {
	encoder, err := codec.New(api)
	if err != nil {
		return err
	}
	return encoder.BindG1(&c.X, &c.Y, c.Encoded[:])
}

type g2Circuit struct {
	X0, X1, Y0, Y1 codec.Fq
	Encoded        [64]frontend.Variable `gnark:",public"`
}

func (c *g2Circuit) Define(api frontend.API) error {
	encoder, err := codec.New(api)
	if err != nil {
		return err
	}
	return encoder.BindG2(&c.X0, &c.X1, &c.Y0, &c.Y1, c.Encoded[:])
}

type systemRecord struct {
	Name             string `json:"name"`
	Classification   string `json:"classification"`
	Commitments      int    `json:"commitments"`
	Constraints      int    `json:"constraints,omitempty"`
	PublicVariables  int    `json:"public_variables,omitempty"`
	SecretVariables  int    `json:"secret_variables,omitempty"`
	SerializedBytes  int64  `json:"serialized_bytes,omitempty"`
	SerializedSHA256 string `json:"serialized_sha256,omitempty"`
	WallMS           int64  `json:"wall_ms"`
	Error            string `json:"error,omitempty"`
}

type caseRecord struct {
	Name           string `json:"name"`
	Expected       string `json:"expected"`
	Classification string `json:"classification"`
	Matches        bool   `json:"matches"`
	WallMS         int64  `json:"wall_ms"`
	ErrorClass     string `json:"error_class,omitempty"`
	Error          string `json:"error,omitempty"`
	ConstraintID   *int   `json:"constraint_id,omitempty"`
}

type result struct {
	Schema               string         `json:"schema"`
	Status               string         `json:"status"`
	Scope                string         `json:"scope"`
	RunSpecSHA256        string         `json:"run_spec_sha256"`
	CodecContractSHA256  string         `json:"codec_contract_sha256"`
	GoVersion            string         `json:"go_version"`
	SolverTasks          int            `json:"solver_tasks"`
	Systems              []systemRecord `json:"systems"`
	Cases                []caseRecord   `json:"cases"`
	StoppedAt            string         `json:"stopped_at,omitempty"`
	Error                string         `json:"error,omitempty"`
	Groth16Verified      bool           `json:"groth16_verified"`
	CurveClaimsForFields bool           `json:"curve_claims_for_field_controls"`
	SetupOrProof         bool           `json:"setup_or_proof_performed"`
	PrivacyClaim         bool           `json:"privacy_claim"`
}

type control struct {
	name       string
	expected   string
	assignment frontend.Circuit
}

func scalarModulus() *big.Int {
	return fr.Modulus()
}

func baseModulus() *big.Int {
	return codec.Modulus()
}

// rawElement deliberately does NOT use emulated.ValueOf or reduce modulo q.
// Raw q/q+1 controls and later direct limb overwrites must survive schema parsing.
func rawElement(value *big.Int) codec.Fq {
	if value.Sign() < 0 || value.BitLen() > 256 {
		panic("raw public control integer shape")
	}
	remaining := new(big.Int).Set(value)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	var limbs [4]frontend.Variable
	for i := range limbs {
		limbs[i] = new(big.Int).And(remaining, mask)
		remaining.Rsh(remaining, 64)
	}
	return codec.Fq{Limbs: limbs}
}

// The reference bytes use an EXPLICIT expected sign from each frozen case.
// This host helper does not compute sign using the circuit's comparator.
func referenceCoefficient(x *big.Int, negative bool) [32]frontend.Variable {
	var be [32]byte
	x.FillBytes(be[:])
	var out [32]frontend.Variable
	for i := range out {
		out[i] = int(be[31-i])
	}
	if negative {
		out[31] = out[31].(int) | 0x80
	}
	return out
}

func g1Assignment(x, y *big.Int, negative bool) *g1Circuit {
	return &g1Circuit{X: rawElement(x), Y: rawElement(y), Encoded: referenceCoefficient(x, negative)}
}

func g2Assignment(x0, x1, y0, y1 *big.Int, negative bool) *g2Circuit {
	a := &g2Circuit{X0: rawElement(x0), X1: rawElement(x1), Y0: rawElement(y0), Y1: rawElement(y1)}
	c0, c1 := referenceCoefficient(x0, false), referenceCoefficient(x1, negative)
	copy(a.Encoded[:32], c0[:])
	copy(a.Encoded[32:], c1[:])
	return a
}

func g1Controls() []control {
	var cases []control
	add := func(name, expected string, a *g1Circuit) { cases = append(cases, control{name, expected, a}) }
	base := func() *g1Circuit { return g1Assignment(big.NewInt(1), big.NewInt(2), false) }
	add("g1.generator_1_2", "ACCEPT", base())
	a := base()
	a.Encoded[0] = a.Encoded[0].(int) ^ 1
	add("g1.public_byte0_xor1_fixed_coordinates", "UNSATISFIED", a)
	a = base()
	a.X = rawElement(big.NewInt(2))
	add("g1.private_x_changed_raw_limbs", "UNSATISFIED", a)
	for _, flag := range []int{0x80, 0x40, 0xc0} {
		a = base()
		a.Encoded[31] = flag
		add(fmt.Sprintf("g1.flag_%02x_fixed_coordinates", flag), "UNSATISFIED", a)
	}
	a = base()
	a.Encoded[0] = 256
	add("g1.public_byte_256", "UNSATISFIED", a)
	a = base()
	a.Encoded[0] = -1
	add("g1.public_byte_minus1", "UNSATISFIED", a)
	q := baseModulus()
	qm1 := new(big.Int).Sub(q, big.NewInt(1))
	add("g1.field_only_x_q_minus1", "ACCEPT", g1Assignment(qm1, big.NewInt(2), false))
	a = base()
	a.X = rawElement(new(big.Int).Add(q, big.NewInt(1)))
	add("g1.original_raw_x_q_plus1_public_x_1", "UNSATISFIED", a)
	a = g1Assignment(big.NewInt(0), big.NewInt(2), false)
	a.X = rawElement(q)
	add("g1.original_raw_x_q_public_x_0", "UNSATISFIED", a)
	spilled := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	add("g1.field_only_canonical_2pow64_plus1", "ACCEPT", g1Assignment(spilled, big.NewInt(2), false))
	a = g1Assignment(spilled, big.NewInt(2), false)
	a.X = rawElement(big.NewInt(0))
	a.X.Limbs[0] = new(big.Int).Set(spilled)
	add("g1.original_raw_oversized_low_limb", "UNSATISFIED", a)
	add("g1.field_only_x_zero_y_nonzero", "ACCEPT", g1Assignment(big.NewInt(0), big.NewInt(2), false))
	add("g1.zero_coordinates_nonidentity_policy", "UNSATISFIED", g1Assignment(big.NewInt(0), big.NewInt(0), false))
	half := new(big.Int).Rsh(new(big.Int).Set(qm1), 1)
	for _, s := range []struct {
		name     string
		y        *big.Int
		negative bool
	}{
		{"half", half, false},
		{"half_plus1", new(big.Int).Add(half, big.NewInt(1)), true},
		{"low_odd_3", big.NewInt(3), false},
		{"high_even_q_minus1", qm1, true},
	} {
		a = g1Assignment(big.NewInt(1), s.y, s.negative)
		add("g1.sign_"+s.name, "ACCEPT", a)
		a = g1Assignment(big.NewInt(1), s.y, s.negative)
		a.Encoded[31] = a.Encoded[31].(int) ^ 0x80
		add("g1.wrong_sign_"+s.name, "UNSATISFIED", a)
	}
	return cases
}

func g2Controls() []control {
	var cases []control
	add := func(name, expected string, a *g2Circuit) { cases = append(cases, control{name, expected, a}) }
	base := func() *g2Circuit {
		return g2Assignment(big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(0), false)
	}
	add("g2.field_only_c1_zero_c0_low", "ACCEPT", base())
	a := base()
	a.Encoded[0] = a.Encoded[0].(int) ^ 1
	add("g2.public_c0_byte_changed_fixed_coordinates", "UNSATISFIED", a)
	a = base()
	a.Encoded[32] = a.Encoded[32].(int) ^ 1
	add("g2.public_c1_payload_byte32_xor1_fixed_coordinates", "UNSATISFIED", a)
	a = base()
	a.Encoded[31] = a.Encoded[31].(int) | 0x80
	add("g2.c0_payload_high_bit_is_not_a_flag", "UNSATISFIED", a)
	a = base()
	for i := 0; i < 32; i++ {
		a.Encoded[i], a.Encoded[32+i] = a.Encoded[32+i], a.Encoded[i]
	}
	add("g2.c0_c1_wire_halves_exchanged", "UNSATISFIED", a)
	for _, flag := range []int{0x80, 0x40, 0xc0} {
		a = base()
		a.Encoded[63] = flag
		add(fmt.Sprintf("g2.flag_%02x_fixed_coordinates", flag), "UNSATISFIED", a)
	}
	add("g2.all_zero_coordinates_nonidentity_policy", "UNSATISFIED", g2Assignment(big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), false))
	qm1 := new(big.Int).Sub(baseModulus(), big.NewInt(1))
	half := new(big.Int).Rsh(new(big.Int).Set(qm1), 1)
	for _, s := range []struct {
		name     string
		y0, y1   *big.Int
		negative bool
	}{
		{"c1_zero_c0_half", half, big.NewInt(0), false},
		{"c1_zero_c0_half_plus1", new(big.Int).Add(half, big.NewInt(1)), big.NewInt(0), true},
		{"nonzero_c1_low_opposite_c0_high", qm1, big.NewInt(2), false},
		{"nonzero_c1_high_opposite_c0_low", big.NewInt(3), qm1, true},
	} {
		a = g2Assignment(big.NewInt(1), big.NewInt(2), s.y0, s.y1, s.negative)
		add("g2.sign_"+s.name, "ACCEPT", a)
		a = g2Assignment(big.NewInt(1), big.NewInt(2), s.y0, s.y1, s.negative)
		a.Encoded[63] = a.Encoded[63].(int) ^ 0x80
		add("g2.wrong_sign_"+s.name, "UNSATISFIED", a)
	}
	return cases
}

func compileShape(name string, circuit frontend.Circuit) (compiled constraint.ConstraintSystem, record systemRecord) {
	started := time.Now()
	record.Name = name
	defer func() {
		record.WallMS = time.Since(started).Milliseconds()
		if p := recover(); p != nil {
			compiled = nil
			record.Classification, record.Error = "COMPILE_PANIC", fmt.Sprint(p)
		}
	}()
	var err error
	compiled, err = frontend.Compile(scalarModulus(), r1cs.NewBuilder, circuit)
	if err != nil {
		record.Classification, record.Error = "COMPILE_ERROR", err.Error()
		return nil, record
	}
	record.Commitments = len(compiled.GetCommitments().CommitmentIndexes())
	if record.Commitments != 0 {
		record.Classification, record.Error = "UNEXPECTED_COMMITMENTS", "bits-only reference must have no commitments"
		return nil, record
	}
	h := sha256.New()
	n, err := compiled.WriteTo(h)
	if err != nil {
		record.Classification, record.Error = "SERIALIZATION_ERROR", err.Error()
		return nil, record
	}
	record.Classification = "COMPILED_R1CS"
	record.Constraints = compiled.GetNbConstraints()
	record.PublicVariables = compiled.GetNbPublicVariables()
	record.SecretVariables = compiled.GetNbSecretVariables()
	record.SerializedBytes, record.SerializedSHA256 = n, hex.EncodeToString(h.Sum(nil))
	return compiled, record
}

func solveControl(compiled constraint.ConstraintSystem, c control) (record caseRecord) {
	started := time.Now()
	record.Name, record.Expected = c.name, c.expected
	defer func() {
		record.WallMS = time.Since(started).Milliseconds()
		if p := recover(); p != nil {
			record.Classification, record.Error = "PANIC", fmt.Sprint(p)
		}
		record.Matches = record.Classification == record.Expected
	}()
	witness, err := frontend.NewWitness(c.assignment, scalarModulus())
	if err != nil {
		record.Classification, record.ErrorClass, record.Error = "WITNESS_ERROR", fmt.Sprintf("%T", err), err.Error()
		return record
	}
	_, err = compiled.Solve(witness, solver.WithNbTasks(1))
	if err == nil {
		record.Classification = "ACCEPT"
		return record
	}
	record.ErrorClass, record.Error = fmt.Sprintf("%T", err), err.Error()
	var unsatisfied *csbn254.UnsatisfiedConstraintError
	if errors.As(err, &unsatisfied) {
		record.Classification = "UNSATISFIED"
		id := unsatisfied.CID
		record.ConstraintID = &id
	} else {
		// A hint/input/solver refusal is retained as a different outcome and
		// NEVER counted as the required compiled-constraint rejection.
		record.Classification = "HINT_OR_SOLVER_ERROR"
	}
	return record
}

func run() (out result) {
	out = result{Schema: "kpxa-native-g16-codec-constraints/v1", Status: "IN_PROGRESS", Scope: "ENCODING_ONLY_NO_CURVE_OR_GROTH16_VERIFICATION", RunSpecSHA256: runSpecSHA, CodecContractSHA256: codecContractSHA, GoVersion: runtime.Version(), SolverTasks: 1}
	defer func() {
		if p := recover(); p != nil {
			out.Status, out.Error = "FIRST_UNEXPECTED_HARNESS_PANIC", fmt.Sprint(p)
		}
	}()
	if len(os.Args) != 1 || runtime.Version() != "go1.26.8" {
		out.Status, out.Error = "INPUT_OR_TOOLCHAIN_ERROR", "closed arguments and exact Go1.26.8 required"
		return out
	}
	for _, group := range []struct {
		name     string
		circuit  frontend.Circuit
		controls func() []control
	}{
		{"g1_encoding", &g1Circuit{}, g1ControlsWithCanonicalBounds},
		{"g2_encoding", &g2Circuit{}, g2Controls},
	} {
		compiled, meta := compileShape(group.name, group.circuit)
		out.Systems = append(out.Systems, meta)
		if compiled == nil {
			out.Status, out.StoppedAt = "FIRST_UNEXPECTED_COMPILE_RESULT", group.name
			return out
		}
		for _, c := range group.controls() {
			record := solveControl(compiled, c)
			out.Cases = append(out.Cases, record)
			if !record.Matches {
				out.Status, out.StoppedAt = "FIRST_UNEXPECTED_CONSTRAINT_RESULT", c.name
				return out
			}
		}
	}
	out.Status = "PASS_FROZEN_ENCODING_ONLY_CONTROLS"
	return out
}

func main() {
	logger.Disable()
	runtime.GOMAXPROCS(1)
	out := run()
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "public result encoding failed:", err)
		os.Exit(2)
	}
	if out.Status != "PASS_FROZEN_ENCODING_ONLY_CONTROLS" {
		os.Exit(2)
	}
}

// The original forty controls stay unchanged. These two assignments make every
// byte/sign/width/nonidentity predicate true except the canonical x<=q-1 bound.
func g1ControlsWithCanonicalBounds() []control {
	cases := g1Controls()
	q := baseModulus()
	for _, row := range []struct {
		name string
		x    *big.Int
	}{
		{"g1.raw_x_q_matching_noncanonical_public_bytes", q},
		{"g1.raw_x_q_plus1_matching_noncanonical_public_bytes", new(big.Int).Add(q, big.NewInt(1))},
	} {
		cases = append(cases, control{row.name, "UNSATISFIED", g1Assignment(row.x, big.NewInt(2), false)})
	}
	return cases
}
