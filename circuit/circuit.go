// Package circuit implements the DEROHE-style confidential transfer circuit
// for Groth16 over BN254.
//
// Private witnesses
//
//	Sk      – sender secret key (BN254 Fr)
//	B       – sender old balance (u32)
//	V       – transfer amount   (u32)
//	BmV     – balance minus amount = B - V (u32, proved equal to B-V)
//	RNew    – randomness for updated sender ciphertext (Fr)
//	RT      – randomness for receiver delta ciphertext  (Fr)
//
// Public inputs (7 BN254 G1 points)
//
//	SenderPk    = Sk * G
//	OldC1       = R_old * G            (old sender ciphertext C1; provided as-is)
//	OldC2       = R_old * SenderPk + B*G
//	NewSenderC1 = RNew * G
//	NewSenderC2 = RNew * SenderPk + BmV*G
//	TransferC1  = RT * G
//	TransferC2  = RT * SenderPk + V*G
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// TransferCircuit is the Groth16 constraint system.
type TransferCircuit struct {
	// ── private witnesses ──────────────────────────────────────────
	Sk   emulated.Element[sw_bn254.ScalarField] `gnark:",secret"`
	RNew emulated.Element[sw_bn254.ScalarField] `gnark:",secret"`
	RT   emulated.Element[sw_bn254.ScalarField] `gnark:",secret"`

	// B, V, BmV kept as native variables so api.ToBinary gives cheap range checks.
	B   frontend.Variable `gnark:",secret"`
	V   frontend.Variable `gnark:",secret"`
	BmV frontend.Variable `gnark:",secret"` // = B - V; proved below

	// ── public inputs ──────────────────────────────────────────────
	SenderPk    sw_bn254.G1Affine `gnark:",public"`
	OldC1       sw_bn254.G1Affine `gnark:",public"`
	OldC2       sw_bn254.G1Affine `gnark:",public"`
	NewSenderC1 sw_bn254.G1Affine `gnark:",public"`
	NewSenderC2 sw_bn254.G1Affine `gnark:",public"`
	TransferC1  sw_bn254.G1Affine `gnark:",public"`
	TransferC2  sw_bn254.G1Affine `gnark:",public"`
}

func (c *TransferCircuit) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[sw_bn254.ScalarField, sw_bn254.G1Affine](api)
	if err != nil {
		return err
	}
	scalarField, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}

	// ── range checks: B, V, BmV ∈ [0, 2^32) ─────────────────────
	// api.ToBinary decomposes into exactly n bits, constraining the value.
	bBits   := api.ToBinary(c.B,   32)
	vBits   := api.ToBinary(c.V,   32)
	bmvBits := api.ToBinary(c.BmV, 32)

	// ── enforce B = V + BmV ───────────────────────────────────────
	// Together with the three range checks this proves 0 ≤ V ≤ B < 2^32.
	api.AssertIsEqual(c.B, api.Add(c.V, c.BmV))

	// ── lift B, V, BmV to emulated scalars for scalar-mul ────────
	bScalar   := scalarField.FromBits(bBits...)
	vScalar   := scalarField.FromBits(vBits...)
	bmvScalar := scalarField.FromBits(bmvBits...)

	// ── 1. SenderPk == Sk * G ─────────────────────────────────────
	computedPk := curve.ScalarMulBase(&c.Sk)
	curve.AssertIsEqual(computedPk, &c.SenderPk)

	// ── 2. OldC2 == Sk * OldC1 + B * G ───────────────────────────
	skC1   := curve.ScalarMul(&c.OldC1, &c.Sk)
	bG     := curve.ScalarMulBase(bScalar)
	oldC2  := curve.Add(skC1, bG)
	curve.AssertIsEqual(oldC2, &c.OldC2)

	// ── 3. NewSenderC1 == RNew * G ────────────────────────────────
	computedNC1 := curve.ScalarMulBase(&c.RNew)
	curve.AssertIsEqual(computedNC1, &c.NewSenderC1)

	// ── 4. NewSenderC2 == RNew * SenderPk + BmV * G ──────────────
	rnPk   := curve.ScalarMul(&c.SenderPk, &c.RNew)
	bmvG   := curve.ScalarMulBase(bmvScalar)
	newC2  := curve.Add(rnPk, bmvG)
	curve.AssertIsEqual(newC2, &c.NewSenderC2)

	// ── 5. TransferC1 == RT * G ───────────────────────────────────
	computedTC1 := curve.ScalarMulBase(&c.RT)
	curve.AssertIsEqual(computedTC1, &c.TransferC1)

	// ── 6. TransferC2 == RT * SenderPk + V * G ───────────────────
	rtPk   := curve.ScalarMul(&c.SenderPk, &c.RT)
	vG     := curve.ScalarMulBase(vScalar)
	transC2 := curve.Add(rtPk, vG)
	curve.AssertIsEqual(transC2, &c.TransferC2)

	return nil
}
