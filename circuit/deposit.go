// Package circuit — DepositCircuit proves that a delta ciphertext correctly
// encrypts a publicly known deposit amount under the account's public key.
//
// Without this proof, anyone could pass a malformed delta_c2 and corrupt
// another account's ciphertext. The proof binds delta_c1 and delta_c2 to a
// consistent randomness R and the public amount.
//
// # Private witnesses
//
//	R – randomness used to construct the delta ciphertext (BN254 Fr)
//
// # Public inputs
//
//	Pk       – account public key (G1)
//	DeltaC1  – delta ciphertext C1 (G1)
//	DeltaC2  – delta ciphertext C2 (G1)
//	Amount   – lamports being deposited (u32, native frontend.Variable)
//
// The circuit proves:
//
//	1. DeltaC1 = R * G
//	2. DeltaC2 = R * Pk + Amount * G
//	3. Amount ∈ [0, 2³²)
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// DepositCircuit is the Groth16 deposit constraint system.
type DepositCircuit struct {
	// ── private witnesses ──────────────────────────────────────────────────
	R emulated.Element[sw_bn254.ScalarField] `gnark:",secret"`

	// ── public inputs ──────────────────────────────────────────────────────
	Pk      sw_bn254.G1Affine `gnark:",public"` // account public key
	DeltaC1 sw_bn254.G1Affine `gnark:",public"` // delta C1 = R * G
	DeltaC2 sw_bn254.G1Affine `gnark:",public"` // delta C2 = R * Pk + Amount * G
	Amount  frontend.Variable `gnark:",public"` // lamports deposited
}

func (c *DepositCircuit) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[sw_bn254.ScalarField, sw_bn254.G1Affine](api)
	if err != nil {
		return err
	}
	scalarField, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}

	// ── 1. Range check: Amount ∈ [0, 2³²) ────────────────────────────────
	amtBits := api.ToBinary(c.Amount, 32)
	amtScalar := scalarField.FromBits(amtBits...)

	// ── 2. DeltaC1 = R * G ────────────────────────────────────────────────
	computedC1 := curve.ScalarMulBase(&c.R)
	curve.AssertIsEqual(computedC1, &c.DeltaC1)

	// ── 3. DeltaC2 = R * Pk + Amount * G ─────────────────────────────────
	rPk    := curve.ScalarMul(&c.Pk, &c.R)
	amtG   := curve.ScalarMulBase(amtScalar)
	computedC2 := curve.Add(rPk, amtG)
	curve.AssertIsEqual(computedC2, &c.DeltaC2)

	return nil
}
