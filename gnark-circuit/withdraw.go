// Package circuit — WithdrawCircuit proves knowledge of a secret key and
// sufficient balance to withdraw a publicly known amount of SOL lamports.
//
// # Private witnesses
//
//	Sk         – account secret key (BN254 Fr)
//	RNew       – randomness for the new (post-withdraw) ciphertext
//	OldBalance – plaintext balance before withdrawal (u32)
//	NewBalance – OldBalance − Amount; proved non-negative via range check (u32)
//
// # Public inputs (5 values)
//
//	Pk              – account public key (G1)
//	OldC1, OldC2   – current on-chain ciphertext (G1, G1)
//	NewC1, NewC2   – replacement ciphertext after withdraw (G1, G1)
//	Amount          – lamports being withdrawn (u32, native frontend.Variable)
//
// The circuit proves:
//
//  1. Pk     = Sk * G                           (key ownership)
//  2. OldC2  = Sk * OldC1 + OldBalance * G      (correct decryption)
//  3. NewC1  = RNew * G                          (fresh randomness)
//  4. NewC2  = RNew * Pk + NewBalance * G        (correct re-encryption)
//  5. OldBalance = Amount + NewBalance           (arithmetic soundness)
//  6. OldBalance, NewBalance, Amount ∈ [0, 2³²) (no overdraft via range check)
package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// WithdrawCircuit is the Groth16 withdraw constraint system.
type WithdrawCircuit struct {
	// ── private witnesses ──────────────────────────────────────────────────
	Sk         emulated.Element[sw_bn254.ScalarField] `gnark:",secret"`
	RNew       emulated.Element[sw_bn254.ScalarField] `gnark:",secret"`
	OldBalance frontend.Variable                      `gnark:",secret"`
	NewBalance frontend.Variable                      `gnark:",secret"` // OldBalance − Amount

	// ── public inputs ──────────────────────────────────────────────────────
	Pk     sw_bn254.G1Affine `gnark:",public"` // account public key
	OldC1  sw_bn254.G1Affine `gnark:",public"` // current ciphertext C1
	OldC2  sw_bn254.G1Affine `gnark:",public"` // current ciphertext C2
	NewC1  sw_bn254.G1Affine `gnark:",public"` // replacement ciphertext C1
	NewC2  sw_bn254.G1Affine `gnark:",public"` // replacement ciphertext C2
	Amount frontend.Variable `gnark:",public"` // lamports withdrawn
}

func (c *WithdrawCircuit) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[sw_bn254.ScalarField, sw_bn254.G1Affine](api)
	if err != nil {
		return err
	}
	scalarField, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}

	// ── 1. Range checks ────────────────────────────────────────────────────
	oldBits := api.ToBinary(c.OldBalance, 32)
	api.ToBinary(c.NewBalance, 32) // NewBalance range check
	api.ToBinary(c.Amount, 32)     // Amount range check

	// ── 2. OldBalance = Amount + NewBalance ────────────────────────────────
	api.AssertIsEqual(c.OldBalance, api.Add(c.Amount, c.NewBalance))

	// ── 3. Lift OldBalance to emulated scalar for EC ops ───────────────────
	oldScalar := scalarField.FromBits(oldBits...)

	// Generator constant used below.
	_, _, g1gen, _ := bn254.Generators()
	gPoint := sw_bn254.NewG1Affine(g1gen)

	// ── 4. Pk = Sk * G ─────────────────────────────────────────────────────
	computedPk := curve.ScalarMulBase(&c.Sk)
	curve.AssertIsEqual(computedPk, &c.Pk)

	// ── 5. OldC2 = Sk * OldC1 + OldBalance * G ────────────────────────────
	skC1 := curve.ScalarMul(&c.OldC1, &c.Sk)
	oldBalG := curve.ScalarMulBase(oldScalar)
	computedOldC2 := curve.Add(skC1, oldBalG)
	curve.AssertIsEqual(computedOldC2, &c.OldC2)

	// ── 6. NewC1 = RNew * G ────────────────────────────────────────────────
	computedNewC1 := curve.ScalarMulBase(&c.RNew)
	curve.AssertIsEqual(computedNewC1, &c.NewC1)

	// ── 7. NewC2 = RNew * Pk + NewBalance * G ─────────────────────────────
	// Compute NewBalance*G as (NewBalance+1)*G − G to avoid ScalarMulBase(0)
	// when NewBalance = 0 (full withdrawal).  Scalar NewBalance+1 ∈ [1, 2³²]
	// is never zero.  Both curve.Add calls operate on non-identity,
	// non-equal points with overwhelming probability for random RNew.
	nbP1Bits := api.ToBinary(api.Add(c.NewBalance, 1), 33)
	nbP1Scalar := scalarField.FromBits(nbP1Bits...)
	nbP1G := curve.ScalarMulBase(nbP1Scalar)
	rnPk := curve.ScalarMul(&c.Pk, &c.RNew)
	computedNewC2 := curve.Add(curve.Add(rnPk, nbP1G), curve.Neg(&gPoint))
	curve.AssertIsEqual(computedNewC2, &c.NewC2)

	return nil
}
