package circuit_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"laurelin/circuit"
)

// buildWitness creates a valid TransferCircuit witness from raw scalar values.
func buildWitness(t *testing.T, skBig, rOldBig, rNewBig, rTBig *big.Int, b, v uint32) *circuit.TransferCircuit {
	t.Helper()

	g := bn254.G1Affine{}
	_, _, g1gen, _ := bn254.Generators()
	g = g1gen

	toFr := func(x *big.Int) bn254fr.Element {
		var e bn254fr.Element
		e.SetBigInt(x)
		return e
	}

	sk := toFr(skBig)
	rOld := toFr(rOldBig)
	rNew := toFr(rNewBig)
	rT := toFr(rTBig)

	var bFr, vFr, bmvFr bn254fr.Element
	bFr.SetUint64(uint64(b))
	vFr.SetUint64(uint64(v))
	bmvFr.SetUint64(uint64(b - v))

	mul := func(a bn254.G1Affine, s bn254fr.Element) bn254.G1Affine {
		var sb big.Int
		s.BigInt(&sb)
		var r bn254.G1Affine
		r.ScalarMultiplication(&a, &sb)
		return r
	}
	add := func(a, b bn254.G1Affine) bn254.G1Affine {
		var r bn254.G1Affine
		r.Add(&a, &b)
		return r
	}

	senderPk := mul(g, sk)
	oldC1 := mul(g, rOld)
	oldC2 := add(mul(oldC1, sk), mul(g, bFr))
	newC1 := mul(g, rNew)
	newC2 := add(mul(newC1, sk), mul(g, bmvFr))
	tC1 := mul(g, rT)
	tC2 := add(mul(senderPk, rT), mul(g, vFr))

	toScalar := func(x *big.Int) emulated.Element[sw_bn254.ScalarField] {
		return emulated.ValueOf[sw_bn254.ScalarField](x)
	}
	toG1 := func(p bn254.G1Affine) sw_bn254.G1Affine {
		return sw_bn254.NewG1Affine(p)
	}

	var skBigInt, rNewBigInt, rTBigInt big.Int
	sk.BigInt(&skBigInt)
	rNew.BigInt(&rNewBigInt)
	rT.BigInt(&rTBigInt)

	return &circuit.TransferCircuit{
		Sk:          toScalar(&skBigInt),
		RNew:        toScalar(&rNewBigInt),
		RT:          toScalar(&rTBigInt),
		B:           b,
		V:           v,
		BmV:         b - v,
		SenderPk:    toG1(senderPk),
		OldC1:       toG1(oldC1),
		OldC2:       toG1(oldC2),
		NewSenderC1: toG1(newC1),
		NewSenderC2: toG1(newC2),
		TransferC1:  toG1(tC1),
		TransferC2:  toG1(tC2),
	}
}

func TestCircuitSatisfiable(t *testing.T) {
	skBig, _ := new(big.Int).SetString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 16)
	rOld, _ := new(big.Int).SetString("cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe", 16)
	rNew, _ := new(big.Int).SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
	rT, _ := new(big.Int).SetString("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 16)

	witness := buildWitness(t, skBig, rOld, rNew, rT, 1000, 400)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.TransferCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("constraints: %d", ccs.GetNbConstraints())

	w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}

	if err := ccs.IsSolved(w); err != nil {
		t.Fatalf("not satisfied: %v", err)
	}
}

func TestGroth16ProveVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Groth16 prove/verify in short mode")
	}

	skBig, _ := new(big.Int).SetString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 16)
	rOld, _ := new(big.Int).SetString("cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe", 16)
	rNew, _ := new(big.Int).SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
	rT, _ := new(big.Int).SetString("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 16)

	witness := buildWitness(t, skBig, rOld, rNew, rT, 1000, 400)

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.TransferCircuit{})
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	w, _ := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	pub, _ := w.Public()
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Log("proof verified ok")
}
