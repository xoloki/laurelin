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
	"laurelin/gnark-circuit"
)

func buildDepositWitness(
	t *testing.T,
	pkSkBig, rBig *big.Int,
	amount uint32,
) *circuit.DepositCircuit {
	t.Helper()

	_, _, g1gen, _ := bn254.Generators()
	G := g1gen

	toFr := func(x *big.Int) bn254fr.Element {
		var e bn254fr.Element
		e.SetBigInt(x)
		return e
	}
	mul := func(p bn254.G1Affine, s bn254fr.Element) bn254.G1Affine {
		var n big.Int
		s.BigInt(&n)
		var r bn254.G1Affine
		r.ScalarMultiplication(&p, &n)
		return r
	}
	add := func(a, b bn254.G1Affine) bn254.G1Affine {
		var r bn254.G1Affine
		r.Add(&a, &b)
		return r
	}

	sk := toFr(pkSkBig)
	r := toFr(rBig)

	var amtFr bn254fr.Element
	amtFr.SetUint64(uint64(amount))

	pk := mul(G, sk)
	deltaC1 := mul(G, r)
	deltaC2 := add(mul(pk, r), mul(G, amtFr)) // r*pk + amount*G

	var rInt big.Int
	r.BigInt(&rInt)

	return &circuit.DepositCircuit{
		R:       emulated.ValueOf[sw_bn254.ScalarField](&rInt),
		Pk:      sw_bn254.NewG1Affine(pk),
		DeltaC1: sw_bn254.NewG1Affine(deltaC1),
		DeltaC2: sw_bn254.NewG1Affine(deltaC2),
		Amount:  amount,
	}
}

var (
	dSkBig, _ = new(big.Int).SetString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 16)
	dRBig, _  = new(big.Int).SetString("cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe", 16)
)

func TestDepositCircuitSatisfiable(t *testing.T) {
	w := buildDepositWitness(t, dSkBig, dRBig, 400)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.DepositCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("constraints: %d", ccs.GetNbConstraints())

	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	if err := ccs.IsSolved(witness); err != nil {
		t.Fatalf("not satisfied: %v", err)
	}
}

func TestDepositGroth16ProveVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Groth16 prove/verify in short mode")
	}

	w := buildDepositWitness(t, dSkBig, dRBig, 400)

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.DepositCircuit{})
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	witness, _ := frontend.NewWitness(w, ecc.BN254.ScalarField())
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	pub, _ := witness.Public()
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Log("deposit proof verified ok")
}

// TestDepositCircuitZeroAmount verifies the circuit handles a zero-lamport
// deposit (Amount=0), which previously caused a "no modular inverse" panic
// in ScalarMulBase when the emulated scalar was zero.
func TestDepositCircuitZeroAmount(t *testing.T) {
	w := buildDepositWitness(t, dSkBig, dRBig, 0)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.DepositCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	if err := ccs.IsSolved(witness); err != nil {
		t.Fatalf("not satisfied: %v", err)
	}
}

func TestDepositCircuitRejectsInvalidWitness(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.DepositCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	_, _, g1gen, _ := bn254.Generators()
	wrongPoint := sw_bn254.NewG1Affine(g1gen)

	mustFail := func(t *testing.T, w *circuit.DepositCircuit) {
		t.Helper()
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatalf("witness: %v", err)
		}
		if err := ccs.IsSolved(witness); err == nil {
			t.Fatal("expected circuit to reject witness, but it was satisfied")
		}
	}

	// constraint 2: DeltaC1 = R * G
	t.Run("wrong_delta_c1", func(t *testing.T) {
		w := buildDepositWitness(t, dSkBig, dRBig, 400)
		w.DeltaC1 = wrongPoint
		mustFail(t, w)
	})

	// constraint 3: DeltaC2 = R * Pk + Amount * G
	t.Run("wrong_delta_c2", func(t *testing.T) {
		w := buildDepositWitness(t, dSkBig, dRBig, 400)
		w.DeltaC2 = wrongPoint
		mustFail(t, w)
	})

	// constraint 3: wrong amount — delta was built for 400, claim 500
	t.Run("wrong_amount", func(t *testing.T) {
		w := buildDepositWitness(t, dSkBig, dRBig, 400)
		w.Amount = 500
		mustFail(t, w)
	})

	// constraint 3: wrong public key — delta built under one pk, claim another
	t.Run("wrong_pk", func(t *testing.T) {
		w := buildDepositWitness(t, dSkBig, dRBig, 400)
		w.Pk = wrongPoint
		mustFail(t, w)
	})
}
