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

func buildWithdrawWitness(
	t *testing.T,
	skBig, rOldBig, rNewBig *big.Int,
	oldBalance, amount uint32,
) *circuit.WithdrawCircuit {
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

	sk   := toFr(skBig)
	rOld := toFr(rOldBig)
	rNew := toFr(rNewBig)

	newBalance := oldBalance - amount

	var oldBalFr, newBalFr bn254fr.Element
	oldBalFr.SetUint64(uint64(oldBalance))
	newBalFr.SetUint64(uint64(newBalance))

	pk     := mul(G, sk)
	oldC1  := mul(G, rOld)
	oldC2  := add(mul(oldC1, sk), mul(G, oldBalFr)) // sk*C1 + oldBal*G
	newC1  := mul(G, rNew)
	newC2  := add(mul(pk, rNew), mul(G, newBalFr))  // rNew*pk + newBal*G

	var skInt, rNewInt big.Int
	sk.BigInt(&skInt)
	rNew.BigInt(&rNewInt)

	return &circuit.WithdrawCircuit{
		Sk:         emulated.ValueOf[sw_bn254.ScalarField](&skInt),
		RNew:       emulated.ValueOf[sw_bn254.ScalarField](&rNewInt),
		OldBalance: oldBalance,
		NewBalance: newBalance,
		Pk:         sw_bn254.NewG1Affine(pk),
		OldC1:      sw_bn254.NewG1Affine(oldC1),
		OldC2:      sw_bn254.NewG1Affine(oldC2),
		NewC1:      sw_bn254.NewG1Affine(newC1),
		NewC2:      sw_bn254.NewG1Affine(newC2),
		Amount:     amount,
	}
}

var (
	wSkBig, _   = new(big.Int).SetString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 16)
	wROldBig, _ = new(big.Int).SetString("cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe", 16)
	wRNewBig, _ = new(big.Int).SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
)

func TestWithdrawCircuitSatisfiable(t *testing.T) {
	w := buildWithdrawWitness(t, wSkBig, wROldBig, wRNewBig, 1000, 400)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.WithdrawCircuit{})
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

func TestWithdrawGroth16ProveVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Groth16 prove/verify in short mode")
	}

	w := buildWithdrawWitness(t, wSkBig, wROldBig, wRNewBig, 1000, 400)

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.WithdrawCircuit{})
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
	t.Log("withdraw proof verified ok")
}

func TestWithdrawCircuitRejectsInvalidWitness(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.WithdrawCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	_, _, g1gen, _ := bn254.Generators()
	wrongPoint := sw_bn254.NewG1Affine(g1gen)

	mustFail := func(t *testing.T, w *circuit.WithdrawCircuit) {
		t.Helper()
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatalf("witness: %v", err)
		}
		if err := ccs.IsSolved(witness); err == nil {
			t.Fatal("expected circuit to reject witness, but it was satisfied")
		}
	}

	// constraint 1: Pk = Sk * G
	t.Run("wrong_secret_key", func(t *testing.T) {
		w := buildWithdrawWitness(t, wSkBig, wROldBig, wRNewBig, 1000, 400)
		w.Sk = emulated.ValueOf[sw_bn254.ScalarField](big.NewInt(42))
		mustFail(t, w)
	})

	// constraint 2: OldC2 = Sk * OldC1 + OldBalance * G
	t.Run("wrong_old_balance", func(t *testing.T) {
		w := buildWithdrawWitness(t, wSkBig, wROldBig, wRNewBig, 1000, 400)
		w.OldBalance = 999 // OldC2 was built with 1000
		mustFail(t, w)
	})

	// constraint 2: wrong old ciphertext
	t.Run("wrong_old_ciphertext", func(t *testing.T) {
		w := buildWithdrawWitness(t, wSkBig, wROldBig, wRNewBig, 1000, 400)
		w.OldC2 = wrongPoint
		mustFail(t, w)
	})

	// constraint 4: NewC2 = RNew * Pk + NewBalance * G
	t.Run("wrong_new_ciphertext", func(t *testing.T) {
		w := buildWithdrawWitness(t, wSkBig, wROldBig, wRNewBig, 1000, 400)
		w.NewC2 = wrongPoint
		mustFail(t, w)
	})

	// constraint 5: OldBalance = Amount + NewBalance
	t.Run("balance_arithmetic_mismatch", func(t *testing.T) {
		w := buildWithdrawWitness(t, wSkBig, wROldBig, wRNewBig, 1000, 400)
		w.NewBalance = 500 // 1000 ≠ 400 + 500... wait, 900. Use 500 so 1000 ≠ 900
		mustFail(t, w)
	})

	// constraint 6: overdraft — NewBalance would be negative
	t.Run("overdraft", func(t *testing.T) {
		w := buildWithdrawWitness(t, wSkBig, wROldBig, wRNewBig, 1000, 400)
		w.Amount = 1200     // Amount > OldBalance
		w.NewBalance = 0    // 1000 ≠ 1200 + 0
		mustFail(t, w)
	})
}
