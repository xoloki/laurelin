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

// buildRingWitness creates a valid RingTransferCircuit witness.
// sender_idx and recv_idx select the real sender/receiver (0 or 1).
func buildRingWitness(
	t *testing.T,
	skBig, rOldBig, rNewBig, rDecoyBig, rTBig, rRecvBig *big.Int,
	decoySkBig, decoyRecvSkBig *big.Int,
	b, v uint32,
	senderIdx, recvIdx uint,
) *circuit.RingTransferCircuit {
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

	sk := toFr(skBig)
	rOld := toFr(rOldBig)
	rNew := toFr(rNewBig)
	rDecoy := toFr(rDecoyBig)
	rT := toFr(rTBig)
	rRecv := toFr(rRecvBig)
	decoySk := toFr(decoySkBig)
	decoyRecvSk := toFr(decoyRecvSkBig)

	var bFr, vFr, bmvFr bn254fr.Element
	bFr.SetUint64(uint64(b))
	vFr.SetUint64(uint64(v))
	bmvFr.SetUint64(uint64(b - v))

	// Real sender
	realSenderPk := mul(G, sk)
	realOldC1 := mul(G, rOld)
	realOldC2 := add(mul(realOldC1, sk), mul(G, bFr))
	realNewC1 := mul(G, rNew)
	realNewC2 := add(mul(realNewC1, sk), mul(G, bmvFr))

	// Decoy sender: generate some initial ciphertext, then re-randomize
	decoyRandFr := toFr(new(big.Int).SetInt64(0x5678abcd))
	decoySenderPk := mul(G, decoySk)
	decoyOldC1 := mul(G, decoyRandFr)
	decoyOldC2 := add(mul(decoyOldC1, decoySk), mul(G, bFr)) // same balance for simplicity
	decoyNewC1 := add(decoyOldC1, mul(G, rDecoy))            // re-randomize
	decoyNewC2 := add(decoyOldC2, mul(decoySenderPk, rDecoy))

	// Transfer delta
	realRecvSk := decoyRecvSk
	_ = realRecvSk
	decoyRecvSkFr := toFr(new(big.Int).SetInt64(0x9abcdef0))

	// Two receiver PKs
	realRecvPk := mul(G, decoyRecvSk) // first param is used as the "real" recv key
	decoyRecvPk := mul(G, decoyRecvSkFr)

	// Real receiver delta: encrypts V under realRecvPk
	transferC1 := mul(G, rT)
	transferC2 := add(mul(realRecvPk, rT), mul(G, vFr))

	// Decoy receiver delta: encrypts 0 under decoyRecvPk (re-rand)
	decoyRecvDeltaC1 := mul(G, rRecv)
	decoyRecvDeltaC2 := mul(decoyRecvPk, rRecv)

	toScalar := func(x *big.Int) emulated.Element[sw_bn254.ScalarField] {
		return emulated.ValueOf[sw_bn254.ScalarField](x)
	}
	toG1 := func(p bn254.G1Affine) sw_bn254.G1Affine {
		return sw_bn254.NewG1Affine(p)
	}

	var skInt, rNewInt, rDecoyInt, rTInt, rRecvInt big.Int
	sk.BigInt(&skInt)
	rNew.BigInt(&rNewInt)
	rDecoy.BigInt(&rDecoyInt)
	rT.BigInt(&rTInt)
	rRecv.BigInt(&rRecvInt)

	// Arrange points according to senderIdx / recvIdx
	var senderPk0, senderPk1 bn254.G1Affine
	var senderOldC10, senderOldC11 bn254.G1Affine
	var senderOldC20, senderOldC21 bn254.G1Affine
	var senderNewC10, senderNewC11 bn254.G1Affine
	var senderNewC20, senderNewC21 bn254.G1Affine

	if senderIdx == 0 {
		senderPk0, senderPk1 = realSenderPk, decoySenderPk
		senderOldC10, senderOldC11 = realOldC1, decoyOldC1
		senderOldC20, senderOldC21 = realOldC2, decoyOldC2
		senderNewC10, senderNewC11 = realNewC1, decoyNewC1
		senderNewC20, senderNewC21 = realNewC2, decoyNewC2
	} else {
		senderPk0, senderPk1 = decoySenderPk, realSenderPk
		senderOldC10, senderOldC11 = decoyOldC1, realOldC1
		senderOldC20, senderOldC21 = decoyOldC2, realOldC2
		senderNewC10, senderNewC11 = decoyNewC1, realNewC1
		senderNewC20, senderNewC21 = decoyNewC2, realNewC2
	}

	var recvPk0, recvPk1 bn254.G1Affine
	var recvDeltaC10, recvDeltaC20, recvDeltaC11, recvDeltaC21 bn254.G1Affine

	if recvIdx == 0 {
		recvPk0, recvPk1 = realRecvPk, decoyRecvPk
		recvDeltaC10, recvDeltaC20 = transferC1, transferC2
		recvDeltaC11, recvDeltaC21 = decoyRecvDeltaC1, decoyRecvDeltaC2
	} else {
		recvPk0, recvPk1 = decoyRecvPk, realRecvPk
		recvDeltaC10, recvDeltaC20 = decoyRecvDeltaC1, decoyRecvDeltaC2
		recvDeltaC11, recvDeltaC21 = transferC1, transferC2
	}

	return &circuit.RingTransferCircuit{
		Sk:        toScalar(&skInt),
		RNew:      toScalar(&rNewInt),
		RDecoy:    toScalar(&rDecoyInt),
		RT:        toScalar(&rTInt),
		RRecv:     toScalar(&rRecvInt),
		B:         b,
		V:         v,
		BmV:       b - v,
		SenderIdx: senderIdx,
		RecvIdx:   recvIdx,

		SenderPk0:    toG1(senderPk0),
		SenderPk1:    toG1(senderPk1),
		SenderOldC10: toG1(senderOldC10),
		SenderOldC11: toG1(senderOldC11),
		SenderOldC20: toG1(senderOldC20),
		SenderOldC21: toG1(senderOldC21),
		SenderNewC10: toG1(senderNewC10),
		SenderNewC11: toG1(senderNewC11),
		SenderNewC20: toG1(senderNewC20),
		SenderNewC21: toG1(senderNewC21),

		RecvPk0:      toG1(recvPk0),
		RecvPk1:      toG1(recvPk1),
		RecvDeltaC10: toG1(recvDeltaC10),
		RecvDeltaC20: toG1(recvDeltaC20),
		RecvDeltaC11: toG1(recvDeltaC11),
		RecvDeltaC21: toG1(recvDeltaC21),
	}
}

func TestRingCircuitSatisfiable(t *testing.T) {
	skBig, _ := new(big.Int).SetString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 16)
	rOld, _ := new(big.Int).SetString("cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe", 16)
	rNew, _ := new(big.Int).SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
	rDecoy, _ := new(big.Int).SetString("aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd", 16)
	rT, _ := new(big.Int).SetString("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 16)
	rRecv, _ := new(big.Int).SetString("1111222233334444111122223333444411112222333344441111222233334444", 16)
	decoySk, _ := new(big.Int).SetString("5555666677778888555566667777888855556666777788885555666677778888", 16)
	decoyRecvSk, _ := new(big.Int).SetString("9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa", 16)

	witness := buildRingWitness(t, skBig, rOld, rNew, rDecoy, rT, rRecv,
		decoySk, decoyRecvSk, 1000, 400, 0, 0)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.RingTransferCircuit{})
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

func TestRingCircuitSatisfiableSenderIdx1(t *testing.T) {
	skBig, _ := new(big.Int).SetString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 16)
	rOld, _ := new(big.Int).SetString("cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe", 16)
	rNew, _ := new(big.Int).SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
	rDecoy, _ := new(big.Int).SetString("aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd", 16)
	rT, _ := new(big.Int).SetString("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 16)
	rRecv, _ := new(big.Int).SetString("1111222233334444111122223333444411112222333344441111222233334444", 16)
	decoySk, _ := new(big.Int).SetString("5555666677778888555566667777888855556666777788885555666677778888", 16)
	decoyRecvSk, _ := new(big.Int).SetString("9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa", 16)

	// sender_idx=1, recv_idx=1 — real sender/receiver in ring slot 1
	witness := buildRingWitness(t, skBig, rOld, rNew, rDecoy, rT, rRecv,
		decoySk, decoyRecvSk, 1000, 400, 1, 1)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.RingTransferCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	if err := ccs.IsSolved(w); err != nil {
		t.Fatalf("not satisfied (senderIdx=1, recvIdx=1): %v", err)
	}
}

func TestRingCircuitRejectsInvalidWitness(t *testing.T) {
	skBig, _ := new(big.Int).SetString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 16)
	rOld, _ := new(big.Int).SetString("cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe", 16)
	rNew, _ := new(big.Int).SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
	rDecoy, _ := new(big.Int).SetString("aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd", 16)
	rT, _ := new(big.Int).SetString("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 16)
	rRecv, _ := new(big.Int).SetString("1111222233334444111122223333444411112222333344441111222233334444", 16)
	decoySk, _ := new(big.Int).SetString("5555666677778888555566667777888855556666777788885555666677778888", 16)
	decoyRecvSk, _ := new(big.Int).SetString("9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa", 16)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.RingTransferCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	_, _, g1gen, _ := bn254.Generators()
	wrongPoint := sw_bn254.NewG1Affine(g1gen) // valid curve point but wrong value

	mustFail := func(t *testing.T, w *circuit.RingTransferCircuit) {
		t.Helper()
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatalf("witness: %v", err)
		}
		if err := ccs.IsSolved(witness); err == nil {
			t.Fatal("expected circuit to reject witness, but it was satisfied")
		}
	}

	// constraint 1: SenderPk[real] = Sk * G
	t.Run("wrong_secret_key", func(t *testing.T) {
		w := buildRingWitness(t, skBig, rOld, rNew, rDecoy, rT, rRecv, decoySk, decoyRecvSk, 1000, 400, 0, 0)
		w.Sk = emulated.ValueOf[sw_bn254.ScalarField](big.NewInt(42))
		mustFail(t, w)
	})

	// constraint 2: OldC2[real] = Sk * OldC1[real] + B * G
	t.Run("wrong_old_balance", func(t *testing.T) {
		w := buildRingWitness(t, skBig, rOld, rNew, rDecoy, rT, rRecv, decoySk, decoyRecvSk, 1000, 400, 0, 0)
		w.B = 999 // OldC2 was encrypted with B=1000
		mustFail(t, w)
	})

	// constraint 4: NewC2[real] = RNew * SenderPk[real] + BmV * G
	t.Run("wrong_new_sender_ciphertext", func(t *testing.T) {
		w := buildRingWitness(t, skBig, rOld, rNew, rDecoy, rT, rRecv, decoySk, decoyRecvSk, 1000, 400, 0, 0)
		w.SenderNewC20 = wrongPoint // senderIdx=0, so slot 0 is real
		mustFail(t, w)
	})

	// constraints 5-6: NewC1/C2[decoy] = OldC1/C2[decoy] + RDecoy * {G, pk[decoy]}
	t.Run("decoy_sender_not_rerandomized", func(t *testing.T) {
		w := buildRingWitness(t, skBig, rOld, rNew, rDecoy, rT, rRecv, decoySk, decoyRecvSk, 1000, 400, 0, 0)
		w.SenderNewC21 = wrongPoint // senderIdx=0, so slot 1 is decoy
		mustFail(t, w)
	})

	// constraints 9-10: DeltaC1/C2[decoy] = RRecv * {G, pk[decoy]}  (encrypts 0)
	t.Run("decoy_recv_delta_nonzero", func(t *testing.T) {
		w := buildRingWitness(t, skBig, rOld, rNew, rDecoy, rT, rRecv, decoySk, decoyRecvSk, 1000, 400, 0, 0)
		w.RecvDeltaC21 = wrongPoint // recvIdx=0, so slot 1 is decoy
		mustFail(t, w)
	})

	// constraint 3: B = V + BmV, plus 32-bit range checks
	t.Run("overdraft", func(t *testing.T) {
		w := buildRingWitness(t, skBig, rOld, rNew, rDecoy, rT, rRecv, decoySk, decoyRecvSk, 1000, 400, 0, 0)
		w.V = 1200 // V > B: 1000 ≠ 1200 + 0
		w.BmV = 0
		mustFail(t, w)
	})

	// boolean assertion on SenderIdx
	t.Run("sender_idx_not_boolean", func(t *testing.T) {
		w := buildRingWitness(t, skBig, rOld, rNew, rDecoy, rT, rRecv, decoySk, decoyRecvSk, 1000, 400, 0, 0)
		w.SenderIdx = 2
		mustFail(t, w)
	})

	// boolean assertion on RecvIdx
	t.Run("recv_idx_not_boolean", func(t *testing.T) {
		w := buildRingWitness(t, skBig, rOld, rNew, rDecoy, rT, rRecv, decoySk, decoyRecvSk, 1000, 400, 0, 0)
		w.RecvIdx = 2
		mustFail(t, w)
	})
}

func TestRingGroth16ProveVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Groth16 prove/verify in short mode")
	}

	skBig, _ := new(big.Int).SetString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 16)
	rOld, _ := new(big.Int).SetString("cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe", 16)
	rNew, _ := new(big.Int).SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
	rDecoy, _ := new(big.Int).SetString("aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd", 16)
	rT, _ := new(big.Int).SetString("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 16)
	rRecv, _ := new(big.Int).SetString("1111222233334444111122223333444411112222333344441111222233334444", 16)
	decoySk, _ := new(big.Int).SetString("5555666677778888555566667777888855556666777788885555666677778888", 16)
	decoyRecvSk, _ := new(big.Int).SetString("9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa9999aaaa", 16)

	witness := buildRingWitness(t, skBig, rOld, rNew, rDecoy, rT, rRecv,
		decoySk, decoyRecvSk, 1000, 400, 0, 0)

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.RingTransferCircuit{})
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
	t.Log("ring proof verified ok")
}
