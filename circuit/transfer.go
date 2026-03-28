// Package circuit implements a DEROHE-style confidential ring transfer circuit
// for Groth16 over BN254 with ring size 2 for both sender and receiver.
//
// # Private witnesses
//
//	Sk        – real sender secret key (BN254 Fr)
//	RNew      – randomness for real sender's new ciphertext
//	RDecoy    – randomness for decoy sender's re-randomized ciphertext
//	RT        – randomness for real receiver's transfer delta
//	RRecv     – randomness for decoy receiver's re-randomized delta
//	B         – real sender old balance (u32)
//	V         – transfer amount (u32)
//	BmV       – B − V (u32; proved equal to B − V)
//	SenderIdx – 0 or 1; which ring member is the real sender
//	RecvIdx   – 0 or 1; which ring member is the real receiver
//
// # Public inputs (16 BN254 G1 points)
//
//	SenderPk0, SenderPk1       – sender ring public keys
//	SenderOldC10, SenderOldC11 – old sender ciphertexts C1
//	SenderOldC20, SenderOldC21 – old sender ciphertexts C2
//	SenderNewC10, SenderNewC11 – new sender ciphertexts C1 (both updated)
//	SenderNewC20, SenderNewC21 – new sender ciphertexts C2 (both updated)
//	RecvPk0, RecvPk1           – receiver ring public keys
//	RecvDeltaC10, RecvDeltaC20 – delta ciphertext for receiver 0
//	RecvDeltaC11, RecvDeltaC21 – delta ciphertext for receiver 1
//
// The circuit proves (using private SenderIdx and RecvIdx):
//
//	1. SenderPk[senderIdx]     = Sk * G
//	2. SenderOldC2[senderIdx]  = Sk * SenderOldC1[senderIdx] + B * G
//	3. SenderNewC1[senderIdx]  = RNew * G
//	4. SenderNewC2[senderIdx]  = RNew * SenderPk[senderIdx] + BmV * G
//	5. SenderNewC1[decoy]      = SenderOldC1[decoy] + RDecoy * G      (re-rand)
//	6. SenderNewC2[decoy]      = SenderOldC2[decoy] + RDecoy * SenderPk[decoy]
//	7. RecvDeltaC1[recvIdx]    = RT * G
//	8. RecvDeltaC2[recvIdx]    = RT * RecvPk[recvIdx] + V * G
//	9. RecvDeltaC1[decoy]      = RRecv * G                             (re-rand = 0)
//	10. RecvDeltaC2[decoy]     = RRecv * RecvPk[decoy]
//	11. 0 ≤ V ≤ B < 2³²  (via B = V + BmV and range checks)
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// RingTransferCircuit is the Groth16 ring-transfer constraint system.
type RingTransferCircuit struct {
	// ── private witnesses ──────────────────────────────────────────────────
	Sk        emulated.Element[sw_bn254.ScalarField] `gnark:",secret"`
	RNew      emulated.Element[sw_bn254.ScalarField] `gnark:",secret"` // real sender new-cipher rand
	RDecoy    emulated.Element[sw_bn254.ScalarField] `gnark:",secret"` // decoy sender re-rand
	RT        emulated.Element[sw_bn254.ScalarField] `gnark:",secret"` // real transfer rand
	RRecv     emulated.Element[sw_bn254.ScalarField] `gnark:",secret"` // decoy recv re-rand

	B         frontend.Variable `gnark:",secret"` // old balance
	V         frontend.Variable `gnark:",secret"` // transfer amount
	BmV       frontend.Variable `gnark:",secret"` // B − V

	SenderIdx frontend.Variable `gnark:",secret"` // 0 or 1
	RecvIdx   frontend.Variable `gnark:",secret"` // 0 or 1

	// ── public inputs — sender ring (2 members) ───────────────────────────
	SenderPk0    sw_bn254.G1Affine `gnark:",public"`
	SenderPk1    sw_bn254.G1Affine `gnark:",public"`
	SenderOldC10 sw_bn254.G1Affine `gnark:",public"`
	SenderOldC11 sw_bn254.G1Affine `gnark:",public"`
	SenderOldC20 sw_bn254.G1Affine `gnark:",public"`
	SenderOldC21 sw_bn254.G1Affine `gnark:",public"`
	SenderNewC10 sw_bn254.G1Affine `gnark:",public"`
	SenderNewC11 sw_bn254.G1Affine `gnark:",public"`
	SenderNewC20 sw_bn254.G1Affine `gnark:",public"`
	SenderNewC21 sw_bn254.G1Affine `gnark:",public"`

	// ── public inputs — receiver ring (2 members) ────────────────────────
	RecvPk0      sw_bn254.G1Affine `gnark:",public"`
	RecvPk1      sw_bn254.G1Affine `gnark:",public"`
	RecvDeltaC10 sw_bn254.G1Affine `gnark:",public"` // delta C1 for recv 0
	RecvDeltaC20 sw_bn254.G1Affine `gnark:",public"` // delta C2 for recv 0
	RecvDeltaC11 sw_bn254.G1Affine `gnark:",public"` // delta C1 for recv 1
	RecvDeltaC21 sw_bn254.G1Affine `gnark:",public"` // delta C2 for recv 1
}

// selectG1 returns a if cond == 0, b if cond == 1.
// Uses emulated.Field.Select for proper element handling.
func selectG1(
	api frontend.API,
	fpField *emulated.Field[emulated.BN254Fp],
	cond frontend.Variable,
	a, b sw_bn254.G1Affine,
) sw_bn254.G1Affine {
	x := fpField.Select(cond, &b.X, &a.X)
	y := fpField.Select(cond, &b.Y, &a.Y)
	return sw_bn254.G1Affine{X: *x, Y: *y}
}

func (c *RingTransferCircuit) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[sw_bn254.ScalarField, sw_bn254.G1Affine](api)
	if err != nil {
		return err
	}
	scalarField, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	fpField, err := emulated.NewField[emulated.BN254Fp](api)
	if err != nil {
		return err
	}

	// ── 1. Indices must be boolean ─────────────────────────────────────────
	api.AssertIsBoolean(c.SenderIdx)
	api.AssertIsBoolean(c.RecvIdx)

	// ── 2. Range checks: B, V, BmV ∈ [0, 2^32) ───────────────────────────
	bBits   := api.ToBinary(c.B,   32)
	vBits   := api.ToBinary(c.V,   32)
	bmvBits := api.ToBinary(c.BmV, 32)

	// ── 3. Enforce B = V + BmV ────────────────────────────────────────────
	api.AssertIsEqual(c.B, api.Add(c.V, c.BmV))

	// ── 4. Lift to emulated scalars ────────────────────────────────────────
	bScalar   := scalarField.FromBits(bBits...)
	vScalar   := scalarField.FromBits(vBits...)
	bmvScalar := scalarField.FromBits(bmvBits...)

	// ── 5. Select real / decoy sender points ───────────────────────────────
	// Select(cond, b, a): returns a when cond==0, b when cond==1.
	realSenderPk     := selectG1(api, fpField, c.SenderIdx, c.SenderPk0,    c.SenderPk1)
	decoySenderPk    := selectG1(api, fpField, c.SenderIdx, c.SenderPk1,    c.SenderPk0)
	realSenderOldC1  := selectG1(api, fpField, c.SenderIdx, c.SenderOldC10, c.SenderOldC11)
	realSenderOldC2  := selectG1(api, fpField, c.SenderIdx, c.SenderOldC20, c.SenderOldC21)
	decoySenderOldC1 := selectG1(api, fpField, c.SenderIdx, c.SenderOldC11, c.SenderOldC10)
	decoySenderOldC2 := selectG1(api, fpField, c.SenderIdx, c.SenderOldC21, c.SenderOldC20)
	realSenderNewC1  := selectG1(api, fpField, c.SenderIdx, c.SenderNewC10, c.SenderNewC11)
	realSenderNewC2  := selectG1(api, fpField, c.SenderIdx, c.SenderNewC20, c.SenderNewC21)
	decoySenderNewC1 := selectG1(api, fpField, c.SenderIdx, c.SenderNewC11, c.SenderNewC10)
	decoySenderNewC2 := selectG1(api, fpField, c.SenderIdx, c.SenderNewC21, c.SenderNewC20)

	// ── 6. SenderPk[senderIdx] = Sk * G ───────────────────────────────────
	computedPk := curve.ScalarMulBase(&c.Sk)
	curve.AssertIsEqual(computedPk, &realSenderPk)

	// ── 7. OldC2[senderIdx] = Sk * OldC1[senderIdx] + B * G ──────────────
	skC1  := curve.ScalarMul(&realSenderOldC1, &c.Sk)
	bG    := curve.ScalarMulBase(bScalar)
	oldC2 := curve.Add(skC1, bG)
	curve.AssertIsEqual(oldC2, &realSenderOldC2)

	// ── 8. NewC1[senderIdx] = RNew * G ────────────────────────────────────
	computedNC1 := curve.ScalarMulBase(&c.RNew)
	curve.AssertIsEqual(computedNC1, &realSenderNewC1)

	// ── 9. NewC2[senderIdx] = RNew * SenderPk[senderIdx] + BmV * G ────────
	rnPk  := curve.ScalarMul(&realSenderPk, &c.RNew)
	bmvG  := curve.ScalarMulBase(bmvScalar)
	newC2 := curve.Add(rnPk, bmvG)
	curve.AssertIsEqual(newC2, &realSenderNewC2)

	// ── 10. Decoy sender re-randomization ─────────────────────────────────
	//        NewC1[decoy] = OldC1[decoy] + RDecoy * G
	//        NewC2[decoy] = OldC2[decoy] + RDecoy * SenderPk[decoy]
	rdG                := curve.ScalarMulBase(&c.RDecoy)
	expectedDecoyNewC1 := curve.Add(&decoySenderOldC1, rdG)
	curve.AssertIsEqual(expectedDecoyNewC1, &decoySenderNewC1)

	rdPk               := curve.ScalarMul(&decoySenderPk, &c.RDecoy)
	expectedDecoyNewC2 := curve.Add(&decoySenderOldC2, rdPk)
	curve.AssertIsEqual(expectedDecoyNewC2, &decoySenderNewC2)

	// ── 11. Select real / decoy receiver points ───────────────────────────
	realRecvPk  := selectG1(api, fpField, c.RecvIdx, c.RecvPk0, c.RecvPk1)
	decoyRecvPk := selectG1(api, fpField, c.RecvIdx, c.RecvPk1, c.RecvPk0)

	// Select receiver deltas
	realRecvDeltaC1  := selectG1(api, fpField, c.RecvIdx, c.RecvDeltaC10, c.RecvDeltaC11)
	realRecvDeltaC2  := selectG1(api, fpField, c.RecvIdx, c.RecvDeltaC20, c.RecvDeltaC21)
	decoyRecvDeltaC1 := selectG1(api, fpField, c.RecvIdx, c.RecvDeltaC11, c.RecvDeltaC10)
	decoyRecvDeltaC2 := selectG1(api, fpField, c.RecvIdx, c.RecvDeltaC21, c.RecvDeltaC20)

	// ── 12. RecvDelta[recvIdx].C1 = RT * G ────────────────────────────────
	computedTC1 := curve.ScalarMulBase(&c.RT)
	curve.AssertIsEqual(computedTC1, &realRecvDeltaC1)

	// ── 13. RecvDelta[recvIdx].C2 = RT * RecvPk[recvIdx] + V * G ──────────
	rtPk    := curve.ScalarMul(&realRecvPk, &c.RT)
	vG      := curve.ScalarMulBase(vScalar)
	transC2 := curve.Add(rtPk, vG)
	curve.AssertIsEqual(transC2, &realRecvDeltaC2)

	// ── 14. Decoy receiver re-randomization (encrypts 0) ──────────────────
	//        RecvDelta[decoy].C1 = RRecv * G
	//        RecvDelta[decoy].C2 = RRecv * RecvPk[decoy]
	computedDRC1 := curve.ScalarMulBase(&c.RRecv)
	curve.AssertIsEqual(computedDRC1, &decoyRecvDeltaC1)

	rrPk := curve.ScalarMul(&decoyRecvPk, &c.RRecv)
	curve.AssertIsEqual(rrPk, &decoyRecvDeltaC2)

	return nil
}
