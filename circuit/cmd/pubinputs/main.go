// pubinputs: print all gnark public inputs and commitment metadata.
//
// cd circuit && go run ./cmd/pubinputs
package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"

	xfer "laurelin/circuit"
)

func main() {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &xfer.RingTransferCircuit{})
	if err != nil {
		panic(err)
	}

	_, _, g1gen, _ := bn254.Generators()
	G := g1gen

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

	var sk, rOld, rNew, rDecoy, rT, rRecv, decoySk, decoyRecvSk bn254fr.Element
	sk.SetUint64(42)
	rOld.SetUint64(100)
	rNew.SetUint64(200)
	rDecoy.SetUint64(777)
	rT.SetUint64(300)
	rRecv.SetUint64(888)
	decoySk.SetUint64(99)
	decoyRecvSk.SetUint64(55)

	const balance, amount = uint32(1000), uint32(400)
	var bFr, vFr, bmvFr bn254fr.Element
	bFr.SetUint64(uint64(balance))
	vFr.SetUint64(uint64(amount))
	bmvFr.SetUint64(uint64(balance - amount))

	realSenderPk  := mul(G, sk)
	realOldC1     := mul(G, rOld)
	realOldC2     := add(mul(realOldC1, sk), mul(G, bFr))
	realNewC1     := mul(G, rNew)
	realNewC2     := add(mul(realNewC1, sk), mul(G, bmvFr))

	decoySenderPk  := mul(G, decoySk)
	decoyRandFr    := bn254fr.Element{}
	decoyRandFr.SetUint64(50)
	decoyOldC1    := mul(G, decoyRandFr)
	decoyOldC2    := add(mul(decoyOldC1, decoySk), mul(G, bFr))
	decoyNewC1    := add(decoyOldC1, mul(G, rDecoy))
	decoyNewC2    := add(decoyOldC2, mul(decoySenderPk, rDecoy))

	realRecvPk    := mul(G, decoyRecvSk)
	var decoyRecvSkFr bn254fr.Element
	decoyRecvSkFr.SetUint64(77)
	decoyRecvPk   := mul(G, decoyRecvSkFr)

	transferC1    := mul(G, rT)
	transferC2    := add(mul(realRecvPk, rT), mul(G, vFr))
	decoyDeltaC1  := mul(G, rRecv)
	decoyDeltaC2  := mul(decoyRecvPk, rRecv)

	var skInt, rNewInt, rDecoyInt, rTInt, rRecvInt big.Int
	sk.BigInt(&skInt)
	rNew.BigInt(&rNewInt)
	rDecoy.BigInt(&rDecoyInt)
	rT.BigInt(&rTInt)
	rRecv.BigInt(&rRecvInt)

	w := &xfer.RingTransferCircuit{
		Sk:        emulated.ValueOf[sw_bn254.ScalarField](&skInt),
		RNew:      emulated.ValueOf[sw_bn254.ScalarField](&rNewInt),
		RDecoy:    emulated.ValueOf[sw_bn254.ScalarField](&rDecoyInt),
		RT:        emulated.ValueOf[sw_bn254.ScalarField](&rTInt),
		RRecv:     emulated.ValueOf[sw_bn254.ScalarField](&rRecvInt),
		B: balance, V: amount, BmV: balance - amount,
		SenderIdx: 0, RecvIdx: 0,
		SenderPk0:    sw_bn254.NewG1Affine(realSenderPk),
		SenderPk1:    sw_bn254.NewG1Affine(decoySenderPk),
		SenderOldC10: sw_bn254.NewG1Affine(realOldC1),
		SenderOldC11: sw_bn254.NewG1Affine(decoyOldC1),
		SenderOldC20: sw_bn254.NewG1Affine(realOldC2),
		SenderOldC21: sw_bn254.NewG1Affine(decoyOldC2),
		SenderNewC10: sw_bn254.NewG1Affine(realNewC1),
		SenderNewC11: sw_bn254.NewG1Affine(decoyNewC1),
		SenderNewC20: sw_bn254.NewG1Affine(realNewC2),
		SenderNewC21: sw_bn254.NewG1Affine(decoyNewC2),
		RecvPk0:      sw_bn254.NewG1Affine(realRecvPk),
		RecvPk1:      sw_bn254.NewG1Affine(decoyRecvPk),
		RecvDeltaC10: sw_bn254.NewG1Affine(transferC1),
		RecvDeltaC20: sw_bn254.NewG1Affine(transferC2),
		RecvDeltaC11: sw_bn254.NewG1Affine(decoyDeltaC1),
		RecvDeltaC21: sw_bn254.NewG1Affine(decoyDeltaC2),
	}

	fullWitness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	_, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	vkBN := vk.(*groth16bn254.VerifyingKey)
	fmt.Printf("VK K len: %d\n", len(vkBN.G1.K))
	fmt.Printf("PublicAndCommitmentCommitted: %v\n", vkBN.PublicAndCommitmentCommitted)
	fmt.Printf("len(PublicAndCommitmentCommitted): %d\n", len(vkBN.PublicAndCommitmentCommitted))

	proof, err := groth16.Prove(ccs, vk.(groth16.ProvingKey), fullWitness)
	if err != nil {
		// We can't easily get a matching pk here; just show the VK info
		fmt.Println("(can't prove with fresh VK — use loaded pk)")
	} else {
		proofBN := proof.(*groth16bn254.Proof)
		fmt.Printf("proof.Commitments: %d\n", len(proofBN.Commitments))
		if len(proofBN.Commitments) > 0 {
			commitBytes := proofBN.Commitments[0].Marshal()
			fmt.Printf("commitment[0] marshal len: %d  bytes: %s\n", len(commitBytes), hex.EncodeToString(commitBytes))

			// Compute the hash
			pubWit, _ := fullWitness.Public()
			pubVec := pubWit.Vector().(bn254fr.Vector)
			maxNbPublicCommitted := 0
			for _, s := range vkBN.PublicAndCommitmentCommitted {
				if len(s) > maxNbPublicCommitted {
					maxNbPublicCommitted = len(s)
				}
			}
			commitmentPrehashSerialized := make([]byte, 64+maxNbPublicCommitted*32)
			copy(commitmentPrehashSerialized, commitBytes[:64])
			offset := 64
			for j := range vkBN.PublicAndCommitmentCommitted[0] {
				idx := vkBN.PublicAndCommitmentCommitted[0][j] - 1
				copy(commitmentPrehashSerialized[offset:], pubVec[idx].Marshal())
				offset += 32
			}
			h := hash_to_field.New([]byte(constraint.CommitmentDst))
			h.Write(commitmentPrehashSerialized[:offset])
			hashBytes := h.Sum(nil)
			fmt.Printf("commitment hash: %s\n", hex.EncodeToString(hashBytes))
			fmt.Printf("CommitmentDst: %q\n", constraint.CommitmentDst)
			fmt.Printf("prehash len: %d  prehash: %s\n", offset, hex.EncodeToString(commitmentPrehashSerialized[:offset]))
		}
		pubWit, _ := fullWitness.Public()
		if err := groth16.Verify(proof, vk, pubWit); err != nil {
			fmt.Printf("gnark verify: FAILED %v\n", err)
		} else {
			fmt.Printf("gnark verify: OK\n")
		}
	}
}
