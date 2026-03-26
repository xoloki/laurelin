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
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &xfer.TransferCircuit{})
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

	var sk, rOld, rNew, rT bn254fr.Element
	sk.SetUint64(42)
	rOld.SetUint64(100)
	rNew.SetUint64(200)
	rT.SetUint64(300)

	const balance, amount = uint32(1000), uint32(400)
	var bFr, vFr, bmvFr bn254fr.Element
	bFr.SetUint64(uint64(balance))
	vFr.SetUint64(uint64(amount))
	bmvFr.SetUint64(uint64(balance - amount))

	senderPk    := mul(G, sk)
	oldC1       := mul(G, rOld)
	oldC2       := add(mul(oldC1, sk), mul(G, bFr))
	newSenderC1 := mul(G, rNew)
	newSenderC2 := add(mul(newSenderC1, sk), mul(G, bmvFr))
	transferC1  := mul(G, rT)
	transferC2  := add(mul(senderPk, rT), mul(G, vFr))

	var skInt, rNewInt, rTInt big.Int
	sk.BigInt(&skInt)
	rNew.BigInt(&rNewInt)
	rT.BigInt(&rTInt)

	w := &xfer.TransferCircuit{
		Sk:          emulated.ValueOf[sw_bn254.ScalarField](&skInt),
		RNew:        emulated.ValueOf[sw_bn254.ScalarField](&rNewInt),
		RT:          emulated.ValueOf[sw_bn254.ScalarField](&rTInt),
		B:           balance,
		V:           amount,
		BmV:         balance - amount,
		SenderPk:    sw_bn254.NewG1Affine(senderPk),
		OldC1:       sw_bn254.NewG1Affine(oldC1),
		OldC2:       sw_bn254.NewG1Affine(oldC2),
		NewSenderC1: sw_bn254.NewG1Affine(newSenderC1),
		NewSenderC2: sw_bn254.NewG1Affine(newSenderC2),
		TransferC1:  sw_bn254.NewG1Affine(transferC1),
		TransferC2:  sw_bn254.NewG1Affine(transferC2),
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
