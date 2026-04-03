package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"laurelin/circuit"
	"os"
)

func main() {
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.RingTransferCircuit{})
	fmt.Fprintln(os.Stderr, "NbPublicVariables:", ccs.GetNbPublicVariables())

	pkFile, _ := os.Open("setup/pk.bin")
	pk := groth16.NewProvingKey(ecc.BN254)
	pk.ReadFrom(pkFile)
	pkFile.Close()

	// Load VK from pk (both come from same setup)
	_, vk, _ := groth16.Setup(ccs) // re-run setup just to see structure
	vkBN := vk.(*groth16bn254.VerifyingKey)
	fmt.Fprintln(os.Stderr, "K length:", len(vkBN.G1.K))
}
