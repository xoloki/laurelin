package main

import (
	"fmt"
	"os"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"laurelin/circuit"
)
func main() {
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.RingTransferCircuit{})
	fmt.Println("NbPublicVariables:", ccs.GetNbPublicVariables())

	f, _ := os.Open("setup/pk.bin")
	pk := groth16.NewProvingKey(ecc.BN254)
	pk.ReadFrom(f); f.Close()

	// derive VK from the same PK
	f2, _ := os.Open("setup/pk.bin")
	vk := groth16.NewVerifyingKey(ecc.BN254)

	// Can't get VK from PK - need to re-run setup. Use a fresh small circuit instead.
	_ = vk; _ = f2

	// Load a new VK from fresh setup just to check K length
	_, vk2, _ := groth16.Setup(ccs)
	vkBN := vk2.(*groth16bn254.VerifyingKey)
	fmt.Println("K length from fresh setup:", len(vkBN.G1.K))
	fmt.Println("Expected: NbPublicVariables =", ccs.GetNbPublicVariables(), "  K should be NbPublicVariables")
}
