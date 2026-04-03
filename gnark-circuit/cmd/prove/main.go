// laurelin-prover: Groth16 prover subprocess for the laurelin wallet.
//
// Reads a JSON witness from stdin, loads the proving key from pk_path,
// runs groth16.Prove, and writes proof JSON to stdout. Errors go to stderr.
//
// Build:
//
//	cd circuit && go build -o laurelin-prover ./cmd/prove
//	mv laurelin-prover somewhere on $PATH
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"

	circuit "laurelin/gnark-circuit"
)

// ── JSON wire format ──────────────────────────────────────────────────────────

// ProverInput is the JSON object read from stdin.
// Scalars are 32-byte hex strings; G1 points are 64-byte hex strings (X||Y BE).
type ProverInput struct {
	Circuit string `json:"circuit"` // "deposit" | "transfer" | "withdraw"
	PKPath  string `json:"pk_path"`

	// Scalars (32-byte hex)
	R      string `json:"r,omitempty"`
	Sk     string `json:"sk,omitempty"`
	RNew   string `json:"r_new,omitempty"`
	RDecoy string `json:"r_decoy,omitempty"`
	RT     string `json:"r_t,omitempty"`
	RRecv  string `json:"r_recv,omitempty"`

	// Amounts / balances (u64)
	Amount     uint64 `json:"amount,omitempty"`
	B          uint64 `json:"b,omitempty"`
	V          uint64 `json:"v,omitempty"`
	BmV        uint64 `json:"bmv,omitempty"`
	OldBalance uint64 `json:"old_balance,omitempty"`
	NewBalance uint64 `json:"new_balance,omitempty"`

	// Indices (0 or 1)
	SenderIdx int `json:"sender_idx,omitempty"`
	RecvIdx   int `json:"recv_idx,omitempty"`

	// G1 points — deposit / withdraw
	Pk      string `json:"pk,omitempty"`
	DeltaC1 string `json:"delta_c1,omitempty"`
	DeltaC2 string `json:"delta_c2,omitempty"`
	OldC1   string `json:"old_c1,omitempty"`
	OldC2   string `json:"old_c2,omitempty"`
	NewC1   string `json:"new_c1,omitempty"`
	NewC2   string `json:"new_c2,omitempty"`

	// G1 points — transfer (sender ring)
	SenderPk0    string `json:"sender_pk_0,omitempty"`
	SenderPk1    string `json:"sender_pk_1,omitempty"`
	SenderOldC10 string `json:"sender_old_c1_0,omitempty"`
	SenderOldC11 string `json:"sender_old_c1_1,omitempty"`
	SenderOldC20 string `json:"sender_old_c2_0,omitempty"`
	SenderOldC21 string `json:"sender_old_c2_1,omitempty"`
	SenderNewC10 string `json:"sender_new_c1_0,omitempty"`
	SenderNewC11 string `json:"sender_new_c1_1,omitempty"`
	SenderNewC20 string `json:"sender_new_c2_0,omitempty"`
	SenderNewC21 string `json:"sender_new_c2_1,omitempty"`

	// G1 points — transfer (receiver ring)
	RecvPk0      string `json:"recv_pk_0,omitempty"`
	RecvPk1      string `json:"recv_pk_1,omitempty"`
	RecvDeltaC10 string `json:"recv_delta_c1_0,omitempty"`
	RecvDeltaC20 string `json:"recv_delta_c2_0,omitempty"`
	RecvDeltaC11 string `json:"recv_delta_c1_1,omitempty"`
	RecvDeltaC21 string `json:"recv_delta_c2_1,omitempty"`
}

// ProverOutput is the JSON object written to stdout.
type ProverOutput struct {
	ProofA     string `json:"proof_a"`     // G1, 64 bytes hex
	ProofB     string `json:"proof_b"`     // G2, 128 bytes hex
	ProofC     string `json:"proof_c"`     // G1, 64 bytes hex
	Commitment string `json:"commitment"`  // G1, 64 bytes hex
	CommitHash string `json:"commit_hash"` // 32 bytes hex
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	// Redirect gnark's zerolog output to stderr so stdout carries only the proof JSON.
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		die("read stdin: %v", err)
	}

	var inp ProverInput
	if err := json.Unmarshal(data, &inp); err != nil {
		die("parse input JSON: %v", err)
	}

	if inp.PKPath == "" {
		die("pk_path is required")
	}

	// Build witness and circuit template
	var (
		w        frontend.Circuit
		template frontend.Circuit
	)
	switch inp.Circuit {
	case "deposit":
		w = buildDepositWitness(&inp)
		template = &circuit.DepositCircuit{}
	case "transfer":
		w = buildTransferWitness(&inp)
		template = &circuit.RingTransferCircuit{}
	case "withdraw":
		w = buildWithdrawWitness(&inp)
		template = &circuit.WithdrawCircuit{}
	default:
		die("unknown circuit %q; must be deposit|transfer|withdraw", inp.Circuit)
	}

	// Compile constraint system
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, template)
	if err != nil {
		die("compile circuit: %v", err)
	}

	// Load proving key
	pk := groth16.NewProvingKey(ecc.BN254)
	f, err := os.Open(inp.PKPath)
	if err != nil {
		die("open pk %s: %v", inp.PKPath, err)
	}
	if _, err := pk.ReadFrom(f); err != nil {
		die("read pk %s: %v", inp.PKPath, err)
	}
	f.Close()

	// Build full witness
	fullWitness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		die("build witness: %v", err)
	}

	// Prove
	proofIface, err := groth16.Prove(ccs, pk, fullWitness)
	if err != nil {
		die("prove: %v", err)
	}
	proof := proofIface.(*groth16bn254.Proof)

	if len(proof.Commitments) != 1 {
		die("expected 1 BSB22 commitment, got %d", len(proof.Commitments))
	}
	commitB := g1Bytes(&proof.Commitments[0])

	// Compute BSB22 commit_hash
	pubWitness, err := fullWitness.Public()
	if err != nil {
		die("public witness: %v", err)
	}
	pubVec := pubWitness.Vector().(bn254fr.Vector)

	committed := committedIndices(ccs)
	prehash := make([]byte, 64+len(committed)*32)
	copy(prehash[:64], commitB[:])
	for j, idx := range committed {
		b := pubVec[idx-1].Bytes()
		copy(prehash[64+j*32:], b[:])
	}
	h := hash_to_field.New([]byte(constraint.CommitmentDst))
	h.Write(prehash)
	var commitHash [32]byte
	copy(commitHash[:], h.Sum(nil))

	proofA := g1Bytes(&proof.Ar)
	proofB := g2Bytes(&proof.Bs)
	proofC := g1Bytes(&proof.Krs)

	out := ProverOutput{
		ProofA:     hex.EncodeToString(proofA[:]),
		ProofB:     hex.EncodeToString(proofB[:]),
		ProofC:     hex.EncodeToString(proofC[:]),
		Commitment: hex.EncodeToString(commitB[:]),
		CommitHash: hex.EncodeToString(commitHash[:]),
	}

	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		die("write output: %v", err)
	}
}

// ── Witness builders ──────────────────────────────────────────────────────────

func buildDepositWitness(inp *ProverInput) *circuit.DepositCircuit {
	return &circuit.DepositCircuit{
		R:       hexToScalar(inp.R),
		Pk:      hexToG1(inp.Pk),
		DeltaC1: hexToG1(inp.DeltaC1),
		DeltaC2: hexToG1(inp.DeltaC2),
		Amount:  inp.Amount,
	}
}

func buildWithdrawWitness(inp *ProverInput) *circuit.WithdrawCircuit {
	return &circuit.WithdrawCircuit{
		Sk:         hexToScalar(inp.Sk),
		RNew:       hexToScalar(inp.RNew),
		OldBalance: inp.OldBalance,
		NewBalance: inp.NewBalance,
		Pk:         hexToG1(inp.Pk),
		OldC1:      hexToG1(inp.OldC1),
		OldC2:      hexToG1(inp.OldC2),
		NewC1:      hexToG1(inp.NewC1),
		NewC2:      hexToG1(inp.NewC2),
		Amount:     inp.Amount,
	}
}

func buildTransferWitness(inp *ProverInput) *circuit.RingTransferCircuit {
	return &circuit.RingTransferCircuit{
		Sk:        hexToScalar(inp.Sk),
		RNew:      hexToScalar(inp.RNew),
		RDecoy:    hexToScalar(inp.RDecoy),
		RT:        hexToScalar(inp.RT),
		RRecv:     hexToScalar(inp.RRecv),
		B:         inp.B,
		V:         inp.V,
		BmV:       inp.BmV,
		SenderIdx: inp.SenderIdx,
		RecvIdx:   inp.RecvIdx,

		SenderPk0:    hexToG1(inp.SenderPk0),
		SenderPk1:    hexToG1(inp.SenderPk1),
		SenderOldC10: hexToG1(inp.SenderOldC10),
		SenderOldC11: hexToG1(inp.SenderOldC11),
		SenderOldC20: hexToG1(inp.SenderOldC20),
		SenderOldC21: hexToG1(inp.SenderOldC21),
		SenderNewC10: hexToG1(inp.SenderNewC10),
		SenderNewC11: hexToG1(inp.SenderNewC11),
		SenderNewC20: hexToG1(inp.SenderNewC20),
		SenderNewC21: hexToG1(inp.SenderNewC21),

		RecvPk0:      hexToG1(inp.RecvPk0),
		RecvPk1:      hexToG1(inp.RecvPk1),
		RecvDeltaC10: hexToG1(inp.RecvDeltaC10),
		RecvDeltaC20: hexToG1(inp.RecvDeltaC20),
		RecvDeltaC11: hexToG1(inp.RecvDeltaC11),
		RecvDeltaC21: hexToG1(inp.RecvDeltaC21),
	}
}

// ── Hex parsing helpers ───────────────────────────────────────────────────────

func hexToScalar(s string) emulated.Element[sw_bn254.ScalarField] {
	if s == "" {
		die("hexToScalar: empty string")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		die("hexToScalar %q: %v", s, err)
	}
	var n big.Int
	n.SetBytes(b)
	return emulated.ValueOf[sw_bn254.ScalarField](&n)
}

func hexToG1(s string) sw_bn254.G1Affine {
	if s == "" {
		die("hexToG1: empty string")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		die("hexToG1 %q: %v", s, err)
	}
	if len(b) != 64 {
		die("hexToG1: expected 64 bytes, got %d", len(b))
	}
	var p bn254.G1Affine
	p.X.SetBytes(b[:32])
	p.Y.SetBytes(b[32:])
	return sw_bn254.NewG1Affine(p)
}

// ── Serialisation helpers (mirrors circuit/cmd/client/main.go) ────────────────

func fpBE(x *fp.Element) [32]byte {
	var bi big.Int
	x.BigInt(&bi)
	var out [32]byte
	bi.FillBytes(out[:])
	return out
}

func g1Bytes(p *bn254.G1Affine) [64]byte {
	var out [64]byte
	x := fpBE(&p.X)
	y := fpBE(&p.Y)
	copy(out[:32], x[:])
	copy(out[32:], y[:])
	return out
}

func g2Bytes(p *bn254.G2Affine) [128]byte {
	var out [128]byte
	xc0 := fpBE(&p.X.A0)
	xc1 := fpBE(&p.X.A1)
	yc0 := fpBE(&p.Y.A0)
	yc1 := fpBE(&p.Y.A1)
	copy(out[0:32], xc1[:])
	copy(out[32:64], xc0[:])
	copy(out[64:96], yc1[:])
	copy(out[96:128], yc0[:])
	return out
}

// committedIndices returns the 1-indexed public witness positions that gnark
// includes in the BSB22 commit_hash prehash for this circuit.
func committedIndices(ccs constraint.ConstraintSystem) []int {
	commits := ccs.GetCommitments().(constraint.Groth16Commitments)
	pacc := commits.GetPublicAndCommitmentCommitted(commits.CommitmentIndexes(), ccs.GetNbPublicVariables())
	if len(pacc) == 0 {
		return nil
	}
	return pacc[0]
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "laurelin-prover error: "+format+"\n", args...)
	os.Exit(1)
}
