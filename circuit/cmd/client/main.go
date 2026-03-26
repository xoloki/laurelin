// Integration client: generates a Groth16 transfer proof and submits
// CreateAccount + Transfer instructions to a local Solana validator.
//
// Must be run from the circuit/ directory:
//
//	cd circuit && go run ./cmd/client <PROGRAM_ID> [payer-keypair.json]
//
// payer-keypair.json defaults to ../accounts/account1.json
package main

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"time"

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

	solanago "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	xfer "laurelin/circuit"
)

const (
	pkPath = "setup/pk.bin"
	rpcURL = "http://localhost:8899"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: client <PROGRAM_ID> [payer-keypair.json]")
	}
	programID := solanago.MustPublicKeyFromBase58(os.Args[1])

	payerPath := "../accounts/account1.json"
	if len(os.Args) >= 3 {
		payerPath = os.Args[2]
	}
	payer, err := solanago.PrivateKeyFromSolanaKeygenFile(payerPath)
	if err != nil {
		fatalf("load payer keypair: %v", err)
	}

	client := rpc.New(rpcURL)

	// ── 1. Load proving key ───────────────────────────────────────────────────
	logf("Loading proving key from %s…", pkPath)
	pk := groth16.NewProvingKey(ecc.BN254)
	pkFile, err := os.Open(pkPath)
	if err != nil {
		fatalf("open pk.bin: %v", err)
	}
	if _, err := pk.ReadFrom(pkFile); err != nil {
		fatalf("read pk.bin: %v", err)
	}
	pkFile.Close()

	// ── 2. Compile circuit (needed by groth16.Prove) ──────────────────────────
	logf("Compiling circuit…")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &xfer.TransferCircuit{})
	if err != nil {
		fatalf("compile circuit: %v", err)
	}

	// ── 3. Build transfer parameters ─────────────────────────────────────────
	_, _, g1gen, _ := bn254.Generators()
	G := g1gen

	randFr := func() bn254fr.Element {
		var e bn254fr.Element
		if _, err := e.SetRandom(); err != nil {
			fatalf("random Fr: %v", err)
		}
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

	// Fresh random scalars each run → unique PDAs, no "account already in use".
	sk     := randFr()
	rOld   := randFr()
	rNew   := randFr()
	rT     := randFr()
	recvSk := randFr()

	const balance, amount = uint32(1000), uint32(400)
	var bFr, vFr, bmvFr bn254fr.Element
	bFr.SetUint64(uint64(balance))
	vFr.SetUint64(uint64(amount))
	bmvFr.SetUint64(uint64(balance - amount))

	senderPk    := mul(G, sk)
	recvPk      := mul(G, recvSk)
	oldC1       := mul(G, rOld)
	oldC2       := add(mul(oldC1, sk), mul(G, bFr))
	newSenderC1 := mul(G, rNew)
	newSenderC2 := add(mul(newSenderC1, sk), mul(G, bmvFr))
	transferC1  := mul(G, rT)
	transferC2  := add(mul(senderPk, rT), mul(G, vFr))

	// ── 4. Build gnark witness ────────────────────────────────────────────────
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
		fatalf("build witness: %v", err)
	}

	// ── 5. Prove ──────────────────────────────────────────────────────────────
	logf("Generating proof…")
	proofIface, err := groth16.Prove(ccs, pk, fullWitness)
	if err != nil {
		fatalf("prove: %v", err)
	}
	proof := proofIface.(*groth16bn254.Proof)

	pubWitness, err := fullWitness.Public()
	if err != nil {
		fatalf("public witness: %v", err)
	}

	// ── 6. Serialise points ───────────────────────────────────────────────────
	senderPkB   := g1Bytes(&senderPk)
	recvPkB     := g1Bytes(&recvPk)
	oldC1B      := g1Bytes(&oldC1)
	oldC2B      := g1Bytes(&oldC2)
	newSC1B     := g1Bytes(&newSenderC1)
	newSC2B     := g1Bytes(&newSenderC2)
	tC1B        := g1Bytes(&transferC1)
	tC2B        := g1Bytes(&transferC2)
	proofAB     := g1Bytes(&proof.Ar)
	proofBB     := g2Bytes(&proof.Bs)
	proofCB     := g1Bytes(&proof.Krs)

	// ── 6b. Compute BSB22 commitment hash ─────────────────────────────────────
	if len(proof.Commitments) != 1 {
		fatalf("expected 1 commitment, got %d", len(proof.Commitments))
	}
	commitB := g1Bytes(&proof.Commitments[0]) // x||y big-endian

	// prehash = commitment_bytes(64) || pubVec[0..55].Marshal() (56×32 = 1792)
	pubVec := pubWitness.Vector().(bn254fr.Vector)
	prehash := make([]byte, 64+len(pubVec)*32)
	copy(prehash[:64], commitB[:])
	for i, v := range pubVec {
		vBytes := v.Bytes() // canonical big-endian 32 bytes
		copy(prehash[64+i*32:], vBytes[:])
	}
	h := hash_to_field.New([]byte(constraint.CommitmentDst))
	h.Write(prehash)
	commitHashBytes := h.Sum(nil) // 32-byte Fr element big-endian
	var commitHash [32]byte
	copy(commitHash[:], commitHashBytes)
	logf("commitment hash: %x", commitHash[:])

	// ── 7. Derive PDAs ────────────────────────────────────────────────────────
	senderPDA, _, err := solanago.FindProgramAddress([][]byte{senderPkB[:32]}, programID)
	if err != nil {
		fatalf("sender PDA: %v", err)
	}
	recvPDA, _, err := solanago.FindProgramAddress([][]byte{recvPkB[:32]}, programID)
	if err != nil {
		fatalf("recv PDA: %v", err)
	}
	logf("Sender PDA: %s", senderPDA)
	logf("Recv   PDA: %s", recvPDA)

	// ── 8. CreateAccount — sender (with initial ciphertext of balance=1000) ───
	logf("Creating sender account (balance=%d)…", balance)
	sendAndConfirm(client, payer, ixCreateAccount(programID, payer.PublicKey(), senderPDA,
		senderPkB, oldC1B, oldC2B))

	// ── 9. CreateAccount — receiver (zero balance: identity ciphertexts) ──────
	logf("Creating receiver account (balance=0)…")
	var zeroPoint [64]byte
	sendAndConfirm(client, payer, ixCreateAccount(programID, payer.PublicKey(), recvPDA,
		recvPkB, zeroPoint, zeroPoint))

	// ── 10. Transfer ──────────────────────────────────────────────────────────
	logf("Sending transfer (amount=%d)…", amount)
	sendAndConfirm(client, payer,
		ixSetComputeUnitLimit(1_400_000),
		ixTransfer(programID, senderPDA, recvPDA,
			proofAB, proofBB, proofCB, commitB, commitHash, newSC1B, newSC2B, tC1B, tC2B))

	// ── 11. Verify on-chain state ─────────────────────────────────────────────
	logf("Verifying on-chain account state…")
	ctx := context.Background()

	senderData := mustGetAccountData(client, ctx, senderPDA)
	checkField("sender c1", senderData[64:128], newSC1B[:])
	checkField("sender c2", senderData[128:192], newSC2B[:])

	recvData := mustGetAccountData(client, ctx, recvPDA)
	// Initial receiver ciphertexts were zero (identity), so new = 0 + delta = delta.
	checkField("recv c1", recvData[64:128], tC1B[:])
	checkField("recv c2", recvData[128:192], tC2B[:])

	logf("All checks passed ✓")
}

// ── Instruction builders ──────────────────────────────────────────────────────

// ixCreateAccount builds opcode-0 data: pubkey(64) || c1(64) || c2(64)
func ixCreateAccount(
	programID, payer, pda solanago.PublicKey,
	pubkey, c1, c2 [64]byte,
) solanago.Instruction {
	data := make([]byte, 1+192)
	data[0] = 0x00
	copy(data[1:65], pubkey[:])
	copy(data[65:129], c1[:])
	copy(data[129:193], c2[:])
	return &solanago.GenericInstruction{
		ProgID: programID,
		AccountValues: solanago.AccountMetaSlice{
			solanago.Meta(payer).WRITE().SIGNER(),
			solanago.Meta(pda).WRITE(),
			solanago.Meta(solanago.SystemProgramID),
		},
		DataBytes: data,
	}
}

// ixTransfer builds opcode-1 data:
// proof(256) || commitment(64) || commitHash(32) || newSC1(64) || newSC2(64) || tC1(64) || tC2(64)
// = 1 + 608 = 609 bytes total
func ixTransfer(
	programID, senderPDA, recvPDA solanago.PublicKey,
	proofA [64]byte, proofB [128]byte, proofC [64]byte,
	commitment [64]byte, commitHash [32]byte,
	newSC1, newSC2, tC1, tC2 [64]byte,
) solanago.Instruction {
	data := make([]byte, 609)
	data[0] = 0x01
	copy(data[1:65], proofA[:])
	copy(data[65:193], proofB[:])
	copy(data[193:257], proofC[:])
	copy(data[257:321], commitment[:])
	copy(data[321:353], commitHash[:])
	copy(data[353:417], newSC1[:])
	copy(data[417:481], newSC2[:])
	copy(data[481:545], tC1[:])
	copy(data[545:609], tC2[:])
	return &solanago.GenericInstruction{
		ProgID: programID,
		AccountValues: solanago.AccountMetaSlice{
			solanago.Meta(senderPDA).WRITE(),
			solanago.Meta(recvPDA).WRITE(),
		},
		DataBytes: data,
	}
}

// ── RPC helpers ───────────────────────────────────────────────────────────────

// ixSetComputeUnitLimit builds a ComputeBudget::SetComputeUnitLimit instruction.
// Instruction layout: [2u8, units_as_le_u32]
func ixSetComputeUnitLimit(units uint32) solanago.Instruction {
	data := []byte{2, byte(units), byte(units >> 8), byte(units >> 16), byte(units >> 24)}
	computeBudgetProgramID := solanago.MustPublicKeyFromBase58("ComputeBudget111111111111111111111111111111")
	return &solanago.GenericInstruction{
		ProgID:        computeBudgetProgramID,
		AccountValues: solanago.AccountMetaSlice{},
		DataBytes:     data,
	}
}

func sendAndConfirm(client *rpc.Client, payer solanago.PrivateKey, ixs ...solanago.Instruction) {
	ctx := context.Background()
	bh, err := client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		fatalf("get blockhash: %v", err)
	}
	tx, err := solanago.NewTransaction(
		ixs,
		bh.Value.Blockhash,
		solanago.TransactionPayer(payer.PublicKey()),
	)
	if err != nil {
		fatalf("build transaction: %v", err)
	}
	if _, err := tx.Sign(func(key solanago.PublicKey) *solanago.PrivateKey {
		if key.Equals(payer.PublicKey()) {
			return &payer
		}
		return nil
	}); err != nil {
		fatalf("sign transaction: %v", err)
	}
	sig, err := client.SendTransactionWithOpts(ctx, tx, rpc.TransactionOpts{
		SkipPreflight:       false,
		PreflightCommitment: rpc.CommitmentProcessed,
	})
	if err != nil {
		fatalf("send transaction: %v", err)
	}
	logf("  sig: %s", sig)
	awaitConfirmed(client, sig)
}

func awaitConfirmed(client *rpc.Client, sig solanago.Signature) {
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		time.Sleep(500 * time.Millisecond)
		resp, err := client.GetSignatureStatuses(ctx, false, sig)
		if err != nil || resp == nil || len(resp.Value) == 0 || resp.Value[0] == nil {
			continue
		}
		st := resp.Value[0]
		if st.Err != nil {
			fatalf("transaction failed: %v", st.Err)
		}
		if st.ConfirmationStatus == rpc.ConfirmationStatusConfirmed ||
			st.ConfirmationStatus == rpc.ConfirmationStatusFinalized {
			return
		}
	}
	fatalf("transaction not confirmed after 15s")
}

func mustGetAccountData(client *rpc.Client, ctx context.Context, pk solanago.PublicKey) []byte {
	opts := rpc.GetAccountInfoOpts{Commitment: rpc.CommitmentConfirmed}
	resp, err := client.GetAccountInfoWithOpts(ctx, pk, &opts)
	if err != nil || resp == nil || resp.Value == nil {
		fatalf("get account %s: %v", pk, err)
	}
	return resp.Value.Data.GetBinary()
}

func checkField(label string, got, want []byte) {
	for i := range want {
		if got[i] != want[i] {
			fatalf("MISMATCH %s at byte %d: got %02x, want %02x", label, i, got[i], want[i])
		}
	}
	logf("  ✓ %s", label)
}

// ── BN254 serialisation ───────────────────────────────────────────────────────

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

// g2Bytes uses EIP-197 format: x_c1 || x_c0 || y_c1 || y_c0
// (matches the format expected by Solana's alt_bn128_pairing syscall)
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

// ── Misc ──────────────────────────────────────────────────────────────────────

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
