// Integration client: exercises the full Laurelin cycle on a local validator.
//
// Cycle:
//  1. CreateAccount — 4 accounts (real sender, decoy sender, real receiver, decoy receiver)
//     Real sender and all receivers start with a zero ciphertext.
//     Decoy sender is initialized with a pre-built ciphertext encrypting balance=1000.
//  2. Deposit — real sender deposits 1000 lamports; on-chain ZK proof verified.
//  3. RingTransfer — real sender transfers 400 (hidden) to real receiver; on-chain ZK proof verified.
//     NOTE: ring transfer updates ciphertexts only; lamports do not move between PDAs.
//  4. Fund receiver — payer sends 400 lamports directly to receiver PDA via system transfer.
//     (In production this would happen through a privacy-preserving mechanism; here it is
//     explicit for demo purposes so that the withdraw step has lamports to pay out.)
//  5. Withdraw — real receiver withdraws 300 lamports; on-chain ZK proof verified.
//  6. Balance checks — decrypt all ciphertexts via BSGS and verify expected values.
//
// Must be run from the circuit/ directory after running `go run ./setup`:
//
//	cd circuit && go run ./cmd/client [PROGRAM_ID] [payer-keypair.json]
//
// If PROGRAM_ID is omitted it is read from local.env.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"strings"
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
	transferPKPath = "setup/transfer_pk.bin"
	depositPKPath  = "setup/deposit_pk.bin"
	withdrawPKPath = "setup/withdraw_pk.bin"
	rpcURL         = "http://localhost:8899"

	depositAmount  = uint32(1000)
	transferAmount = uint32(400)
	withdrawAmount = uint32(300)
	// recvNewBalance is the receiver's remaining encrypted balance after withdrawal.
	recvNewBalance = transferAmount - withdrawAmount // 100
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func readLocalEnv() map[string]string {
	env := make(map[string]string)
	f, err := os.Open("local.env")
	if err != nil {
		return env
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "=", 2)
		if len(parts) == 2 {
			env[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return env
}

func writeLocalEnv(programID, transferSig string) {
	content := fmt.Sprintf("PROGRAM_ID=%s\nRING_TRANSFER_SIG=%s\n", programID, transferSig)
	if err := os.WriteFile("local.env", []byte(content), 0644); err != nil {
		logf("warning: could not write local.env: %v", err)
	}
}

func loadPK(path string) groth16.ProvingKey {
	pk := groth16.NewProvingKey(ecc.BN254)
	f, err := os.Open(path)
	if err != nil {
		fatalf("open %s: %v", path, err)
	}
	if _, err := pk.ReadFrom(f); err != nil {
		fatalf("read %s: %v", path, err)
	}
	f.Close()
	return pk
}


func compileCCS(c frontend.Circuit) constraint.ConstraintSystem {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		fatalf("compile circuit: %v", err)
	}
	return ccs
}

// committedIndices returns the 1-indexed public witness positions that gnark
// includes in the BSB22 commit_hash prehash for this circuit.
// Equivalent to vk.PublicAndCommitmentCommitted[0] without running Setup.
func committedIndices(ccs constraint.ConstraintSystem) []int {
	commits := ccs.GetCommitments().(constraint.Groth16Commitments)
	pacc := commits.GetPublicAndCommitmentCommitted(commits.CommitmentIndexes(), ccs.GetNbPublicVariables())
	if len(pacc) == 0 {
		return nil
	}
	return pacc[0]
}

// proveCircuit generates a Groth16 proof and returns the serialised proof
// components plus the BSB22 commitment point and hash.
func proveCircuit(
	ccs constraint.ConstraintSystem,
	pk groth16.ProvingKey,
	w frontend.Circuit,
) (proofA [64]byte, proofB [128]byte, proofC [64]byte, commitB [64]byte, commitHash [32]byte) {
	fullWitness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		fatalf("build witness: %v", err)
	}
	proofIface, err := groth16.Prove(ccs, pk, fullWitness)
	if err != nil {
		fatalf("prove: %v", err)
	}
	proof := proofIface.(*groth16bn254.Proof)

	if len(proof.Commitments) != 1 {
		fatalf("expected 1 BSB22 commitment, got %d", len(proof.Commitments))
	}
	commitB = g1Bytes(&proof.Commitments[0])

	pubWitness, err := fullWitness.Public()
	if err != nil {
		fatalf("public witness: %v", err)
	}
	pubVec := pubWitness.Vector().(bn254fr.Vector)

	// Compute commit_hash exactly as gnark's verifier does:
	// only include the public witnesses listed in PublicAndCommitmentCommitted[0]
	// (1-indexed into pubVec).
	committed := committedIndices(ccs)
	prehash := make([]byte, 64+len(committed)*32)
	copy(prehash[:64], commitB[:])
	for j, idx := range committed {
		b := pubVec[idx-1].Bytes() // idx is 1-indexed
		copy(prehash[64+j*32:], b[:])
	}
	h := hash_to_field.New([]byte(constraint.CommitmentDst))
	h.Write(prehash)
	copy(commitHash[:], h.Sum(nil))

	proofA = g1Bytes(&proof.Ar)
	proofB = g2Bytes(&proof.Bs)
	proofC = g1Bytes(&proof.Krs)
	return
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	localEnv := readLocalEnv()

	var programIDStr string
	if len(os.Args) >= 2 {
		programIDStr = os.Args[1]
	} else if id, ok := localEnv["PROGRAM_ID"]; ok {
		programIDStr = id
		logf("Using PROGRAM_ID from local.env: %s", programIDStr)
	} else {
		fatalf("usage: client [PROGRAM_ID] [payer-keypair.json]  (or set PROGRAM_ID in local.env)")
	}
	programID := solanago.MustPublicKeyFromBase58(programIDStr)

	payerPath := "../accounts/account1.json"
	if len(os.Args) >= 3 {
		payerPath = os.Args[2]
	}
	payer, err := solanago.PrivateKeyFromSolanaKeygenFile(payerPath)
	if err != nil {
		fatalf("load payer keypair: %v", err)
	}

	client := rpc.New(rpcURL)

	// ── 1. Load proving keys ──────────────────────────────────────────────────
	logf("Loading proving keys…")
	depositPK  := loadPK(depositPKPath)
	transferPK := loadPK(transferPKPath)
	withdrawPK := loadPK(withdrawPKPath)

	// ── 2. Compile circuits ───────────────────────────────────────────────────
	logf("Compiling circuits…")
	depositCCS  := compileCCS(&xfer.DepositCircuit{})
	transferCCS := compileCCS(&xfer.RingTransferCircuit{})
	withdrawCCS := compileCCS(&xfer.WithdrawCircuit{})

	// ── 3. Build BSGS table ───────────────────────────────────────────────────
	_, _, g1gen, _ := bn254.Generators()
	G := g1gen

	logf("Building BSGS table (range 0..2^32)…")
	bsgs := buildBSGSTable(G)
	logf("BSGS table ready (%d entries)", bsgsM)

	// Arithmetic helpers
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
	toFr := func(v uint64) bn254fr.Element {
		var e bn254fr.Element
		e.SetUint64(v)
		return e
	}

	// ── 4. Generate keys ──────────────────────────────────────────────────────
	senderSk    := randFr()
	decoySk     := randFr()
	recvSk      := randFr()
	decoyRecvSk := randFr()

	senderPk    := mul(G, senderSk)
	decoySenderPk := mul(G, decoySk)
	recvPk      := mul(G, recvSk)
	decoyRecvPk := mul(G, decoyRecvSk)

	// ── 5. Build deposit parameters ───────────────────────────────────────────
	// Deposit: prove deltaC1 = rDep*G, deltaC2 = rDep*senderPk + depositAmount*G
	rDep        := randFr()
	depDeltaC1  := mul(G, rDep)
	depDeltaC2  := add(mul(senderPk, rDep), mul(G, toFr(uint64(depositAmount))))

	// After deposit from zero ciphertext:
	//   senderPDA.c1 = depDeltaC1, senderPDA.c2 = depDeltaC2
	realOldC1 := depDeltaC1
	realOldC2 := depDeltaC2

	// ── 6. Build ring transfer parameters ────────────────────────────────────
	// Sender ring (2 members; slot 0 = real sender, balance=depositAmount)
	rNew   := randFr()
	rDecoy := randFr()

	realNewC1 := mul(G, rNew)
	realNewC2 := add(mul(senderPk, rNew), mul(G, toFr(uint64(depositAmount-transferAmount)))) // 600

	// Decoy sender: CreateAccount with a pre-built ciphertext encrypting depositAmount
	decoyRand  := randFr()
	decoyOldC1 := mul(G, decoyRand)
	decoyOldC2 := add(mul(decoySenderPk, decoyRand), mul(G, toFr(uint64(depositAmount))))
	decoyNewC1 := add(decoyOldC1, mul(G, rDecoy))
	decoyNewC2 := add(decoyOldC2, mul(decoySenderPk, rDecoy))

	// Receiver ring (2 members; slot 0 = real receiver starting from zero)
	rT    := randFr()
	rRecv := randFr()

	transferC1  := mul(G, rT)
	transferC2  := add(mul(recvPk, rT), mul(G, toFr(uint64(transferAmount)))) // 400 to real recv
	decoyDeltaC1 := mul(G, rRecv)
	decoyDeltaC2 := mul(decoyRecvPk, rRecv) // 0 to decoy recv

	// ── 7. Build withdraw parameters ─────────────────────────────────────────
	// After ring transfer from zero ciphertext, recvPDA.c1/c2 = transferC1/C2.
	// Receiver proves: old_balance=transferAmount, amount=withdrawAmount, new_balance=recvNewBalance.
	rWd      := randFr()
	recvNewC1 := mul(G, rWd)
	recvNewC2 := add(mul(recvPk, rWd), mul(G, toFr(uint64(recvNewBalance)))) // 100

	// ── 8. Prove deposit ──────────────────────────────────────────────────────
	logf("Proving deposit (depositAmount=%d)…", depositAmount)
	var rDepInt big.Int
	rDep.BigInt(&rDepInt)
	depWitness := &xfer.DepositCircuit{
		R:       emulated.ValueOf[sw_bn254.ScalarField](&rDepInt),
		Pk:      sw_bn254.NewG1Affine(senderPk),
		DeltaC1: sw_bn254.NewG1Affine(depDeltaC1),
		DeltaC2: sw_bn254.NewG1Affine(depDeltaC2),
		Amount:  depositAmount,
	}
	depProofA, depProofB, depProofC, depCommitB, depCommitHash := proveCircuit(depositCCS, depositPK, depWitness)
	logf("  deposit commitment: %x…", depCommitHash[:8])

	// ── 9. Prove ring transfer ────────────────────────────────────────────────
	logf("Proving ring transfer (amount=%d, senderIdx=0, recvIdx=0)…", transferAmount)
	var skInt, rNewInt, rDecoyInt, rTInt, rRecvInt big.Int
	senderSk.BigInt(&skInt)
	rNew.BigInt(&rNewInt)
	rDecoy.BigInt(&rDecoyInt)
	rT.BigInt(&rTInt)
	rRecv.BigInt(&rRecvInt)

	xferWitness := &xfer.RingTransferCircuit{
		Sk:        emulated.ValueOf[sw_bn254.ScalarField](&skInt),
		RNew:      emulated.ValueOf[sw_bn254.ScalarField](&rNewInt),
		RDecoy:    emulated.ValueOf[sw_bn254.ScalarField](&rDecoyInt),
		RT:        emulated.ValueOf[sw_bn254.ScalarField](&rTInt),
		RRecv:     emulated.ValueOf[sw_bn254.ScalarField](&rRecvInt),
		B:         depositAmount,
		V:         transferAmount,
		BmV:       depositAmount - transferAmount,
		SenderIdx: 0,
		RecvIdx:   0,

		SenderPk0:    sw_bn254.NewG1Affine(senderPk),
		SenderPk1:    sw_bn254.NewG1Affine(decoySenderPk),
		SenderOldC10: sw_bn254.NewG1Affine(realOldC1),
		SenderOldC11: sw_bn254.NewG1Affine(decoyOldC1),
		SenderOldC20: sw_bn254.NewG1Affine(realOldC2),
		SenderOldC21: sw_bn254.NewG1Affine(decoyOldC2),
		SenderNewC10: sw_bn254.NewG1Affine(realNewC1),
		SenderNewC11: sw_bn254.NewG1Affine(decoyNewC1),
		SenderNewC20: sw_bn254.NewG1Affine(realNewC2),
		SenderNewC21: sw_bn254.NewG1Affine(decoyNewC2),

		RecvPk0:      sw_bn254.NewG1Affine(recvPk),
		RecvPk1:      sw_bn254.NewG1Affine(decoyRecvPk),
		RecvDeltaC10: sw_bn254.NewG1Affine(transferC1),
		RecvDeltaC20: sw_bn254.NewG1Affine(transferC2),
		RecvDeltaC11: sw_bn254.NewG1Affine(decoyDeltaC1),
		RecvDeltaC21: sw_bn254.NewG1Affine(decoyDeltaC2),
	}
	xferProofA, xferProofB, xferProofC, xferCommitB, xferCommitHash := proveCircuit(transferCCS, transferPK, xferWitness)
	logf("  transfer commitment: %x…", xferCommitHash[:8])

	// ── 10. Prove withdraw ────────────────────────────────────────────────────
	logf("Proving withdraw (amount=%d, remainingBalance=%d)…", withdrawAmount, recvNewBalance)
	var recvSkInt, rWdInt big.Int
	recvSk.BigInt(&recvSkInt)
	rWd.BigInt(&rWdInt)
	wdWitness := &xfer.WithdrawCircuit{
		Sk:         emulated.ValueOf[sw_bn254.ScalarField](&recvSkInt),
		RNew:       emulated.ValueOf[sw_bn254.ScalarField](&rWdInt),
		OldBalance: transferAmount,
		NewBalance: recvNewBalance,
		Pk:         sw_bn254.NewG1Affine(recvPk),
		OldC1:      sw_bn254.NewG1Affine(transferC1),
		OldC2:      sw_bn254.NewG1Affine(transferC2),
		NewC1:      sw_bn254.NewG1Affine(recvNewC1),
		NewC2:      sw_bn254.NewG1Affine(recvNewC2),
		Amount:     withdrawAmount,
	}
	wdProofA, wdProofB, wdProofC, wdCommitB, wdCommitHash := proveCircuit(withdrawCCS, withdrawPK, wdWitness)
	logf("  withdraw commitment: %x…", wdCommitHash[:8])

	// ── 11. Serialise point bytes ─────────────────────────────────────────────
	senderPkB    := g1Bytes(&senderPk)
	decoySenderPkB := g1Bytes(&decoySenderPk)
	recvPkB     := g1Bytes(&recvPk)
	decoyRecvPkB := g1Bytes(&decoyRecvPk)

	depDeltaC1B := g1Bytes(&depDeltaC1)
	depDeltaC2B := g1Bytes(&depDeltaC2)

	realNewC1B  := g1Bytes(&realNewC1)
	realNewC2B  := g1Bytes(&realNewC2)
	decoyNewC1B := g1Bytes(&decoyNewC1)
	decoyNewC2B := g1Bytes(&decoyNewC2)

	transferC1B  := g1Bytes(&transferC1)
	transferC2B  := g1Bytes(&transferC2)
	decoyDeltaC1B := g1Bytes(&decoyDeltaC1)
	decoyDeltaC2B := g1Bytes(&decoyDeltaC2)

	recvNewC1B := g1Bytes(&recvNewC1)
	recvNewC2B := g1Bytes(&recvNewC2)

	decoyOldC1B := g1Bytes(&decoyOldC1)
	decoyOldC2B := g1Bytes(&decoyOldC2)

	// ── 12. Derive PDAs ───────────────────────────────────────────────────────
	vaultPDA, _, err := solanago.FindProgramAddress([][]byte{[]byte("vault")}, programID)
	if err != nil {
		fatalf("vault PDA: %v", err)
	}
	logf("Vault PDA: %s", vaultPDA)

	senderPDA0, _, err := solanago.FindProgramAddress([][]byte{senderPkB[:32]}, programID)
	if err != nil {
		fatalf("sender PDA 0: %v", err)
	}
	senderPDA1, _, err := solanago.FindProgramAddress([][]byte{decoySenderPkB[:32]}, programID)
	if err != nil {
		fatalf("sender PDA 1: %v", err)
	}
	recvPDA0, _, err := solanago.FindProgramAddress([][]byte{recvPkB[:32]}, programID)
	if err != nil {
		fatalf("recv PDA 0: %v", err)
	}
	recvPDA1, _, err := solanago.FindProgramAddress([][]byte{decoyRecvPkB[:32]}, programID)
	if err != nil {
		fatalf("recv PDA 1: %v", err)
	}
	logf("Sender PDA 0 (real):  %s", senderPDA0)
	logf("Sender PDA 1 (decoy): %s", senderPDA1)
	logf("Recv   PDA 0 (real):  %s", recvPDA0)
	logf("Recv   PDA 1 (decoy): %s", recvPDA1)

	// ── 13. CreateAccount — all 4 ring members ────────────────────────────────
	// Real sender and receivers start with zero ciphertext (identity point = all-zero bytes).
	// Decoy sender is initialized with its pre-built ciphertext (no deposit needed).
	var zeroPoint [64]byte

	logf("Creating sender 0 (real, zero ciphertext)…")
	sendAndConfirm(client, payer, ixCreateAccount(programID, payer.PublicKey(), senderPDA0,
		senderPkB, zeroPoint, zeroPoint))

	logf("Creating sender 1 (decoy, balance=%d)…", depositAmount)
	sendAndConfirm(client, payer, ixCreateAccount(programID, payer.PublicKey(), senderPDA1,
		decoySenderPkB, decoyOldC1B, decoyOldC2B))

	logf("Creating receiver 0 (real, zero ciphertext)…")
	sendAndConfirm(client, payer, ixCreateAccount(programID, payer.PublicKey(), recvPDA0,
		recvPkB, zeroPoint, zeroPoint))

	logf("Creating receiver 1 (decoy, zero ciphertext)…")
	sendAndConfirm(client, payer, ixCreateAccount(programID, payer.PublicKey(), recvPDA1,
		decoyRecvPkB, zeroPoint, zeroPoint))

	// ── 14. Deposit — real sender deposits depositAmount lamports ─────────────
	logf("Depositing %d lamports into vault (ZK proof verified on-chain)…", depositAmount)
	sendAndConfirm(client, payer,
		ixSetComputeUnitLimit(500_000),
		ixDeposit(programID, payer.PublicKey(), senderPDA0, vaultPDA,
			depProofA, depProofB, depProofC,
			depCommitB, depCommitHash,
			depDeltaC1B, depDeltaC2B,
			uint64(depositAmount),
		))

	// Check: sender 0 ciphertext should equal deposit delta
	ctx := context.Background()
	senderData0 := mustGetAccountData(client, ctx, senderPDA0)
	checkField("sender0 c1 after deposit", senderData0[64:128], depDeltaC1B[:])
	checkField("sender0 c2 after deposit", senderData0[128:192], depDeltaC2B[:])

	// ── 15. Ring Transfer ─────────────────────────────────────────────────────
	logf("Ring transfer (amount=%d, ZK proof verified on-chain)…", transferAmount)
	ringTransferSig := sendAndConfirm(client, payer,
		ixSetComputeUnitLimit(1_400_000),
		ixRingTransfer(
			programID,
			senderPDA0, senderPDA1,
			recvPDA0, recvPDA1,
			xferProofA, xferProofB, xferProofC,
			xferCommitB, xferCommitHash,
			realNewC1B, realNewC2B,
			decoyNewC1B, decoyNewC2B,
			transferC1B, transferC2B,
			decoyDeltaC1B, decoyDeltaC2B,
		))
	logComputeUnits(client, ringTransferSig)
	writeLocalEnv(programIDStr, ringTransferSig.String())

	// ── 16. Withdraw — receiver withdraws withdrawAmount lamports from vault ──
	// The vault holds the deposited lamports; the receiver's ZK proof entitles
	// them to withdraw their share without revealing their identity.
	logf("Withdrawing %d lamports from vault to receiver 0 (ZK proof verified on-chain)…", withdrawAmount)
	sendAndConfirm(client, payer,
		ixSetComputeUnitLimit(800_000),
		ixWithdraw(programID, recvPDA0, vaultPDA, payer.PublicKey(),
			wdProofA, wdProofB, wdProofC,
			wdCommitB, wdCommitHash,
			recvNewC1B, recvNewC2B,
			uint64(withdrawAmount),
		))

	// ── 18. Verify on-chain ciphertext state ──────────────────────────────────
	logf("Verifying on-chain ciphertext state…")

	senderData0 = mustGetAccountData(client, ctx, senderPDA0)
	checkField("sender0 c1 after transfer", senderData0[64:128], realNewC1B[:])
	checkField("sender0 c2 after transfer", senderData0[128:192], realNewC2B[:])

	senderData1 := mustGetAccountData(client, ctx, senderPDA1)
	checkField("sender1 c1 after transfer", senderData1[64:128], decoyNewC1B[:])
	checkField("sender1 c2 after transfer", senderData1[128:192], decoyNewC2B[:])

	// Receiver 0 started at zero; delta added = transferC1/C2
	recvData0 := mustGetAccountData(client, ctx, recvPDA0)
	checkField("recv0 c1 after transfer", recvData0[64:128], recvNewC1B[:])
	checkField("recv0 c2 after transfer", recvData0[128:192], recvNewC2B[:])

	recvData1 := mustGetAccountData(client, ctx, recvPDA1)
	checkField("recv1 c1 after transfer", recvData1[64:128], decoyDeltaC1B[:])
	checkField("recv1 c2 after transfer", recvData1[128:192], decoyDeltaC2B[:])

	// ── 19. Decrypt balances via BSGS ─────────────────────────────────────────
	logf("Decrypting balances…")

	s0C1 := g1FromBytes(senderData0[64:128])
	s0C2 := g1FromBytes(senderData0[128:192])
	s1C1 := g1FromBytes(senderData1[64:128])
	s1C2 := g1FromBytes(senderData1[128:192])
	r0C1 := g1FromBytes(recvData0[64:128])
	r0C2 := g1FromBytes(recvData0[128:192])
	r1C1 := g1FromBytes(recvData1[64:128])
	r1C2 := g1FromBytes(recvData1[128:192])

	checkBalance("sender0 (real)",  decryptBalance(s0C1, s0C2, senderSk,    &bsgs), depositAmount-transferAmount) // 600
	checkBalance("sender1 (decoy)", decryptBalance(s1C1, s1C2, decoySk,     &bsgs), depositAmount)               // 1000
	checkBalance("recv0   (real)",  decryptBalance(r0C1, r0C2, recvSk,      &bsgs), recvNewBalance)              // 100
	checkBalance("recv1   (decoy)", decryptBalance(r1C1, r1C2, decoyRecvSk, &bsgs), 0)

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

// ixDeposit builds opcode-2 deposit data (489 bytes total):
//
//	proof(256) || commitment(64) || commitHash(32) || deltaC1(64) || deltaC2(64) || amount(8 LE)
func ixDeposit(
	programID, payer, pda, vault solanago.PublicKey,
	proofA [64]byte, proofB [128]byte, proofC [64]byte,
	commitment [64]byte, commitHash [32]byte,
	deltaC1, deltaC2 [64]byte,
	amount uint64,
) solanago.Instruction {
	data := make([]byte, 489)
	off := 0
	data[off] = 0x02; off++
	copy(data[off:off+64], proofA[:]); off += 64
	copy(data[off:off+128], proofB[:]); off += 128
	copy(data[off:off+64], proofC[:]); off += 64
	copy(data[off:off+64], commitment[:]); off += 64
	copy(data[off:off+32], commitHash[:]); off += 32
	copy(data[off:off+64], deltaC1[:]); off += 64
	copy(data[off:off+64], deltaC2[:]); off += 64
	binary.LittleEndian.PutUint64(data[off:off+8], amount); off += 8
	if off != 489 {
		panic(fmt.Sprintf("ixDeposit: expected 489 bytes, got %d", off))
	}
	return &solanago.GenericInstruction{
		ProgID: programID,
		AccountValues: solanago.AccountMetaSlice{
			solanago.Meta(payer).WRITE().SIGNER(),
			solanago.Meta(pda).WRITE(),
			solanago.Meta(vault).WRITE(),
			solanago.Meta(solanago.SystemProgramID),
		},
		DataBytes: data,
	}
}

// ixRingTransfer builds opcode-1 ring transfer data (865 bytes total):
//
//	proof(256) || commitment(64) || commitHash(32)
//	|| senderNewC1[0](64) || senderNewC2[0](64)
//	|| senderNewC1[1](64) || senderNewC2[1](64)
//	|| recvDeltaC1[0](64) || recvDeltaC2[0](64)
//	|| recvDeltaC1[1](64) || recvDeltaC2[1](64)
func ixRingTransfer(
	programID solanago.PublicKey,
	senderPDA0, senderPDA1 solanago.PublicKey,
	recvPDA0, recvPDA1 solanago.PublicKey,
	proofA [64]byte, proofB [128]byte, proofC [64]byte,
	commitment [64]byte, commitHash [32]byte,
	senderNewC10, senderNewC20 [64]byte,
	senderNewC11, senderNewC21 [64]byte,
	recvDeltaC10, recvDeltaC20 [64]byte,
	recvDeltaC11, recvDeltaC21 [64]byte,
) solanago.Instruction {
	data := make([]byte, 865)
	off := 0
	data[off] = 0x01; off++
	copy(data[off:off+64], proofA[:]); off += 64
	copy(data[off:off+128], proofB[:]); off += 128
	copy(data[off:off+64], proofC[:]); off += 64
	copy(data[off:off+64], commitment[:]); off += 64
	copy(data[off:off+32], commitHash[:]); off += 32
	copy(data[off:off+64], senderNewC10[:]); off += 64
	copy(data[off:off+64], senderNewC20[:]); off += 64
	copy(data[off:off+64], senderNewC11[:]); off += 64
	copy(data[off:off+64], senderNewC21[:]); off += 64
	copy(data[off:off+64], recvDeltaC10[:]); off += 64
	copy(data[off:off+64], recvDeltaC20[:]); off += 64
	copy(data[off:off+64], recvDeltaC11[:]); off += 64
	copy(data[off:off+64], recvDeltaC21[:]); off += 64
	if off != 865 {
		panic(fmt.Sprintf("ixRingTransfer: expected 865 bytes, got %d", off))
	}
	return &solanago.GenericInstruction{
		ProgID: programID,
		AccountValues: solanago.AccountMetaSlice{
			solanago.Meta(senderPDA0).WRITE(),
			solanago.Meta(senderPDA1).WRITE(),
			solanago.Meta(recvPDA0).WRITE(),
			solanago.Meta(recvPDA1).WRITE(),
		},
		DataBytes: data,
	}
}

// ixWithdraw builds opcode-3 withdraw data (489 bytes total):
//
//	proof(256) || commitment(64) || commitHash(32) || newC1(64) || newC2(64) || amount(8 LE)
func ixWithdraw(
	programID, pda, vault, destination solanago.PublicKey,
	proofA [64]byte, proofB [128]byte, proofC [64]byte,
	commitment [64]byte, commitHash [32]byte,
	newC1, newC2 [64]byte,
	amount uint64,
) solanago.Instruction {
	data := make([]byte, 489)
	off := 0
	data[off] = 0x03; off++
	copy(data[off:off+64], proofA[:]); off += 64
	copy(data[off:off+128], proofB[:]); off += 128
	copy(data[off:off+64], proofC[:]); off += 64
	copy(data[off:off+64], commitment[:]); off += 64
	copy(data[off:off+32], commitHash[:]); off += 32
	copy(data[off:off+64], newC1[:]); off += 64
	copy(data[off:off+64], newC2[:]); off += 64
	binary.LittleEndian.PutUint64(data[off:off+8], amount); off += 8
	if off != 489 {
		panic(fmt.Sprintf("ixWithdraw: expected 489 bytes, got %d", off))
	}
	return &solanago.GenericInstruction{
		ProgID: programID,
		AccountValues: solanago.AccountMetaSlice{
			solanago.Meta(pda).WRITE(),
			solanago.Meta(vault).WRITE(),
			solanago.Meta(destination).WRITE(),
		},
		DataBytes: data,
	}
}

// ── RPC helpers ───────────────────────────────────────────────────────────────

func ixSetComputeUnitLimit(units uint32) solanago.Instruction {
	data := []byte{2, byte(units), byte(units >> 8), byte(units >> 16), byte(units >> 24)}
	computeBudgetProgramID := solanago.MustPublicKeyFromBase58("ComputeBudget111111111111111111111111111111")
	return &solanago.GenericInstruction{
		ProgID:        computeBudgetProgramID,
		AccountValues: solanago.AccountMetaSlice{},
		DataBytes:     data,
	}
}

func sendAndConfirm(client *rpc.Client, payer solanago.PrivateKey, ixs ...solanago.Instruction) solanago.Signature {
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
	return sig
}

func logComputeUnits(client *rpc.Client, sig solanago.Signature) {
	ctx := context.Background()
	maxVersion := uint64(0)
	resp, err := client.GetTransaction(ctx, sig, &rpc.GetTransactionOpts{
		Commitment:                     rpc.CommitmentConfirmed,
		MaxSupportedTransactionVersion: &maxVersion,
	})
	if err != nil || resp == nil || resp.Meta == nil || resp.Meta.ComputeUnitsConsumed == nil {
		logf("  compute units: (unavailable)")
		return
	}
	logf("  compute units: %d / 1,400,000", *resp.Meta.ComputeUnitsConsumed)
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

func checkBalance(label string, got, want uint32) {
	if got != want {
		fatalf("BALANCE MISMATCH %s: got %d, want %d", label, got, want)
	}
	logf("  ✓ %s balance = %d", label, got)
}

func checkField(label string, got, want []byte) {
	for i := range want {
		if got[i] != want[i] {
			fatalf("MISMATCH %s at byte %d: got %02x, want %02x", label, i, got[i], want[i])
		}
	}
	logf("  ✓ %s", label)
}

// ── BN254 serialisation / BSGS helpers ───────────────────────────────────────

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

func g1FromBytes(b []byte) bn254.G1Affine {
	var p bn254.G1Affine
	p.X.SetBytes(b[:32])
	p.Y.SetBytes(b[32:64])
	return p
}

// decryptBalance recovers v from an ElGamal ciphertext (C1, C2) and secret key sk.
// v·G = C2 - sk·C1; then BSGS solves for v.
func decryptBalance(C1, C2 bn254.G1Affine, sk bn254fr.Element, t *bsgsTable) uint32 {
	var skInt big.Int
	sk.BigInt(&skInt)
	var skC1 bn254.G1Affine
	skC1.ScalarMultiplication(&C1, &skInt)
	var vG bn254.G1Affine
	vG.Sub(&C2, &skC1)
	v, ok := t.solve(vG)
	if !ok {
		fatalf("BSGS: discrete log not found (balance out of range?)")
	}
	return v
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
