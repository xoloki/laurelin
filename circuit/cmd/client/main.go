// Integration client: exercises the full Laurelin cycle on a local validator.
//
// Realistic 4-user test:
//   Alice(1000), Bob(800), Carol(600), Dave(400) each deposit their initial balance.
//   4 ring transfers cover every SenderIdx×RecvIdx combination:
//     T1 senderIdx=0 recvIdx=0: Alice→Carol  200
//     T2 senderIdx=0 recvIdx=1: Alice→Dave   150
//     T3 senderIdx=1 recvIdx=0: Bob→Carol    100
//     T4 senderIdx=1 recvIdx=1: Bob→Dave      80
//   Expected balances after transfers: Alice=650, Bob=620, Carol=900, Dave=630.
//   All 4 users then withdraw their full balance; final encrypted balances = 0.
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
)

// ── Package-level geometry ────────────────────────────────────────────────────

var G bn254.G1Affine

func init() { _, _, G, _ = bn254.Generators() }

// ── Arithmetic helpers ────────────────────────────────────────────────────────

func mulG1(p bn254.G1Affine, s bn254fr.Element) bn254.G1Affine {
	var n big.Int
	s.BigInt(&n)
	var r bn254.G1Affine
	r.ScalarMultiplication(&p, &n)
	return r
}

func addG1(a, b bn254.G1Affine) bn254.G1Affine {
	var r bn254.G1Affine
	r.Add(&a, &b)
	return r
}

func toFrElem(v uint64) bn254fr.Element {
	var e bn254fr.Element
	e.SetUint64(v)
	return e
}

func randFrElem() bn254fr.Element {
	var e bn254fr.Element
	if _, err := e.SetRandom(); err != nil {
		fatalf("randFrElem: %v", err)
	}
	return e
}

// ── User ──────────────────────────────────────────────────────────────────────

type User struct {
	name    string
	bn254SK bn254fr.Element
	bn254PK bn254.G1Affine
	pkBytes [64]byte
	pda     solanago.PublicKey
	c1, c2  bn254.G1Affine // current on-chain ciphertext (tracked locally)
	balance uint32
}

func newUser(name string, programID solanago.PublicKey) *User {
	sk := randFrElem()
	var n big.Int
	sk.BigInt(&n)
	var pk bn254.G1Affine
	pk.ScalarMultiplication(&G, &n)
	pkB := g1Bytes(&pk)
	pda, _, err := solanago.FindProgramAddress([][]byte{pkB[:32]}, programID)
	if err != nil {
		fatalf("newUser %s PDA: %v", name, err)
	}
	return &User{name: name, bn254SK: sk, bn254PK: pk, pkBytes: pkB, pda: pda}
}

// ── ZK operations ────────────────────────────────────────────────────────────

func doDeposit(
	client *rpc.Client, payer solanago.PrivateKey,
	programID, vaultPDA solanago.PublicKey,
	user *User, amount uint32,
	depositCCS constraint.ConstraintSystem, depositPK groth16.ProvingKey,
) {
	r := randFrElem()
	var rInt big.Int
	r.BigInt(&rInt)
	deltaC1 := mulG1(G, r)
	deltaC2 := addG1(mulG1(user.bn254PK, r), mulG1(G, toFrElem(uint64(amount))))

	depWitness := &xfer.DepositCircuit{
		R:       emulated.ValueOf[sw_bn254.ScalarField](&rInt),
		Pk:      sw_bn254.NewG1Affine(user.bn254PK),
		DeltaC1: sw_bn254.NewG1Affine(deltaC1),
		DeltaC2: sw_bn254.NewG1Affine(deltaC2),
		Amount:  amount,
	}
	logf("Proving deposit for %s (amount=%d)…", user.name, amount)
	proofA, proofB, proofC, commitB, commitHash := proveCircuit(depositCCS, depositPK, depWitness)

	deltaC1B := g1Bytes(&deltaC1)
	deltaC2B := g1Bytes(&deltaC2)
	sendAndConfirm(client, payer,
		ixSetComputeUnitLimit(500_000),
		ixDeposit(programID, payer.PublicKey(), user.pda, vaultPDA,
			proofA, proofB, proofC, commitB, commitHash,
			deltaC1B, deltaC2B, uint64(amount),
		))

	// Starting from zero ciphertext: new c1/c2 = delta
	user.c1 = addG1(user.c1, deltaC1)
	user.c2 = addG1(user.c2, deltaC2)
	user.balance += amount
}

func doWithdraw(
	client *rpc.Client, payer solanago.PrivateKey,
	programID, vaultPDA solanago.PublicKey,
	user *User, amount uint32,
	withdrawCCS constraint.ConstraintSystem, withdrawPK groth16.ProvingKey,
) {
	newBalance := user.balance - amount
	r := randFrElem()
	var rInt, skInt big.Int
	r.BigInt(&rInt)
	user.bn254SK.BigInt(&skInt)
	newC1 := mulG1(G, r)
	newC2 := addG1(mulG1(user.bn254PK, r), mulG1(G, toFrElem(uint64(newBalance))))

	wdWitness := &xfer.WithdrawCircuit{
		Sk:         emulated.ValueOf[sw_bn254.ScalarField](&skInt),
		RNew:       emulated.ValueOf[sw_bn254.ScalarField](&rInt),
		OldBalance: user.balance,
		NewBalance: newBalance,
		Pk:         sw_bn254.NewG1Affine(user.bn254PK),
		OldC1:      sw_bn254.NewG1Affine(user.c1),
		OldC2:      sw_bn254.NewG1Affine(user.c2),
		NewC1:      sw_bn254.NewG1Affine(newC1),
		NewC2:      sw_bn254.NewG1Affine(newC2),
		Amount:     amount,
	}
	logf("Proving withdraw for %s (amount=%d, remaining=%d)…", user.name, amount, newBalance)
	proofA, proofB, proofC, commitB, commitHash := proveCircuit(withdrawCCS, withdrawPK, wdWitness)

	newC1B := g1Bytes(&newC1)
	newC2B := g1Bytes(&newC2)
	sendAndConfirm(client, payer,
		ixSetComputeUnitLimit(800_000),
		ixWithdraw(programID, user.pda, vaultPDA, payer.PublicKey(),
			proofA, proofB, proofC, commitB, commitHash,
			newC1B, newC2B, uint64(amount),
		))

	user.c1 = newC1
	user.c2 = newC2
	user.balance = newBalance
}

func doRingTransfer(
	client *rpc.Client, payer solanago.PrivateKey,
	programID solanago.PublicKey,
	senders, receivers [2]*User,
	senderIdx, recvIdx int,
	amount uint32,
	transferCCS constraint.ConstraintSystem, transferPK groth16.ProvingKey,
) {
	realSender  := senders[senderIdx]
	decoySender := senders[1-senderIdx]
	realRecv    := receivers[recvIdx]
	decoyRecv   := receivers[1-recvIdx]
	newBalance  := realSender.balance - amount

	rNew   := randFrElem()
	rDecoy := randFrElem()
	rT     := randFrElem()
	rRecv  := randFrElem()

	// Real sender: fresh ciphertext encrypting newBalance
	senderNewC1Real  := mulG1(G, rNew)
	senderNewC2Real  := addG1(mulG1(realSender.bn254PK, rNew), mulG1(G, toFrElem(uint64(newBalance))))
	// Decoy sender: re-randomize (same balance, new blinding)
	senderNewC1Decoy := addG1(decoySender.c1, mulG1(G, rDecoy))
	senderNewC2Decoy := addG1(decoySender.c2, mulG1(decoySender.bn254PK, rDecoy))
	// Real receiver: delta ciphertext encrypting amount
	recvDeltaC1Real  := mulG1(G, rT)
	recvDeltaC2Real  := addG1(mulG1(realRecv.bn254PK, rT), mulG1(G, toFrElem(uint64(amount))))
	// Decoy receiver: zero delta (re-randomized)
	recvDeltaC1Decoy := mulG1(G, rRecv)
	recvDeltaC2Decoy := mulG1(decoyRecv.bn254PK, rRecv)

	// Map to ring slots [0] and [1]
	var senderNewC1, senderNewC2 [2]bn254.G1Affine
	var recvDeltaC1, recvDeltaC2 [2]bn254.G1Affine
	senderNewC1[senderIdx]   = senderNewC1Real
	senderNewC2[senderIdx]   = senderNewC2Real
	senderNewC1[1-senderIdx] = senderNewC1Decoy
	senderNewC2[1-senderIdx] = senderNewC2Decoy
	recvDeltaC1[recvIdx]     = recvDeltaC1Real
	recvDeltaC2[recvIdx]     = recvDeltaC2Real
	recvDeltaC1[1-recvIdx]   = recvDeltaC1Decoy
	recvDeltaC2[1-recvIdx]   = recvDeltaC2Decoy

	var skInt, rNewInt, rDecoyInt, rTInt, rRecvInt big.Int
	realSender.bn254SK.BigInt(&skInt)
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
		B:         realSender.balance,
		V:         amount,
		BmV:       newBalance,
		SenderIdx: senderIdx,
		RecvIdx:   recvIdx,

		SenderPk0:    sw_bn254.NewG1Affine(senders[0].bn254PK),
		SenderPk1:    sw_bn254.NewG1Affine(senders[1].bn254PK),
		SenderOldC10: sw_bn254.NewG1Affine(senders[0].c1),
		SenderOldC11: sw_bn254.NewG1Affine(senders[1].c1),
		SenderOldC20: sw_bn254.NewG1Affine(senders[0].c2),
		SenderOldC21: sw_bn254.NewG1Affine(senders[1].c2),
		SenderNewC10: sw_bn254.NewG1Affine(senderNewC1[0]),
		SenderNewC11: sw_bn254.NewG1Affine(senderNewC1[1]),
		SenderNewC20: sw_bn254.NewG1Affine(senderNewC2[0]),
		SenderNewC21: sw_bn254.NewG1Affine(senderNewC2[1]),

		RecvPk0:      sw_bn254.NewG1Affine(receivers[0].bn254PK),
		RecvPk1:      sw_bn254.NewG1Affine(receivers[1].bn254PK),
		RecvDeltaC10: sw_bn254.NewG1Affine(recvDeltaC1[0]),
		RecvDeltaC20: sw_bn254.NewG1Affine(recvDeltaC2[0]),
		RecvDeltaC11: sw_bn254.NewG1Affine(recvDeltaC1[1]),
		RecvDeltaC21: sw_bn254.NewG1Affine(recvDeltaC2[1]),
	}
	logf("Proving ring transfer: %s→%s (senderIdx=%d recvIdx=%d amount=%d)…",
		realSender.name, realRecv.name, senderIdx, recvIdx, amount)
	proofA, proofB, proofC, commitB, commitHash := proveCircuit(transferCCS, transferPK, xferWitness)

	sig := sendAndConfirm(client, payer,
		ixSetComputeUnitLimit(1_400_000),
		ixRingTransfer(
			programID,
			senders[0].pda, senders[1].pda,
			receivers[0].pda, receivers[1].pda,
			proofA, proofB, proofC, commitB, commitHash,
			g1Bytes(&senderNewC1[0]), g1Bytes(&senderNewC2[0]),
			g1Bytes(&senderNewC1[1]), g1Bytes(&senderNewC2[1]),
			g1Bytes(&recvDeltaC1[0]), g1Bytes(&recvDeltaC2[0]),
			g1Bytes(&recvDeltaC1[1]), g1Bytes(&recvDeltaC2[1]),
		))
	logComputeUnits(client, sig)

	// Update in-memory ciphertext state
	senders[0].c1 = senderNewC1[0]
	senders[0].c2 = senderNewC2[0]
	senders[1].c1 = senderNewC1[1]
	senders[1].c2 = senderNewC2[1]
	senders[senderIdx].balance = newBalance

	receivers[0].c1 = addG1(receivers[0].c1, recvDeltaC1[0])
	receivers[0].c2 = addG1(receivers[0].c2, recvDeltaC2[0])
	receivers[1].c1 = addG1(receivers[1].c1, recvDeltaC1[1])
	receivers[1].c2 = addG1(receivers[1].c2, recvDeltaC2[1])
	receivers[recvIdx].balance += amount
}

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

	committed := committedIndices(ccs)
	prehash := make([]byte, 64+len(committed)*32)
	copy(prehash[:64], commitB[:])
	for j, idx := range committed {
		b := pubVec[idx-1].Bytes()
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
	logf("Building BSGS table (range 0..2^32)…")
	bsgs := buildBSGSTable(G)
	logf("BSGS table ready (%d entries)", bsgsM)

	// ── 4. Create users ───────────────────────────────────────────────────────
	alice := newUser("Alice", programID)
	bob   := newUser("Bob",   programID)
	carol := newUser("Carol", programID)
	dave  := newUser("Dave",  programID)
	users := []*User{alice, bob, carol, dave}

	// ── 5. Derive vault PDA ───────────────────────────────────────────────────
	vaultPDA, _, err := solanago.FindProgramAddress([][]byte{[]byte("vault")}, programID)
	if err != nil {
		fatalf("vault PDA: %v", err)
	}
	logf("Vault PDA: %s", vaultPDA)

	// ── 6. CreateAccount — all 4 users ────────────────────────────────────────
	var zeroPoint [64]byte
	for _, u := range users {
		logf("Creating account for %s…", u.name)
		sendAndConfirm(client, payer,
			ixCreateAccount(programID, payer.PublicKey(), u.pda,
				u.pkBytes, zeroPoint, zeroPoint))
	}

	// ── 7. Deposit — each user deposits their initial balance ─────────────────
	doDeposit(client, payer, programID, vaultPDA, alice, 1000, depositCCS, depositPK)
	doDeposit(client, payer, programID, vaultPDA, bob,    800, depositCCS, depositPK)
	doDeposit(client, payer, programID, vaultPDA, carol,  600, depositCCS, depositPK)
	doDeposit(client, payer, programID, vaultPDA, dave,   400, depositCCS, depositPK)

	// ── 8. Ring transfers — all SenderIdx×RecvIdx combos ─────────────────────
	// Sender ring: Alice(slot 0), Bob(slot 1)
	// Receiver ring: Carol(slot 0), Dave(slot 1)
	// Expected final: Alice=650, Bob=620, Carol=900, Dave=630
	senders   := [2]*User{alice, bob}
	receivers := [2]*User{carol, dave}

	doRingTransfer(client, payer, programID, senders, receivers, 0, 0, 200, transferCCS, transferPK)
	doRingTransfer(client, payer, programID, senders, receivers, 0, 1, 150, transferCCS, transferPK)
	doRingTransfer(client, payer, programID, senders, receivers, 1, 0, 100, transferCCS, transferPK)
	doRingTransfer(client, payer, programID, senders, receivers, 1, 1,  80, transferCCS, transferPK)

	// Verify tracked balances match expected
	logf("Verifying tracked balances after transfers…")
	checkBalance("Alice (tracked)", alice.balance, 650)
	checkBalance("Bob   (tracked)", bob.balance,   620)
	checkBalance("Carol (tracked)", carol.balance,  900)
	checkBalance("Dave  (tracked)", dave.balance,   630)

	// ── 9. Withdraw — each user withdraws full balance ────────────────────────
	doWithdraw(client, payer, programID, vaultPDA, alice, alice.balance, withdrawCCS, withdrawPK)
	doWithdraw(client, payer, programID, vaultPDA, bob,   bob.balance,   withdrawCCS, withdrawPK)
	doWithdraw(client, payer, programID, vaultPDA, carol, carol.balance, withdrawCCS, withdrawPK)
	doWithdraw(client, payer, programID, vaultPDA, dave,  dave.balance,  withdrawCCS, withdrawPK)

	// ── 10. Verify final encrypted balances = 0 via BSGS ─────────────────────
	logf("Decrypting final on-chain balances (expect all = 0)…")
	ctx := context.Background()
	for _, u := range users {
		data := mustGetAccountData(client, ctx, u.pda)
		c1 := g1FromBytes(data[64:128])
		c2 := g1FromBytes(data[128:192])
		got := decryptBalance(c1, c2, u.bn254SK, &bsgs)
		checkBalance(u.name+" (on-chain)", got, 0)
	}

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
