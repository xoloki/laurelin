// Integration client: generates a ring Groth16 transfer proof and submits
// CreateAccount + Transfer instructions to a local Solana validator.
//
// Ring structure: 2 sender accounts, 2 receiver accounts.
// The real sender is ring slot 0; the real receiver is ring slot 0.
//
// Must be run from the circuit/ directory:
//
//	cd circuit && go run ./cmd/client <PROGRAM_ID> [payer-keypair.json]
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

	// ── 2. Compile circuit ────────────────────────────────────────────────────
	logf("Compiling circuit…")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &xfer.RingTransferCircuit{})
	if err != nil {
		fatalf("compile circuit: %v", err)
	}

	// ── 3. Generate keys and parameters ──────────────────────────────────────
	_, _, g1gen, _ := bn254.Generators()
	G := g1gen

	logf("Building BSGS table (range 0..2^32)…")
	bsgs := buildBSGSTable(G)
	logf("BSGS table ready (%d entries)", bsgsM)

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

	const balance, amount = uint32(1000), uint32(400)
	var bFr, vFr, bmvFr bn254fr.Element
	bFr.SetUint64(uint64(balance))
	vFr.SetUint64(uint64(amount))
	bmvFr.SetUint64(uint64(balance - amount))

	// ── Sender ring (2 members; ring slot 0 = real sender) ────────────────────
	sk      := randFr() // real sender secret key
	rOld    := randFr() // old ciphertext randomness
	rNew    := randFr() // new ciphertext randomness
	rDecoy  := randFr() // decoy sender re-rand randomness
	decoySk := randFr() // decoy sender secret key

	realSenderPk  := mul(G, sk)
	realOldC1     := mul(G, rOld)
	realOldC2     := add(mul(realOldC1, sk), mul(G, bFr))
	realNewC1     := mul(G, rNew)
	realNewC2     := add(mul(realNewC1, sk), mul(G, bmvFr))

	decoySenderPk  := mul(G, decoySk)
	decoyRand      := randFr()
	decoyOldC1     := mul(G, decoyRand)
	decoyOldC2     := add(mul(decoyOldC1, decoySk), mul(G, bFr)) // decoy also has balance=1000
	decoyNewC1     := add(decoyOldC1, mul(G, rDecoy))             // re-randomize
	decoyNewC2     := add(decoyOldC2, mul(decoySenderPk, rDecoy))

	// ── Receiver ring (2 members; ring slot 0 = real receiver) ───────────────
	recvSk      := randFr()
	decoyRecvSk := randFr()
	rT          := randFr() // real transfer randomness
	rRecv       := randFr() // decoy recv re-rand randomness

	realRecvPk  := mul(G, recvSk)
	decoyRecvPk := mul(G, decoyRecvSk)

	// Real receiver delta: encrypts V under realRecvPk
	transferC1 := mul(G, rT)
	transferC2 := add(mul(realRecvPk, rT), mul(G, vFr))

	// Decoy receiver delta: encrypts 0 under decoyRecvPk
	decoyDeltaC1 := mul(G, rRecv)
	decoyDeltaC2 := mul(decoyRecvPk, rRecv)

	// ── 4. Build gnark witness ────────────────────────────────────────────────
	var skInt, rNewInt, rDecoyInt, rTInt, rRecvInt big.Int
	sk.BigInt(&skInt)
	rNew.BigInt(&rNewInt)
	rDecoy.BigInt(&rDecoyInt)
	rT.BigInt(&rTInt)
	rRecv.BigInt(&rRecvInt)

	// ring slot 0 = real sender/receiver
	w := &xfer.RingTransferCircuit{
		Sk:        emulated.ValueOf[sw_bn254.ScalarField](&skInt),
		RNew:      emulated.ValueOf[sw_bn254.ScalarField](&rNewInt),
		RDecoy:    emulated.ValueOf[sw_bn254.ScalarField](&rDecoyInt),
		RT:        emulated.ValueOf[sw_bn254.ScalarField](&rTInt),
		RRecv:     emulated.ValueOf[sw_bn254.ScalarField](&rRecvInt),
		B:         balance,
		V:         amount,
		BmV:       balance - amount,
		SenderIdx: 0,
		RecvIdx:   0,

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

	// ── 6. Serialise proof points ─────────────────────────────────────────────
	proofAB := g1Bytes(&proof.Ar)
	proofBB := g2Bytes(&proof.Bs)
	proofCB := g1Bytes(&proof.Krs)

	// ── 6b. Compute BSB22 commitment hash ─────────────────────────────────────
	if len(proof.Commitments) != 1 {
		fatalf("expected 1 commitment, got %d", len(proof.Commitments))
	}
	commitB := g1Bytes(&proof.Commitments[0])

	pubVec := pubWitness.Vector().(bn254fr.Vector)
	prehash := make([]byte, 64+len(pubVec)*32)
	copy(prehash[:64], commitB[:])
	for i, v := range pubVec {
		vBytes := v.Bytes()
		copy(prehash[64+i*32:], vBytes[:])
	}
	h := hash_to_field.New([]byte(constraint.CommitmentDst))
	h.Write(prehash)
	commitHashBytes := h.Sum(nil)
	var commitHash [32]byte
	copy(commitHash[:], commitHashBytes)
	logf("commitment hash: %x", commitHash[:])
	logf("public inputs:   %d scalars", len(pubVec))

	// ── 7. Serialise ciphertext updates ──────────────────────────────────────
	// Sender ring updates
	realNewC1B  := g1Bytes(&realNewC1)
	realNewC2B  := g1Bytes(&realNewC2)
	decoyNewC1B := g1Bytes(&decoyNewC1)
	decoyNewC2B := g1Bytes(&decoyNewC2)

	// Receiver deltas (slot 0 = real, slot 1 = decoy)
	recvDeltaC10B := g1Bytes(&transferC1)
	recvDeltaC20B := g1Bytes(&transferC2)
	recvDeltaC11B := g1Bytes(&decoyDeltaC1)
	recvDeltaC21B := g1Bytes(&decoyDeltaC2)

	// ── 8. Derive PDAs ────────────────────────────────────────────────────────
	realSenderPkB  := g1Bytes(&realSenderPk)
	decoySenderPkB := g1Bytes(&decoySenderPk)
	realRecvPkB    := g1Bytes(&realRecvPk)
	decoyRecvPkB   := g1Bytes(&decoyRecvPk)

	senderPDA0, _, err := solanago.FindProgramAddress([][]byte{realSenderPkB[:32]}, programID)
	if err != nil {
		fatalf("sender PDA 0: %v", err)
	}
	senderPDA1, _, err := solanago.FindProgramAddress([][]byte{decoySenderPkB[:32]}, programID)
	if err != nil {
		fatalf("sender PDA 1: %v", err)
	}
	recvPDA0, _, err := solanago.FindProgramAddress([][]byte{realRecvPkB[:32]}, programID)
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

	// Serialise initial ciphertexts for CreateAccount
	realOldC1B  := g1Bytes(&realOldC1)
	realOldC2B  := g1Bytes(&realOldC2)
	decoyOldC1B := g1Bytes(&decoyOldC1)
	decoyOldC2B := g1Bytes(&decoyOldC2)

	// ── 9. CreateAccount — all 4 ring members ────────────────────────────────
	logf("Creating sender 0 (real, balance=%d)…", balance)
	sendAndConfirm(client, payer, ixCreateAccount(programID, payer.PublicKey(), senderPDA0,
		realSenderPkB, realOldC1B, realOldC2B))

	logf("Creating sender 1 (decoy, balance=%d)…", balance)
	sendAndConfirm(client, payer, ixCreateAccount(programID, payer.PublicKey(), senderPDA1,
		decoySenderPkB, decoyOldC1B, decoyOldC2B))

	logf("Creating receiver 0 (real, balance=0)…")
	var zeroPoint [64]byte
	sendAndConfirm(client, payer, ixCreateAccount(programID, payer.PublicKey(), recvPDA0,
		realRecvPkB, zeroPoint, zeroPoint))

	logf("Creating receiver 1 (decoy, balance=0)…")
	sendAndConfirm(client, payer, ixCreateAccount(programID, payer.PublicKey(), recvPDA1,
		decoyRecvPkB, zeroPoint, zeroPoint))

	// ── 10. Ring Transfer ─────────────────────────────────────────────────────
	logf("Sending ring transfer (amount=%d)…", amount)
	sendAndConfirm(client, payer,
		ixSetComputeUnitLimit(1_400_000),
		ixRingTransfer(
			programID,
			senderPDA0, senderPDA1,
			recvPDA0, recvPDA1,
			proofAB, proofBB, proofCB,
			commitB, commitHash,
			realNewC1B, realNewC2B,
			decoyNewC1B, decoyNewC2B,
			recvDeltaC10B, recvDeltaC20B,
			recvDeltaC11B, recvDeltaC21B,
		))

	// ── 11. Verify on-chain state ─────────────────────────────────────────────
	logf("Verifying on-chain account state…")
	ctx := context.Background()

	// Sender 0: c1 and c2 should be updated to the new real-sender ciphertexts
	senderData0 := mustGetAccountData(client, ctx, senderPDA0)
	checkField("sender0 c1", senderData0[64:128], realNewC1B[:])
	checkField("sender0 c2", senderData0[128:192], realNewC2B[:])

	// Sender 1: c1 and c2 should be re-randomized
	senderData1 := mustGetAccountData(client, ctx, senderPDA1)
	checkField("sender1 c1", senderData1[64:128], decoyNewC1B[:])
	checkField("sender1 c2", senderData1[128:192], decoyNewC2B[:])

	// Receiver 0: started at zero, delta added = transferC1/C2
	recvData0 := mustGetAccountData(client, ctx, recvPDA0)
	checkField("recv0 c1", recvData0[64:128], recvDeltaC10B[:])
	checkField("recv0 c2", recvData0[128:192], recvDeltaC20B[:])

	// Receiver 1: started at zero, delta added = decoy delta
	recvData1 := mustGetAccountData(client, ctx, recvPDA1)
	checkField("recv1 c1", recvData1[64:128], recvDeltaC11B[:])
	checkField("recv1 c2", recvData1[128:192], recvDeltaC21B[:])

	logf("All checks passed ✓")

	// ── 12. Decrypt balances via BSGS ─────────────────────────────────────────
	logf("Decrypting balances…")

	s0C1 := g1FromBytes(senderData0[64:128])
	s0C2 := g1FromBytes(senderData0[128:192])
	s1C1 := g1FromBytes(senderData1[64:128])
	s1C2 := g1FromBytes(senderData1[128:192])
	r0C1 := g1FromBytes(recvData0[64:128])
	r0C2 := g1FromBytes(recvData0[128:192])
	r1C1 := g1FromBytes(recvData1[64:128])
	r1C2 := g1FromBytes(recvData1[128:192])

	checkBalance("sender0 (real)",  decryptBalance(s0C1, s0C2, sk,          &bsgs), balance-amount)
	checkBalance("sender1 (decoy)", decryptBalance(s1C1, s1C2, decoySk,     &bsgs), balance)
	checkBalance("recv0   (real)",  decryptBalance(r0C1, r0C2, recvSk,      &bsgs), amount)
	checkBalance("recv1   (decoy)", decryptBalance(r1C1, r1C2, decoyRecvSk, &bsgs), 0)
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
