# Laurelin

A Solana on-chain program for **confidential token transfers** using Groth16 zero-knowledge proofs over BN254. Balances are stored as ElGamal ciphertexts; transfers are validated by a ZK proof that the sender knows their secret key, the ciphertexts are well-formed, and the balance constraint holds — all without revealing amounts on-chain.

The design follows the [DEROHE](https://github.com/deroproject/derohe) protocol adapted for Solana.

---

## How it works

Each account stores a BN254 ElGamal keypair and a ciphertext of the current balance:

```
pubkey = sk × G          (G1 generator)
C1     = r × G
C2     = r × pk + v × G  (encrypts value v under pubkey)
```

A transfer proves in zero-knowledge:

- The sender knows `sk` such that `pk = sk × G`
- The old ciphertext correctly encrypts the old balance `B`
- The new sender ciphertext correctly encrypts `B − v`
- The transfer ciphertext correctly encrypts `v`
- `0 ≤ v ≤ B < 2³²`

The receiver's balance is updated homomorphically (EC addition) without decryption.

---

## Repository layout

```
src/                     Rust — Solana on-chain program
  lib.rs                 Program entrypoint; REAL_VK; instruction dispatch
  instruction.rs         Instruction parsing (CreateAccount, Transfer)
  state.rs               Account state layout; Groth16Proof type
  groth16.rs             Groth16 verifier (4-pairing check + BSB22 commitment)
  bn254.rs               BN254 primitives via Solana alt_bn128_* syscalls
  client.rs              (unused Rust client stub)

circuit/                 Go — gnark Groth16 circuit and tooling
  circuit.go             TransferCircuit constraint system (gnark v0.10)
  circuit_test.go        Unit test for the circuit

circuit/setup/           Trusted setup
  main.go                Compiles circuit → runs Groth16 setup → saves pk.bin
                         and prints VerificationKey as Rust source

circuit/cmd/client/      Integration test client
  main.go                Generates a proof, submits CreateAccount + Transfer
                         to a local Solana validator, verifies account state

circuit/cmd/klen/        Diagnostic: print NbPublicVariables and K length
circuit/cmd/pubinputs/   Diagnostic: print all gnark public inputs and verify
                         they match the Rust limb decomposition

accounts/                Solana keypair JSON files for local testing
ledger/                  Local validator ledger data
deploy-contract          Shell script: solana program deploy
start-testnet.yml        Docker Compose for local validator (if used)
```

---

## Public input encoding

gnark represents each BN254 Fp coordinate as four 64-bit limbs (little-endian). A G1 point contributes 8 Fr scalars. Seven public points × 8 = **56 scalars**.

gnark v0.10 silently adds a BSB22 commitment (used internally for limb range proofs), giving **IC length = 58**:

| IC index | Value |
|----------|-------|
| 0 | constant wire 1 (unconditional) |
| 1–56 | limbs of SenderPk, OldC1, OldC2, NewSenderC1, NewSenderC2, TransferC1, TransferC2 |
| 57 | BSB22 commitment hash |

The commitment hash is `ExpandMsgXMD(SHA-256, commitment_bytes ∥ limb_0..55, "bsb22-commitment", 48)` reduced mod the BN254 scalar field. It is computed in Go and passed in the instruction; `proof.Commitments[0]` is added directly to `vk_x` before the pairing check.

---

## Running locally

### Prerequisites

- Rust + `cargo build-sbf` (Solana BPF toolchain)
- Go ≥ 1.21
- `solana` CLI ≥ 1.18
- A running local validator (`solana-test-validator` or the provided `ledger/`)

### 1. Trusted setup (one-time, or after circuit changes)

```bash
cd circuit
go run ./setup 2>/dev/null > setup/vk_new.rs
# Paste the printed Rust block into src/lib.rs replacing REAL_VK.
```

This saves `circuit/setup/pk.bin` (proving key) and prints the verification key as a Rust static.

### 2. Build and deploy the Solana program

```bash
cargo build-sbf
./deploy-contract
# Prints: Program Id: <PROGRAM_ID>
```

### 3. Run the integration test

```bash
cd circuit
go run ./cmd/client <PROGRAM_ID>
```

This generates a fresh proof, submits CreateAccount (sender balance = 1000) + CreateAccount (receiver, zero) + Transfer (amount = 400) to the local validator, then verifies the on-chain ciphertext updates.

Expected output ends with:
```
  ✓ sender c1
  ✓ sender c2
  ✓ recv c1
  ✓ recv c2
All checks passed ✓
```

---

## Instruction format

### `CreateAccount` (opcode 0)

| Field | Bytes | Description |
|-------|-------|-------------|
| opcode | 1 | `0x00` |
| pubkey | 64 | BN254 G1 point `sk × G` (x ∥ y, big-endian) |
| c1 | 64 | Initial ciphertext C1 |
| c2 | 64 | Initial ciphertext C2 |

Accounts: `[payer (write, signer), pda (write), system_program]`

PDA seed: first 32 bytes of `pubkey` (the X coordinate).

### `Transfer` (opcode 1)

| Field | Bytes | Description |
|-------|-------|-------------|
| opcode | 1 | `0x01` |
| proof.A | 64 | Groth16 proof A (G1, x ∥ y) |
| proof.B | 128 | Groth16 proof B (G2, EIP-197: x_c1 ∥ x_c0 ∥ y_c1 ∥ y_c0) |
| proof.C | 64 | Groth16 proof C (G1, x ∥ y) |
| commitment | 64 | gnark BSB22 commitment point (G1, x ∥ y) |
| commit_hash | 32 | BSB22 hash scalar (big-endian Fr element) |
| new_sender_c1 | 64 | Updated sender ciphertext C1 |
| new_sender_c2 | 64 | Updated sender ciphertext C2 |
| transfer_c1 | 64 | Transfer delta ciphertext C1 |
| transfer_c2 | 64 | Transfer delta ciphertext C2 |

Total: 609 bytes. Requires `SetComputeUnitLimit(1_400_000)` prepended in the transaction.

Accounts: `[sender_pda (write), receiver_pda (write)]`
