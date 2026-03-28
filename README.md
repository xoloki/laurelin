# Laurelin

A Solana on-chain program for **private token transfers** using Groth16 zero-knowledge proofs over BN254. Balances are stored as ElGamal ciphertexts; transfers and withdrawals are validated by ZK proofs that the sender knows their secret key, the ciphertexts are well-formed, and the balance constraint holds — all without revealing amounts, sender, or recipient on-chain.

The design follows the [DEROHE](https://github.com/deroproject/derohe) protocol adapted for Solana.

---

## How it works

Each account stores a BN254 ElGamal keypair and a ciphertext of the current balance:

```
pubkey = sk × G          (G1 generator)
C1     = r × G
C2     = r × pk + v × G  (encrypts value v under pubkey)
```

### Ring Transfer

Uses a **2+2 ring signature**: 2 sender accounts and 2 receiver accounts are included, with only the prover knowing which are real. The proof establishes in zero-knowledge:

- The prover knows `sk` for one member of the sender ring (`pk = sk × G`)
- That member's old ciphertext correctly encrypts balance `B`
- That member's new ciphertext correctly encrypts `B − v`
- The decoy sender's ciphertext is validly re-randomized (same balance, unlinkable)
- One member of the receiver ring receives a ciphertext encrypting `v`
- The decoy receiver's ciphertext is re-randomized (encrypts 0)
- `0 ≤ v ≤ B < 2³²`

All four accounts are updated on-chain; observers cannot determine which sender spent or which receiver received.

### Deposit

No ZK proof required. The deposit amount is public — the client computes a delta ciphertext `(r×G, r×pk + amount×G)` and the program adds it homomorphically to the account's existing ciphertext. The lamport transfer is verified by the runtime.

### Withdraw

A single-account proof. The proof establishes in zero-knowledge:

- The prover knows `sk` for the account (`pk = sk × G`)
- The stored ciphertext correctly encrypts `old_balance` under `sk`
- The new ciphertext correctly encrypts `old_balance − amount`
- `0 ≤ new_balance < 2³²` (no overdraft)

The on-chain program verifies the proof, updates the ciphertext, and transfers `amount` lamports from the PDA to the destination account.

---

## Repository layout

```
src/                     Rust — Solana on-chain program
  lib.rs                 Program entrypoint; includes VK files; instruction dispatch
  instruction.rs         Instruction parsing (CreateAccount, RingTransfer, Withdraw)
  state.rs               Account state layout; Groth16Proof type
  groth16.rs             Groth16 verifier (4-pairing check + BSB22 commitment)
  bn254.rs               BN254 primitives via Solana alt_bn128_* syscalls
  transfer_vk_generated.rs  Auto-generated transfer VK (gitignored; see setup below)
  withdraw_vk_generated.rs  Auto-generated withdraw VK (gitignored; see setup below)
build.rs                 Generates stub VK files if absent (for cargo test)

circuit/                 Go — gnark Groth16 circuits and tooling
  transfer.go            RingTransferCircuit — 2+2 ring constraint system (gnark v0.10)
  transfer_test.go       Unit tests for the ring circuit
  withdraw.go            WithdrawCircuit — single-account balance proof
  withdraw_test.go       Unit tests for the withdraw circuit

circuit/setup/           Trusted setup
  main.go                Compiles circuits → runs Groth16 setup → saves pk files
                         and writes src/*_vk_generated.rs
                         Flags: -circuit transfer|withdraw|all (default: all)

circuit/cmd/client/      Integration test client
  main.go                Generates a proof, submits CreateAccount + RingTransfer
                         to a local Solana validator, verifies account state and
                         decrypts balances via BSGS
  bsgs.go                Baby-step giant-step discrete log solver (range 0..2^32)

circuit/cmd/klen/        Diagnostic: print NbPublicVariables and K length
circuit/cmd/pubinputs/   Diagnostic: print all gnark public inputs and verify
                         they match the Rust limb decomposition

.github/workflows/ci.yml CI: unit tests (Go + Rust) + full integration test

accounts/                Solana keypair JSON files for local testing
ledger/                  Local validator ledger data
deploy-contract          Shell script: solana program deploy
start-testnet.yml        Docker Compose for local validator
```

---

## Public input encoding

gnark represents each BN254 Fp coordinate as four 64-bit limbs (little-endian). A G1 point contributes 8 Fr scalars. gnark v0.10 also silently adds a BSB22 commitment hash as the final public input.

### Ring Transfer — 129 public inputs (IC length 130)

| IC index | Value |
|----------|-------|
| 0 | constant wire 1 |
| 1–128 | limbs of SenderPk0, SenderPk1, SenderOldC10, SenderOldC11, SenderOldC20, SenderOldC21, SenderNewC10, SenderNewC11, SenderNewC20, SenderNewC21, RecvPk0, RecvPk1, RecvDeltaC10, RecvDeltaC20, RecvDeltaC11, RecvDeltaC21 |
| 129 | BSB22 commitment hash |

### Withdraw — 42 public inputs (IC length 43)

| IC index | Value |
|----------|-------|
| 0 | constant wire 1 |
| 1–40 | limbs of Pk, OldC1, OldC2, NewC1, NewC2 (5 G1 points × 8 scalars) |
| 41 | Amount (native field element, u64 big-endian in 32 bytes) |
| 42 | BSB22 commitment hash |

The BSB22 commitment hash is `ExpandMsgXMD(SHA-256, commitment_bytes ∥ limbs, "bsb22-commitment", 48)` reduced mod the BN254 scalar field. It is computed by the Go client and passed in the instruction; `proof.Commitments[0]` is added directly to `vk_x` before the pairing check.

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
go run ./setup                     # both circuits (default)
go run ./setup -circuit transfer   # transfer only
go run ./setup -circuit withdraw   # withdraw only
```

This saves proving keys (`circuit/setup/transfer_pk.bin`, `circuit/setup/withdraw_pk.bin`) and writes verification keys (`src/transfer_vk_generated.rs`, `src/withdraw_vk_generated.rs`), which are `include!`-ed by `src/lib.rs` at compile time.

### 2. Build and deploy the Solana program

```bash
cargo build-sbf
./deploy-contract
# Prints: Program Id: <PROGRAM_ID>
```

### 3. Run unit tests

```bash
# Rust unit tests (no setup required — build.rs generates stub VK files)
cargo test

# Go circuit tests (fast, skips Groth16 prove/verify)
cd circuit && go test -short ./...

# Go circuit tests including Groth16 prove/verify (slow)
cd circuit && go test ./...
```

### 4. Run the integration test

```bash
cd circuit
go run ./cmd/client <PROGRAM_ID> [payer-keypair.json]
```

This generates a fresh ring proof, submits 4× CreateAccount (2 senders, 2 receivers) + RingTransfer (amount = 400) to the local validator, verifies all four on-chain ciphertext updates, and decrypts the resulting balances via BSGS. The payer keypair defaults to `../accounts/account1.json`.

Expected output ends with:
```
  ✓ sender0 c1
  ✓ sender0 c2
  ✓ sender1 c1
  ✓ sender1 c2
  ✓ recv0 c1
  ✓ recv0 c2
  ✓ recv1 c1
  ✓ recv1 c2
All checks passed ✓
Decrypting balances…
  ✓ sender0 (real)  balance = 600
  ✓ sender1 (decoy) balance = 1000
  ✓ recv0   (real)  balance = 400
  ✓ recv1   (decoy) balance = 0
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

### `RingTransfer` (opcode 1)

| Field | Bytes | Description |
|-------|-------|-------------|
| opcode | 1 | `0x01` |
| proof.A | 64 | Groth16 proof A (G1, x ∥ y) |
| proof.B | 128 | Groth16 proof B (G2, EIP-197: x_c1 ∥ x_c0 ∥ y_c1 ∥ y_c0) |
| proof.C | 64 | Groth16 proof C (G1, x ∥ y) |
| commitment | 64 | gnark BSB22 commitment point (G1, x ∥ y) |
| commit_hash | 32 | BSB22 hash scalar (big-endian Fr element) |
| sender_new_c1[0] | 64 | New ciphertext C1 for sender ring member 0 |
| sender_new_c2[0] | 64 | New ciphertext C2 for sender ring member 0 |
| sender_new_c1[1] | 64 | New ciphertext C1 for sender ring member 1 |
| sender_new_c2[1] | 64 | New ciphertext C2 for sender ring member 1 |
| recv_delta_c1[0] | 64 | Delta ciphertext C1 for receiver ring member 0 |
| recv_delta_c2[0] | 64 | Delta ciphertext C2 for receiver ring member 0 |
| recv_delta_c1[1] | 64 | Delta ciphertext C1 for receiver ring member 1 |
| recv_delta_c2[1] | 64 | Delta ciphertext C2 for receiver ring member 1 |

Total: 865 bytes. Requires `SetComputeUnitLimit(1_400_000)` prepended in the transaction.

Accounts: `[senderPDA0 (write), senderPDA1 (write), recvPDA0 (write), recvPDA1 (write)]`

The proof hides which sender account is the real spender and which receiver gets the value. The decoy sender's ciphertext is re-randomized (same balance, unlinkable); the decoy receiver gets a zero-value re-encryption.

### `Withdraw` (opcode 2)

| Field | Bytes | Description |
|-------|-------|-------------|
| opcode | 1 | `0x02` |
| proof.A | 64 | Groth16 proof A (G1, x ∥ y) |
| proof.B | 128 | Groth16 proof B (G2, EIP-197) |
| proof.C | 64 | Groth16 proof C (G1, x ∥ y) |
| commitment | 64 | gnark BSB22 commitment point (G1, x ∥ y) |
| commit_hash | 32 | BSB22 hash scalar |
| new_c1 | 64 | Replacement ciphertext C1 (encrypts old_balance − amount) |
| new_c2 | 64 | Replacement ciphertext C2 |
| amount | 8 | Lamports to withdraw (u64, little-endian) |

Total: 489 bytes.

Accounts: `[pda (write), destination (write)]`

The proof hides the old balance; the program verifies it is sufficient to cover `amount`, updates the ciphertext, and transfers the lamports.
