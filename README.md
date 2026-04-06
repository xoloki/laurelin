# Laurelin

A Solana program for **private token transfers** using Groth16 zero-knowledge proofs over BN254. Balances are stored as ElGamal ciphertexts on Baby JubJub (BJJ); transfers and withdrawals are validated by ZK proofs that the sender knows their secret key, the ciphertexts are well-formed, and the balance constraint holds — all without revealing amounts, sender, or recipient on-chain.

The design follows the [DEROHE](https://github.com/deroproject/derohe) protocol adapted for Solana.

---

## How it works

Each account stores a BJJ ElGamal keypair and a ciphertext of the current balance:

```
pubkey = sk * G          (BJJ generator)
C1     = r * G
C2     = r * pk + v * G  (encrypts value v under pubkey)
```

BJJ is a twisted Edwards curve defined over BN254's scalar field (Fr), so point coordinates are native Groth16 field elements — no emulated arithmetic needed in the circuit.

### Ring Transfer

Uses a **2+2 ring**: 2 sender accounts and 2 receiver accounts are included, with only the prover knowing which are real. The proof establishes in zero-knowledge:

- The prover knows `sk` for one member of the sender ring (`pk = sk * G`)
- That member's old ciphertext correctly encrypts balance `B`
- That member's new ciphertext correctly encrypts `B - v`
- The decoy sender's ciphertext is validly re-randomized (same balance, unlinkable)
- One member of the receiver ring receives a delta ciphertext encrypting `v`
- The decoy receiver's delta encrypts 0 (re-randomization)
- `0 <= v <= B < 2^32`

All four accounts are updated on-chain; observers cannot determine which sender spent or which receiver received.

### Deposit

The deposit amount is public. A Groth16 proof verifies the delta ciphertext `(r*G, r*pk + amount*G)` is correctly formed. The program adds it homomorphically to the account's existing ciphertext and transfers lamports into the vault.

### Withdraw

A single-account proof. The proof establishes in zero-knowledge:

- The prover knows `sk` for the account (`pk = sk * G`)
- The stored ciphertext correctly encrypts `old_balance` under `sk`
- The new ciphertext correctly encrypts `old_balance - amount`
- `0 <= new_balance < 2^32` (no overdraft)

The on-chain program verifies the proof, replaces the ciphertext, and transfers `amount` lamports from the vault to the destination account.

---

## Repository layout

```
contract/                Solana on-chain program (laurelin-contract)
  src/lib.rs             Program entrypoint; instruction dispatch; public input builders
  src/instruction.rs     Instruction parsing (CreateAccount, RingTransfer, Deposit, Withdraw)
  src/state.rs           Account state layout (BJJPoint, Groth16Proof)
  src/groth16.rs         Groth16 verifier (4-pairing check via alt_bn128 syscalls)
  src/bn254.rs           BN254 primitives (G1 mul/add/negate, pairing) via Solana syscalls
  src/bjj.rs             Pure-Rust BJJ field arithmetic (Montgomery CIOS) and point addition
  src/*_vk_generated.rs  Auto-generated verification keys (gitignored; see setup below)
  build.rs               Generates stub VK files if absent (for cargo test)

circuit/                 Groth16 R1CS circuits (laurelin-circuit) + trusted setup binary
  src/deposit.rs         DepositCircuit — delta ciphertext correctness (7 public inputs)
  src/withdraw.rs        WithdrawCircuit — balance proof (11 public inputs)
  src/transfer.rs        RingTransferCircuit<N> — 2+2 ring transfer (32 public inputs at N=2)
  src/gadgets.rs         Shared constraint gadgets (scalar mul, one-hot select, range check)
  src/bin/setup.rs       laurelin-setup: trusted setup binary (generates PK + VK files)

wallet/                  CLI wallet (laurelin-wallet) + integration test
  src/main.rs            CLI entrypoint (clap)
  src/lib.rs             Library re-exports for the integration test binary
  src/bjj.rs             BJJ crypto: ElGamal encrypt/decrypt, BSGS, point serialization
  src/prover.rs          In-process ark-groth16 proving (no subprocess)
  src/wallet.rs          Wallet file management (AES-256-GCM + Argon2id encryption)
  src/rpc.rs             Solana RPC helpers
  src/instructions.rs    Instruction builders
  src/commands/           CLI command implementations
  src/bin/integration_test.rs  Full-cycle integration test binary

.github/workflows/ci.yml  CI: unit tests + integration test (setup, deploy, prove, verify)
SECURITY_AUDIT.md          Current security audit findings
```

---

## Public input encoding

BJJ coordinates are native BN254 Fr elements — each point contributes 2 Fr scalars (X, Y) as public inputs. No limb decomposition or BSB22 commitment.

### Ring Transfer — 32 public inputs (IC length 33)

```
sender_pks[0..2]       (4 Fr)
sender_old_c1[0..2]    (4 Fr)
sender_old_c2[0..2]    (4 Fr)
sender_new_c1[0..2]    (4 Fr)
sender_new_c2[0..2]    (4 Fr)
recv_pks[0..2]         (4 Fr)
recv_delta_c1[0..2]    (4 Fr)
recv_delta_c2[0..2]    (4 Fr)
```

### Deposit — 7 public inputs (IC length 8)

```
pk        (2 Fr)
delta_c1  (2 Fr)
delta_c2  (2 Fr)
amount    (1 Fr)
```

### Withdraw — 11 public inputs (IC length 12)

```
pk      (2 Fr)
old_c1  (2 Fr)
old_c2  (2 Fr)
new_c1  (2 Fr)
new_c2  (2 Fr)
amount  (1 Fr)
```

---

## Running locally

### Prerequisites

- Rust stable + `cargo build-sbf` (Solana SBF toolchain)
- `solana` CLI >= 1.18
- A running local validator (`solana-test-validator`)

### 1. Trusted setup (one-time, or after circuit changes)

```bash
cargo build --release --bin laurelin-setup
./target/release/laurelin-setup --pk-dir /tmp/laurelin-setup --vk-dir contract/src
```

This saves proving keys (`/tmp/laurelin-setup/*_pk.bin`) and writes verification keys (`contract/src/*_vk_generated.rs`), which are `include!`-ed by `contract/src/lib.rs` at compile time.

### 2. Build and deploy the Solana program

```bash
cargo build-sbf --manifest-path contract/Cargo.toml
solana program deploy target/deploy/laurelin.so
# Prints: Program Id: <PROGRAM_ID>
```

### 3. Run unit tests

```bash
# Contract + circuit tests (no setup required — build.rs generates stub VK files)
cargo test --package laurelin-contract --package laurelin-circuit
```

### 4. Run the integration test

```bash
# Full cycle: setup, build, deploy, 4 deposits + 4 transfers + 4 withdrawals
./run-integration-test
```

Or run the test binary directly against an already-deployed program:

```bash
./target/release/laurelin-integration-test <PROGRAM_ID> <PAYER_KEYPAIR> <PK_DIR>
```

The integration test creates 4 wallets, deposits SOL, runs ring transfers covering all `senderIdx x recvIdx` combinations `(0,0), (0,1), (1,0), (1,1)`, withdraws all balances to zero, and verifies every balance via BSGS decryption.

---

## Instruction format

### `CreateAccount` (opcode 0)

| Field | Bytes | Description |
|-------|-------|-------------|
| opcode | 1 | `0x00` |
| pubkey | 64 | BJJ point `sk * G` (X ∥ Y, big-endian) |

Total: 65 bytes.

Accounts: `[payer (write, signer), pda (write), system_program]`

PDA seed: first 32 bytes of `pubkey` (the X coordinate). Initial ciphertext is set to the BJJ identity `(0, 1)` by the contract (zero balance).

### `RingTransfer` (opcode 1)

| Field | Bytes | Description |
|-------|-------|-------------|
| opcode | 1 | `0x01` |
| proof.A | 64 | Groth16 proof A (BN254 G1, X ∥ Y) |
| proof.B | 128 | Groth16 proof B (BN254 G2, EIP-197: x.c1 ∥ x.c0 ∥ y.c1 ∥ y.c0) |
| proof.C | 64 | Groth16 proof C (BN254 G1, X ∥ Y) |
| sender_new_c1[0..2] | 128 | New ciphertext C1 for sender ring members |
| sender_new_c2[0..2] | 128 | New ciphertext C2 for sender ring members |
| recv_delta_c1[0..2] | 128 | Delta ciphertext C1 for receiver ring members |
| recv_delta_c2[0..2] | 128 | Delta ciphertext C2 for receiver ring members |

Total: 769 bytes. Requires `SetComputeUnitLimit(1_400_000)`.

Accounts: `[senderPDA0 (write), senderPDA1 (write), recvPDA0 (write), recvPDA1 (write)]`

### `Deposit` (opcode 2)

| Field | Bytes | Description |
|-------|-------|-------------|
| opcode | 1 | `0x02` |
| proof | 256 | Groth16 proof (A ∥ B ∥ C) |
| delta_c1 | 64 | Delta ciphertext C1 |
| delta_c2 | 64 | Delta ciphertext C2 |
| amount | 8 | Lamports to deposit (u64, little-endian) |

Total: 393 bytes. Requires `SetComputeUnitLimit(1_400_000)`.

Accounts: `[payer (write, signer), pda (write), vault_pda (write), system_program]`

### `Withdraw` (opcode 3)

| Field | Bytes | Description |
|-------|-------|-------------|
| opcode | 1 | `0x03` |
| proof | 256 | Groth16 proof (A ∥ B ∥ C) |
| new_c1 | 64 | Replacement ciphertext C1 (encrypts old_balance - amount) |
| new_c2 | 64 | Replacement ciphertext C2 |
| amount | 8 | Lamports to withdraw (u64, little-endian) |

Total: 393 bytes.

Accounts: `[pda (write), vault_pda (write), destination (write)]`

---

## Wallet CLI

```
laurelin-wallet init [--insecure]        Generate keypair, create wallet file
laurelin-wallet pubkey [--verbose]       Show Solana + BJJ pubkeys (+ PDA)
laurelin-wallet create-account           Register PDA on-chain
laurelin-wallet deposit <lamports>       Deposit SOL into confidential balance
laurelin-wallet transfer <lamports> --to <bjj-pubkey>   Ring transfer
laurelin-wallet withdraw <lamports>      Withdraw from confidential to SOL
laurelin-wallet balance [--sol]          Show SOL and/or confidential balance
laurelin-wallet accounts                 List all on-chain Laurelin accounts
laurelin-wallet send <lamports> --to <addr>   Plain SOL transfer
laurelin-wallet history [--limit N]      Recent transaction history
laurelin-wallet config set-program <id>  Set program ID
laurelin-wallet config set-pk-dir <path> Set proving key directory
laurelin-wallet config set-url <url>     Set RPC URL
```

Wallet files are encrypted with AES-256-GCM (key derived via Argon2id). Use `--insecure` for plaintext (testing only).

---

## Limitations

- **Ring size N=2 only.** Larger rings exceed Solana's 1232-byte transaction limit and 1.4M compute unit budget. See `SECURITY_AUDIT.md` for details.
- **Balance capped at 2^32 lamports (~4.3 SOL).** Circuit range checks use 32-bit decomposition. The wallet rejects amounts above this limit.
- **Single-party trusted setup.** The proving/verification keys are generated by a single party. A multi-party ceremony is required for production use.
