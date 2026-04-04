# Security Audit — Laurelin

Conducted 2026-04-04, post-BJJ migration.

Covers the full Rust codebase: `contract/` (on-chain program), `circuit/` (ark-groth16 R1CS circuits), `wallet/` (CLI + in-process prover).

---

## CRITICAL

### C-1. CreateAccount accepted arbitrary initial ciphertext (vault theft)

The `CreateAccount` instruction previously accepted caller-supplied `c1` and `c2` values without proof they encrypt zero. An attacker could create an account with a ciphertext encrypting an arbitrary balance, then immediately withdraw real SOL from the vault.

**Status: FIXED (2026-04-04).** `CreateAccount` now only accepts a BJJ public key. The contract hardcodes the identity ciphertext `(0, 1)` for both c1 and c2. Instruction payload shrunk from 193 to 65 bytes.

### C-2. Withdraw destination not bound to proof (front-running)

The withdraw instruction takes `[pda, vault_pda, destination]` as accounts, but no account requires a signer flag, and the `destination` address is not included in the Groth16 public inputs. An attacker monitoring the mempool can copy the proof from a pending withdraw transaction and submit a new transaction with the same proof but their own destination address.

**Status: OPEN.** Fix options: (a) require `destination` to be a signer, or (b) add a hash of the destination pubkey to the circuit's public inputs.

---

## HIGH

### H-1. No signer verification on ring transfer accounts

The ring transfer instruction does not require any account to be a signer. While the Groth16 proof cryptographically proves knowledge of the sender's secret key, the lack of a Solana-level signer means any party who obtains a valid proof can submit it. This violates defense-in-depth.

**Status: OPEN.**

### H-2. No duplicate account check in ring transfer

The ring transfer accepts 4 account keys `[sender0, sender1, recv0, recv1]` without verifying they are all distinct. If a PDA appears in multiple positions, the sequential writes cause state corruption — the later write overwrites the earlier one.

**Status: OPEN.** Fix: add pairwise inequality checks on the 4 account keys in `process_ring_transfer`.

### H-3. No subgroup membership check on BJJ points

Baby JubJub has cofactor 8. Neither the on-chain program nor the wallet verifies that public keys or ciphertext points are in the prime-order subgroup. Small-order points could leak information about the real sender/receiver index through re-randomization behavior.

**Status: OPEN.** Fix: validate subgroup membership when registering a public key in `CreateAccount`. Wallet should also validate points received from the chain.

---

## MEDIUM

### M-1. Non-canonical field elements not rejected on-chain

`contract/src/bjj.rs` `fr_from_be` converts 32 big-endian bytes to limbs without checking the value is less than the BN254 Fr modulus. Values >= p fed into Montgomery arithmetic produce incorrect results, corrupting on-chain ciphertext state.

**Status: OPEN.** Fix: add a `>= p` check in `fr_from_be` or at the instruction parsing layer.

### M-2. V1 plaintext wallet key material not zeroized during load

When loading a V1 (plaintext) wallet, hex-decoded secret key bytes in `Vec<u8>` are not explicitly zeroized before being dropped. The key material persists on the heap until overwritten.

**Status: OPEN.**

### M-3. Vault creation asymmetry

Deposits transfer SOL to the vault via `system_instruction::transfer` (requires system-owned account), but withdrawals use raw lamport manipulation (`**vault_pda.lamports.borrow_mut() -= amount`). This asymmetry works because the vault is program-owned after creation, but is fragile.

**Status: OPEN.**

---

## LOW

### L-1. BSGS table X-coordinate key collision

The BSGS baby-step table uses the 32-byte X coordinate as the HashMap key. Two points sharing the same X (one being the Y-negation of the other) would collide. Extremely low probability for the 2^16 table.

**Status: Accepted (negligible risk).**

### L-2. Timing side-channel in on-chain field arithmetic

`ge_p` uses early-return comparison, creating data-dependent timing. Minimal practical impact — on-chain execution timing is noisy, and the values compared are intermediate results, not secret keys.

**Status: Accepted.**

### L-3. Proving key files loaded without integrity verification

PK files are deserialized without hash verification. A local attacker who modifies PK files could generate proofs for a backdoored circuit. However, the on-chain VK would need to match, limiting exploitability.

**Status: Accepted (requires local compromise).**

---

## INFORMATIONAL

- **Trusted setup**: Uses single-party `rand::thread_rng()` randomness. Toxic waste not explicitly destroyed. No MPC ceremony. Standard limitation for development; must be addressed before production.
- **BJJ secret key not zeroized after conversion to BJJFr**: `wallet.laurelin_sk_fr()` returns a `BJJFr` that doesn't implement `Zeroize`. The scalar persists on the stack.
- **On-chain amount not capped to circuit range**: The contract accepts `amount` as `u64` but the circuit range-checks to `[0, 2^32)`. Out-of-range amounts fail at proof generation, not on-chain. Wastes gas for impossible transactions.
- **Config file permissions**: `~/.laurelin/config.json` written without restrictive permissions. Contains `program_id` and `rpc_url` (not secrets, but a local attacker could redirect to a malicious RPC).
- **Integration test coverage**: All 4 `senderIdx x recvIdx` combinations tested. Full deposit/transfer/withdraw cycle with BSGS balance verification at each step.

---

## Remediation Priority

1. **C-2**: Withdraw front-running — require destination signer or bind to proof
2. **H-2**: Duplicate account check in ring transfer
3. **H-3**: Subgroup membership validation on BJJ points
4. **M-1**: Canonical field element validation
5. **H-1**: Signer requirement on transfers (defense-in-depth)
