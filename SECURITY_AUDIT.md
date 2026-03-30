# Security Audit — Laurelin

Conducted 2026-03-29, pre-mainnet hardening pass.

---

## Must Verify (Open Questions)

### C1. Ring transfer sender authorization in-circuit

Does the `transfer` circuit include a constraint proving the prover knows `sk` for one of the sender ring members? If not, anyone could construct a valid-looking proof without owning an account.

The ZK proof is intended to be the authorization mechanism — a valid proof implies knowledge of the secret key. But this needs explicit verification in the circuit code before it can be relied upon.

**Response (2026-03-30):** Verified. `selectG1(api, fpField, cond, a, b)` correctly returns `a` when `cond==0` and `b` when `cond==1`. The suspicious comment was documenting gnark's counterintuitive true-value-first `Select` API, not a bug — it has been updated to describe `selectG1`'s own semantics. Step 6 (`SenderPk[senderIdx] = Sk * G`) correctly enforces that the prover knows `sk` for the selected ring member. **No issue.**

### C2. Withdraw destination not bound to signer

The on-chain withdraw handler may allow an arbitrary destination account to be passed. If the program does not verify that destination == signer's Solana pubkey, a malicious RPC or MITM could substitute a different destination address.

---

## Real Issues to Fix

### H1. 32-bit balance cap (~4.3 SOL maximum per account)

ZK circuits range-check amounts with `ToBinary(x, 32)`, capping the maximum confidential balance at 2^32 lamports ≈ **4.3 SOL**. Depositing more than this will corrupt the balance. Must be extended to at least 40–50 bits before mainnet.

**Affected files:** `circuit/transfer.go`, `circuit/deposit.go`, `circuit/withdraw.go`

### L1. Wallet file permissions not enforced

`~/.laurelin/wallet.json` is written without explicitly setting `0600` permissions. On systems with a permissive umask, the file may be group- or world-readable.

**Fix:** After writing in `wallet/src/wallet.rs`:
```rust
use std::os::unix::fs::PermissionsExt;
std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
```

### L2. Use `OsRng` for cryptographic key material in wallet

`rand::thread_rng()` is used to generate Argon2 salts and AES-GCM nonces in `wallet/src/wallet.rs`. While `thread_rng()` is seeded from OS entropy and is cryptographically acceptable, explicitly using `rand::rngs::OsRng` makes the intent clear and removes any ambiguity.

---

## Likely False Positives

These were flagged during review but appear safe by design:

- **Proof replay:** Each operation updates the on-chain ciphertext state. A replayed proof will fail verification because the old ciphertext public inputs no longer match the account's current state.
- **Deposit authorization:** Any address can deposit into a PDA without the owner's signature. This is intentional — same semantics as receiving SOL.
- **Vault PDA ownership:** The vault is a program-derived address. It cannot be pre-empted by an attacker.

---

## Remediation Order

1. ~~Verify `transfer` circuit enforces prover knowledge of sender `sk`~~ — **C1 resolved**
2. Verify / fix withdraw destination validation on-chain — **C2**
3. Extend balance range checks from 32-bit to 40+ bits — **H1**
4. Enforce `0600` permissions on wallet file — **L1**
5. Switch salt/nonce generation to `OsRng` — **L2**
