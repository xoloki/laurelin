# Laurelin — Design Decisions

This document explains the key design choices and the tradeoffs behind them. The README covers *what* the system does; this covers *why* it works the way it does.

---

## Proof system: Groth16 over BN254

**Why Groth16?**
Groth16 produces constant-size proofs (192 bytes: A, B, C) regardless of circuit complexity, and verification is a fixed-cost operation: one linear combination over the public inputs followed by 3–4 pairing checks. This makes on-chain verification cost predictable and bounded.

**Why BN254?**
Solana has a native precompile (`alt_bn128`) for BN254 point operations and pairings. Without it, verifying a Groth16 proof on-chain would be impossible within any reasonable compute budget. BN254 is the only curve with this first-class support on Solana.

**The compute budget constraint**
The ring transfer instruction hits 1.4M compute units — the transaction maximum. This is driven primarily by the Groth16 linear combination over 129 public inputs (one G1 scalar mul per input) plus the pairings. The large public input count is inherent to the DEROHE design: all four accounts' old and new ciphertexts must be public so the on-chain program can update state. If the ring size were doubled from 2 to 4, the instruction would exceed the budget entirely.

---

## Why gnark for the circuit?

gnark is the best-maintained Go library for Groth16 over BN254. The prover runs off-chain as a subprocess (the Go binary `laurelin-prover`), called by the Rust wallet client via JSON over stdin/stdout. This keeps the Rust wallet thin and avoids pulling gnark's large dependency tree into the Rust build.

---

## Emulated fields: the cost of same-curve construction

Groth16 over BN254 means the constraint system (R1CS) does all arithmetic natively over BN254's **scalar field Fr**. This is the "free" field inside the circuit.

BN254 G1 points have coordinates in BN254's **base field Fp**, which is a different prime from Fr. Since the circuit can only do arithmetic natively over Fr, any operation involving point coordinates (additions, scalar multiplications, equality checks) must simulate Fp arithmetic using Fr operations — representing each Fp element as four 64-bit Fr limbs and re-implementing field multiplication and reduction from scratch. This is called *emulated arithmetic* and is the dominant cost of the 30-second proving time.

The root cause is that we use BN254 for both the proof system (outer curve) and the ElGamal encryption (inner curve). Using a different outer curve whose scalar field equalled BN254's base field would eliminate the emulation overhead — this is the idea behind *curve cycles* like Pallas/Vesta. But BN254 is the only curve with native Solana precompile support, so there is no viable alternative outer curve for this deployment target.

---

## Balance range: 32-bit (max ~4.3 SOL)

All balance and amount values are range-checked to 32 bits in the circuit (`ToBinary(x, 32)`). This caps the maximum confidential balance at 2³² lamports ≈ 4.3 SOL.

This is an intentional tradeoff: extending to 64 bits would roughly double proving time for the three scalar multiplications that use balance-derived scalars (`B×G`, `V×G`, `(B−V)×G`). At 30 seconds per proof, doubling even part of that cost is significant.

The BSGS decryption table (used client-side to recover balances from ciphertexts) also scales as O(√range): the current 2³² range uses 2¹⁶ baby steps (~2s build time). Moving to 2⁴⁰ would require 2²⁰ steps (~32s) and is not viable without caching or a redesigned algorithm.

The 32-bit limit is acceptable for the current use case. When it needs to change, the right approach is:
1. Extend the circuit range checks to the target bit width
2. Cache the BSGS table to disk (it is deterministic; build once, load on subsequent runs)
3. Re-run trusted setup (circuit change requires new proving/verification keys and program redeployment)

---

## Ring size: 2+2

The transfer ring uses 2 senders and 2 receivers. This is the minimum ring size that provides any anonymity (the real sender is hidden among 2 candidates, as is the real receiver).

Ring size is constrained from above by the compute budget: each additional ring member adds 8 more G1 points to the public input set (16 field elements × 4 limbs = more scalar muls in the linear combination) and 2 more constraints in the circuit. At ring size 2, we are already at the compute budget ceiling.

---

## ElGamal encryption and the DEROHE protocol

Balances are stored as ElGamal ciphertexts under the user's BN254 public key:

```
C1 = r × G
C2 = r × pk + v × G
```

Transfers use *homomorphic addition*: the receiver's balance ciphertext is updated by adding a delta ciphertext (encrypting the transfer amount) component-wise. The sender's new ciphertext re-encrypts the reduced balance. Neither the amount nor the identities of sender or receiver are revealed on-chain.

This follows the [DEROHE](https://github.com/deroproject/derohe) protocol, adapted from its original Monero-style chain to Solana's account model.

**Why not commit-reveal or Tornado-style nullifiers?**
Nullifier schemes require storing a growing set of spent commitments on-chain. The DEROHE approach instead updates ciphertext state in place, keeping per-account storage constant at 192 bytes regardless of transaction history.

---

## Keypair design: two separate keys per wallet

Each wallet holds two independent keypairs:

- **Solana keypair** (Ed25519): signs transactions, pays fees, holds native SOL
- **Laurelin keypair** (BN254): the ElGamal key used for confidential balance encryption

These are intentionally unlinked. The Laurelin public key (the X coordinate of `sk × G`) is the identifier in the confidential system; the Solana public key is the identifier in the base layer. This means on-chain observers cannot correlate a user's confidential activity with their Solana address.

The Solana public key is stored unencrypted in the wallet file (for read-only operations like checking SOL balance and transaction history). The Ed25519 seed and BN254 scalar are each encrypted separately with AES-256-GCM under an Argon2id-derived key.

---

## SOL backing: vault PDA

Native SOL deposited into the confidential system is held in a single program-derived vault account (`seeds = [b"vault"]`). All deposits add to the vault; all withdrawals subtract from it. The on-chain program enforces that withdrawals cannot exceed the vault balance.

This is a simple custodial model. The vault holds the aggregate of all users' confidential balances, not individual allocations — individual balances are tracked only through the ciphertext state.

---

## BSGS decryption

Recovering a balance from a ciphertext requires solving the discrete logarithm: given `v × G`, find `v`. This is done with baby-step giant-step (BSGS) with M = 2¹⁶, covering the range [0, 2³²) in O(M) time and space. The table is built once per process invocation and reused for all decrypt operations in that session.

Pollard's kangaroo algorithm has the same O(√N) asymptotic cost and lower memory usage, but offers no wall-clock advantage over BSGS for this range — both algorithms pay the same per-step cost (a BN254 affine point conversion). The primary benefit of kangaroo would be working over arbitrary ranges without a fixed precomputed table, which is only relevant if the balance range is extended.
