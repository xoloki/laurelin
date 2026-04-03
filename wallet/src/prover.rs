//! In-process Groth16 proving via ark-groth16.
//!
//! Proving keys are loaded from `.bin` files produced by the `laurelin-setup`
//! binary (CanonicalSerialize format).  No subprocess or IPC needed.

use std::fs;
use std::path::Path;

use anyhow::Context;
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ed_on_bn254::{EdwardsAffine, Fr as BJJFr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_std::rand::thread_rng;

use laurelin_circuit::{
    deposit::DepositCircuit, transfer::RingTransferCircuit, withdraw::WithdrawCircuit,
};

// ── Proof result ──────────────────────────────────────────────────────────────

/// Groth16 proof serialised for the Solana on-chain verifier.
///
/// Layout matches `Groth16Proof` in the on-chain program:
///   proof_a (G1, 64B) || proof_b (G2, 128B) || proof_c (G1, 64B)
/// Total: 256 bytes.  No BSB22 commitment.
#[derive(Debug, Clone)]
pub struct ProofBytes {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
}

// ── Serialisation helpers ─────────────────────────────────────────────────────

/// Serialise a G1Affine point to 64-byte X||Y (big-endian Fq coords).
fn g1_to_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    let x = p.x.into_bigint().to_bytes_be();
    let y = p.y.into_bigint().to_bytes_be();
    out[32 - x.len()..32].copy_from_slice(&x);
    out[64 - y.len()..64].copy_from_slice(&y);
    out
}

/// Serialise a G2Affine point to 128-byte EIP-197 format:
///   x.c1 || x.c0 || y.c1 || y.c0  (each 32 bytes, big-endian)
fn g2_to_bytes(p: &G2Affine) -> [u8; 128] {
    fn fq_be(f: &ark_bn254::Fq) -> [u8; 32] {
        let b = f.into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - b.len()..].copy_from_slice(&b);
        out
    }
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&fq_be(&p.x.c1));
    out[32..64].copy_from_slice(&fq_be(&p.x.c0));
    out[64..96].copy_from_slice(&fq_be(&p.y.c1));
    out[96..128].copy_from_slice(&fq_be(&p.y.c0));
    out
}

fn proof_to_bytes(proof: &ark_groth16::Proof<Bn254>) -> ProofBytes {
    ProofBytes {
        proof_a: g1_to_bytes(&proof.a),
        proof_b: g2_to_bytes(&proof.b),
        proof_c: g1_to_bytes(&proof.c),
    }
}

// ── Proving key loading ───────────────────────────────────────────────────────

fn load_pk(path: &Path) -> anyhow::Result<ProvingKey<Bn254>> {
    let data = fs::read(path).with_context(|| format!("read pk {}", path.display()))?;
    ProvingKey::<Bn254>::deserialize_uncompressed(&*data)
        .with_context(|| format!("deserialize pk {}", path.display()))
}

// ── Public prove functions ────────────────────────────────────────────────────

/// Prove a deposit.
pub fn prove_deposit(
    pk_path: &Path,
    r: &BJJFr,
    pk: &EdwardsAffine,
    delta_c1: &EdwardsAffine,
    delta_c2: &EdwardsAffine,
    amount: u64,
) -> anyhow::Result<ProofBytes> {
    let proving_key = load_pk(pk_path)?;
    let circuit = DepositCircuit {
        r: Some(*r),
        pk: Some(*pk),
        delta_c1: Some(*delta_c1),
        delta_c2: Some(*delta_c2),
        amount: Some(amount as u32),
    };
    let mut rng = thread_rng();
    let proof = Groth16::<Bn254>::prove(&proving_key, circuit, &mut rng)
        .context("ark-groth16 deposit prove")?;
    Ok(proof_to_bytes(&proof))
}

/// Prove a withdrawal.
#[allow(clippy::too_many_arguments)]
pub fn prove_withdraw(
    pk_path: &Path,
    sk: &BJJFr,
    r_new: &BJJFr,
    old_balance: u64,
    new_balance: u64,
    pk: &EdwardsAffine,
    old_c1: &EdwardsAffine,
    old_c2: &EdwardsAffine,
    new_c1: &EdwardsAffine,
    new_c2: &EdwardsAffine,
    amount: u64,
) -> anyhow::Result<ProofBytes> {
    let proving_key = load_pk(pk_path)?;
    let circuit = WithdrawCircuit {
        sk: Some(*sk),
        r_new: Some(*r_new),
        old_balance: Some(old_balance as u32),
        new_balance: Some(new_balance as u32),
        pk: Some(*pk),
        old_c1: Some(*old_c1),
        old_c2: Some(*old_c2),
        new_c1: Some(*new_c1),
        new_c2: Some(*new_c2),
        amount: Some(amount as u32),
    };
    let mut rng = thread_rng();
    let proof = Groth16::<Bn254>::prove(&proving_key, circuit, &mut rng)
        .context("ark-groth16 withdraw prove")?;
    Ok(proof_to_bytes(&proof))
}

/// Prove a ring transfer (N=2).
#[allow(clippy::too_many_arguments)]
pub fn prove_transfer(
    pk_path: &Path,
    sk: &BJJFr,
    r_new: &BJJFr,
    r_decoys: [BJJFr; 2],
    r_t: &BJJFr,
    r_recvs: [BJJFr; 2],
    b: u64,
    v: u64,
    bmv: u64,
    sender_idx: usize,
    recv_idx: usize,
    sender_pks: [EdwardsAffine; 2],
    sender_old_c1: [EdwardsAffine; 2],
    sender_old_c2: [EdwardsAffine; 2],
    sender_new_c1: [EdwardsAffine; 2],
    sender_new_c2: [EdwardsAffine; 2],
    recv_pks: [EdwardsAffine; 2],
    recv_delta_c1: [EdwardsAffine; 2],
    recv_delta_c2: [EdwardsAffine; 2],
) -> anyhow::Result<ProofBytes> {
    let proving_key = load_pk(pk_path)?;
    let circuit = RingTransferCircuit::<2> {
        sk: Some(*sk),
        r_new: Some(*r_new),
        r_decoys: [Some(r_decoys[0]), Some(r_decoys[1])],
        r_t: Some(*r_t),
        r_recvs: [Some(r_recvs[0]), Some(r_recvs[1])],
        balance: Some(b as u32),
        amount: Some(v as u32),
        new_balance: Some(bmv as u32),
        sender_idx: Some(sender_idx),
        recv_idx: Some(recv_idx),
        sender_pks: [Some(sender_pks[0]), Some(sender_pks[1])],
        sender_old_c1: [Some(sender_old_c1[0]), Some(sender_old_c1[1])],
        sender_old_c2: [Some(sender_old_c2[0]), Some(sender_old_c2[1])],
        sender_new_c1: [Some(sender_new_c1[0]), Some(sender_new_c1[1])],
        sender_new_c2: [Some(sender_new_c2[0]), Some(sender_new_c2[1])],
        recv_pks: [Some(recv_pks[0]), Some(recv_pks[1])],
        recv_delta_c1: [Some(recv_delta_c1[0]), Some(recv_delta_c1[1])],
        recv_delta_c2: [Some(recv_delta_c2[0]), Some(recv_delta_c2[1])],
    };
    let mut rng = thread_rng();
    let proof = Groth16::<Bn254>::prove(&proving_key, circuit, &mut rng)
        .context("ark-groth16 transfer prove")?;
    Ok(proof_to_bytes(&proof))
}
