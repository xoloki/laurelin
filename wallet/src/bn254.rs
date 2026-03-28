#![allow(dead_code)]
//! BN254 arithmetic: ElGamal encryption, BSGS decryption, serialisation.
//!
//! All G1 points are serialised as X||Y (32+32 bytes, big-endian field elements),
//! matching the gnark convention used in the Go client and on-chain verifier.
//! The identity/zero point is represented as 64 zero bytes.

use std::collections::HashMap;

use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_std::UniformRand;

// ── Serialisation ─────────────────────────────────────────────────────────────

/// Serialise a Fq element as a 32-byte big-endian array.
pub fn fq_to_bytes(f: &Fq) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    // BigInt<4> for BN254 Fq is always 32 bytes; pad from the left if shorter.
    let len = bytes.len();
    out[32 - len..].copy_from_slice(&bytes);
    out
}

/// Serialise a Fr element as a 32-byte big-endian array.
pub fn fr_to_bytes(s: &Fr) -> [u8; 32] {
    let bytes = s.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let len = bytes.len();
    out[32 - len..].copy_from_slice(&bytes);
    out
}

/// Deserialise a Fr element from 32 big-endian bytes, reducing mod order.
pub fn fr_from_bytes(b: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(b)
}

/// Serialise a G1Affine point as 64-byte X||Y (big-endian).
/// The identity / zero point serialises as 64 zero bytes.
pub fn g1_to_bytes(p: &G1Affine) -> [u8; 64] {
    if p.infinity {
        return [0u8; 64];
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&fq_to_bytes(&p.x));
    out[32..].copy_from_slice(&fq_to_bytes(&p.y));
    out
}

/// Deserialise a G1Affine point from 64-byte X||Y (big-endian).
/// 64 zero bytes → identity.
pub fn g1_from_bytes(b: &[u8; 64]) -> anyhow::Result<G1Affine> {
    if b == &[0u8; 64] {
        return Ok(G1Affine::zero());
    }
    let x = Fq::from_be_bytes_mod_order(&b[..32]);
    let y = Fq::from_be_bytes_mod_order(&b[32..]);
    let p = G1Affine {
        x,
        y,
        infinity: false,
    };
    anyhow::ensure!(
        p.is_on_curve(),
        "g1_from_bytes: point not on BN254 G1 curve"
    );
    Ok(p)
}

/// Encode a G1 point as a lowercase hex string (128 hex chars).
pub fn g1_to_hex(p: &G1Affine) -> String {
    hex::encode(g1_to_bytes(p))
}

/// Encode an Fr scalar as a lowercase hex string (64 hex chars).
pub fn fr_to_hex(s: &Fr) -> String {
    hex::encode(fr_to_bytes(s))
}

// ── BN254 G1 arithmetic ───────────────────────────────────────────────────────

/// Return the BN254 G1 generator.
pub fn generator() -> G1Affine {
    G1Affine::generator()
}

/// Scalar multiplication: s * P.
pub fn scalar_mul(p: &G1Affine, s: &Fr) -> G1Affine {
    (G1Projective::from(*p) * s).into_affine()
}

/// Point addition: P + Q.
pub fn point_add(a: &G1Affine, b: &G1Affine) -> G1Affine {
    (G1Projective::from(*a) + G1Projective::from(*b)).into_affine()
}

/// Point subtraction: P − Q.
pub fn point_sub(a: &G1Affine, b: &G1Affine) -> G1Affine {
    (G1Projective::from(*a) - G1Projective::from(*b)).into_affine()
}

// ── ElGamal ───────────────────────────────────────────────────────────────────

/// An ElGamal ciphertext (C1, C2) under the DEROHE scheme.
///
/// Encryption: r ← Fr, C1 = r*G, C2 = r*PK + v*G
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub c1: G1Affine,
    pub c2: G1Affine,
}

impl Default for Ciphertext {
    /// The "zero" ciphertext: identity || identity (represents encrypted 0 with r=0).
    fn default() -> Self {
        Self {
            c1: G1Affine::zero(),
            c2: G1Affine::zero(),
        }
    }
}

/// Encrypt `amount` under `pk`.  Returns (ciphertext, randomness r).
pub fn elgamal_encrypt(pk: &G1Affine, amount: u64) -> (Ciphertext, Fr) {
    let mut rng = rand::thread_rng();
    let r = Fr::rand(&mut rng);
    let g = generator();
    let v_fr = Fr::from(amount);
    let c1 = scalar_mul(&g, &r);
    let c2 = point_add(&scalar_mul(pk, &r), &scalar_mul(&g, &v_fr));
    (Ciphertext { c1, c2 }, r)
}

/// Re-randomise a ciphertext by adding a fresh random blinding factor.
/// Returns (new ciphertext, random blinding Fr used).
pub fn elgamal_rerandomize(ct: &Ciphertext, pk: &G1Affine) -> (Ciphertext, Fr) {
    let mut rng = rand::thread_rng();
    let r = Fr::rand(&mut rng);
    let g = generator();
    let new_c1 = point_add(&ct.c1, &scalar_mul(&g, &r));
    let new_c2 = point_add(&ct.c2, &scalar_mul(pk, &r));
    (
        Ciphertext {
            c1: new_c1,
            c2: new_c2,
        },
        r,
    )
}

/// Build a "zero-value delta" ciphertext (encrypts 0): C1 = r*G, C2 = r*PK.
pub fn elgamal_zero_delta(pk: &G1Affine) -> (Ciphertext, Fr) {
    let mut rng = rand::thread_rng();
    let r = Fr::rand(&mut rng);
    let g = generator();
    let c1 = scalar_mul(&g, &r);
    let c2 = scalar_mul(pk, &r);
    (Ciphertext { c1, c2 }, r)
}

/// Add two ciphertexts component-wise (homomorphic addition).
pub fn ciphertext_add(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    Ciphertext {
        c1: point_add(&a.c1, &b.c1),
        c2: point_add(&a.c2, &b.c2),
    }
}

/// Decrypt: compute v*G = C2 − sk*C1.
pub fn elgamal_decrypt_point(ct: &Ciphertext, sk: &Fr) -> G1Affine {
    let sk_c1 = scalar_mul(&ct.c1, sk);
    point_sub(&ct.c2, &sk_c1)
}

// ── BSGS ─────────────────────────────────────────────────────────────────────

/// Baby-step giant-step table for ElGamal decryption over [0, 2^32).
///
/// M = 2^16 baby steps and 2^16 giant steps → range [0, 2^32).
/// Build time: O(2^16) point additions; query time: O(2^16).
pub const BSGS_M: u64 = 1 << 16;

pub struct BsgsTable {
    /// Maps 32-byte X coordinate (big-endian) → baby-step index j.
    /// The identity maps to the key [0u8; 32] with index 0.
    baby: HashMap<[u8; 32], u64>,
    /// −M*G: the giant step to subtract each iteration.
    neg_mg: G1Affine,
}

impl BsgsTable {
    /// Build the table. This takes O(2^16) point additions (~65536).
    pub fn build() -> Self {
        let g = generator();
        let m = BSGS_M;

        let mut baby: HashMap<[u8; 32], u64> = HashMap::with_capacity((m + 1) as usize);

        // j = 0: identity point → key is all zeros
        baby.insert([0u8; 32], 0);

        // j = 1..=M: iteratively add G
        let g_proj = G1Projective::from(g);
        let mut current = G1Projective::from(G1Affine::zero()); // identity
        for j in 1..=m {
            current += g_proj;
            let p = current.into_affine();
            let key = fq_to_bytes(&p.x);
            baby.insert(key, j);
        }

        // current is now M*G; negate for giant step
        let mg: G1Affine = current.into_affine();
        let neg_mg = -mg; // negate Y

        BsgsTable { baby, neg_mg }
    }

    /// Solve for v ∈ [0, 2^32) such that `v * G == point`.
    /// Returns None if no solution found (value out of range).
    pub fn solve(&self, point: G1Affine) -> Option<u64> {
        let m = BSGS_M;
        let neg_mg_proj = G1Projective::from(self.neg_mg);
        let mut giant = G1Projective::from(point);

        for k in 0..m {
            let p_affine = giant.into_affine();
            let key = if p_affine.infinity {
                [0u8; 32]
            } else {
                fq_to_bytes(&p_affine.x)
            };

            if let Some(&j) = self.baby.get(&key) {
                return Some(k * m + j);
            }

            // Giant step: subtract M*G
            giant += neg_mg_proj;
        }

        None
    }
}

/// Decrypt an ElGamal ciphertext to a u64 balance using BSGS.
/// Returns None if the balance is out of [0, 2^32).
pub fn bsgs_decrypt(ct: &Ciphertext, sk: &Fr, table: &BsgsTable) -> Option<u64> {
    let v_g = elgamal_decrypt_point(ct, sk);
    table.solve(v_g)
}
