#![allow(dead_code)]
//! Baby JubJub crypto: ElGamal encryption, BSGS decryption, serialisation.
//!
//! BJJ is a twisted Edwards curve over BN254's Fr field.  Point coordinates
//! are BN254 Fr elements (ark_ed_on_bn254::Fq == ark_bn254::Fr), so the
//! serialisation is the same 32-byte big-endian Fr representation used
//! everywhere else in the system.
//!
//! Points are serialised as X||Y (64 bytes, big-endian coordinate fields).
//! The identity maps to all-zero X and Y = 1 (64 bytes: 63 zeros + 0x01).
//! For the BSGS table the X coordinate (32 bytes) is used as the key.

use std::collections::HashMap;

use ark_bn254::Fr as BN254Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as BJJFr};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_std::UniformRand;

/// Maximum confidential balance / amount: 2^32 − 1 lamports (~4.3 SOL).
pub const MAX_CONFIDENTIAL_LAMPORTS: u64 = u32::MAX as u64;

// ── Serialisation ─────────────────────────────────────────────────────────────

/// Serialise a BN254 Fr element (= BJJ coordinate) to 32-byte big-endian.
pub fn coord_to_bytes(f: &BN254Fr) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let len = bytes.len();
    out[32 - len..].copy_from_slice(&bytes);
    out
}

/// Serialise a BJJ scalar (group order field element) to 32-byte big-endian.
pub fn bjj_fr_to_bytes(s: &BJJFr) -> [u8; 32] {
    let bytes = s.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let len = bytes.len();
    out[32 - len..].copy_from_slice(&bytes);
    out
}

/// Deserialise a BJJ scalar from 32 big-endian bytes, reducing mod order.
pub fn bjj_fr_from_bytes(b: &[u8; 32]) -> BJJFr {
    BJJFr::from_be_bytes_mod_order(b)
}

/// Serialise an EdwardsAffine point to 64-byte X||Y (big-endian).
/// The identity maps to 64 zero bytes (X=0, Y=0 sentinel — different from the
/// curve's (0,1) identity, but we handle this explicitly in from_bytes).
///
/// Actually we use X=0, Y=1 representation for consistency with the on-chain
/// program, so the 64-byte encoding is: 32 zero bytes (X=0) || 31 zero bytes
/// + 0x01 (Y=1).
pub fn point_to_bytes(p: &EdwardsAffine) -> [u8; 64] {
    let mut out = [0u8; 64];
    // EdwardsAffine::is_zero() checks if the point equals the identity (0,1)
    if p.is_zero() {
        // Identity: X=0 (32 zero bytes), Y=1
        out[63] = 1;
        return out;
    }
    out[0..32].copy_from_slice(&coord_to_bytes(&p.x));
    out[32..64].copy_from_slice(&coord_to_bytes(&p.y));
    out
}

/// Deserialise a 64-byte X||Y array into an EdwardsAffine point.
pub fn point_from_bytes(b: &[u8; 64]) -> anyhow::Result<EdwardsAffine> {
    let x = BN254Fr::from_be_bytes_mod_order(&b[0..32]);
    let y = BN254Fr::from_be_bytes_mod_order(&b[32..64]);
    // Identity: (0, 1)
    if x.is_zero() && y == BN254Fr::from(1u64) {
        return Ok(EdwardsAffine::zero());
    }
    let p = EdwardsAffine::new_unchecked(x, y);
    anyhow::ensure!(p.is_on_curve(), "point_from_bytes: point not on BJJ curve");
    Ok(p)
}

/// Encode a point as a lowercase hex string (128 hex chars).
pub fn point_to_hex(p: &EdwardsAffine) -> String {
    hex::encode(point_to_bytes(p))
}

/// Encode a BJJ scalar as a lowercase hex string (64 hex chars).
pub fn bjj_fr_to_hex(s: &BJJFr) -> String {
    hex::encode(bjj_fr_to_bytes(s))
}

// ── BJJ arithmetic ────────────────────────────────────────────────────────────

/// Return the BJJ generator.
pub fn generator() -> EdwardsAffine {
    EdwardsAffine::generator()
}

/// Scalar multiplication: s * P.
pub fn scalar_mul(p: &EdwardsAffine, s: &BJJFr) -> EdwardsAffine {
    (EdwardsProjective::from(*p) * s).into_affine()
}

/// Point addition: P + Q.
pub fn point_add(a: &EdwardsAffine, b: &EdwardsAffine) -> EdwardsAffine {
    (EdwardsProjective::from(*a) + EdwardsProjective::from(*b)).into_affine()
}

/// Point subtraction: P − Q.
pub fn point_sub(a: &EdwardsAffine, b: &EdwardsAffine) -> EdwardsAffine {
    (EdwardsProjective::from(*a) - EdwardsProjective::from(*b)).into_affine()
}

// ── ElGamal ───────────────────────────────────────────────────────────────────

/// An ElGamal ciphertext (C1, C2) under the DEROHE scheme.
///
/// Encryption: r ← BJJFr, C1 = r*G, C2 = r*PK + v*G
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub c1: EdwardsAffine,
    pub c2: EdwardsAffine,
}

impl Default for Ciphertext {
    /// The "zero" ciphertext: identity || identity (represents encrypted 0 with r=0).
    fn default() -> Self {
        Self {
            c1: EdwardsAffine::zero(),
            c2: EdwardsAffine::zero(),
        }
    }
}

/// Encrypt `amount` under `pk`.  Returns (ciphertext, randomness r).
pub fn elgamal_encrypt(pk: &EdwardsAffine, amount: u64) -> (Ciphertext, BJJFr) {
    let mut rng = rand::thread_rng();
    let r = BJJFr::rand(&mut rng);
    let g = generator();
    let v_fr = BJJFr::from(amount);
    let c1 = scalar_mul(&g, &r);
    let c2 = point_add(&scalar_mul(pk, &r), &scalar_mul(&g, &v_fr));
    (Ciphertext { c1, c2 }, r)
}

/// Re-randomise a ciphertext by adding a fresh random blinding factor.
pub fn elgamal_rerandomize(ct: &Ciphertext, pk: &EdwardsAffine) -> (Ciphertext, BJJFr) {
    let mut rng = rand::thread_rng();
    let r = BJJFr::rand(&mut rng);
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
pub fn elgamal_zero_delta(pk: &EdwardsAffine) -> (Ciphertext, BJJFr) {
    let mut rng = rand::thread_rng();
    let r = BJJFr::rand(&mut rng);
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
pub fn elgamal_decrypt_point(ct: &Ciphertext, sk: &BJJFr) -> EdwardsAffine {
    let sk_c1 = scalar_mul(&ct.c1, sk);
    point_sub(&ct.c2, &sk_c1)
}

// ── BSGS ─────────────────────────────────────────────────────────────────────

/// Baby-step giant-step table for ElGamal decryption over [0, 2^32).
///
/// M = 2^16; build time O(2^16), query time O(2^16).
pub const BSGS_M: u64 = 1 << 16;

pub struct BsgsTable {
    /// Maps 32-byte big-endian X coordinate → baby-step index j.
    baby: HashMap<[u8; 32], u64>,
    /// −M*G: the giant step to subtract each iteration.
    neg_mg: EdwardsAffine,
}

impl BsgsTable {
    /// Build the table.  O(2^16) point additions.
    pub fn build() -> Self {
        let g = generator();
        let m = BSGS_M;

        let mut baby: HashMap<[u8; 32], u64> = HashMap::with_capacity((m + 1) as usize);

        // j = 0: identity point → X = 0
        baby.insert([0u8; 32], 0);

        let g_proj = EdwardsProjective::from(g);
        let mut current = EdwardsProjective::from(EdwardsAffine::zero());
        for j in 1..=m {
            current += g_proj;
            let p = current.into_affine();
            let key = coord_to_bytes(&p.x);
            baby.insert(key, j);
        }

        // current = M*G; negate for giant step
        let mg: EdwardsAffine = current.into_affine();
        // EdwardsAffine negation: (x, y) → (-x, y)
        let neg_mg = -mg;

        BsgsTable { baby, neg_mg }
    }

    /// Solve for v ∈ [0, 2^32) such that `v * G == point`.
    pub fn solve(&self, point: EdwardsAffine) -> Option<u64> {
        let m = BSGS_M;
        let neg_mg_proj = EdwardsProjective::from(self.neg_mg);
        let mut giant = EdwardsProjective::from(point);

        for k in 0..m {
            let p_affine = giant.into_affine();
            let key = if p_affine.is_zero() {
                [0u8; 32]
            } else {
                coord_to_bytes(&p_affine.x)
            };

            if let Some(&j) = self.baby.get(&key) {
                return Some(k * m + j);
            }

            giant += neg_mg_proj;
        }

        None
    }
}

/// Decrypt an ElGamal ciphertext to a u64 balance using BSGS.
pub fn bsgs_decrypt(ct: &Ciphertext, sk: &BJJFr, table: &BsgsTable) -> Option<u64> {
    let v_g = elgamal_decrypt_point(ct, sk);
    table.solve(v_g)
}
