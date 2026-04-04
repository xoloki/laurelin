//! Ring transfer circuit for ring size `N`.
//!
//! Proves a DEROHE-style confidential transfer: 1 of N senders and 1 of N
//! receivers, with every other ring member's ciphertext re-randomized.
//!
//! # Private witnesses
//!
//! - `sk`         — real sender's BJJ secret key
//! - `r_new`      — fresh randomness for the real sender's new ciphertext
//! - `r_decoys`   — per-member re-randomness (index `sender_idx` is unused)
//! - `r_t`        — randomness for the real receiver's transfer delta
//! - `r_recvs`    — per-member re-randomness (index `recv_idx` is unused)
//! - `balance`    — real sender's old plaintext balance (u32)
//! - `amount`     — transfer amount (u32)
//! - `new_balance`— `balance − amount` (u32); proved non-negative via range check
//! - `sender_idx` — index in `[0, N)` of the real sender
//! - `recv_idx`   — index in `[0, N)` of the real receiver
//!
//! # Public inputs
//!
//! 8 arrays of N BJJ points each (16N native Fr elements total):
//!
//! ```text
//! sender_pks[N], sender_old_c1[N], sender_old_c2[N],
//! sender_new_c1[N], sender_new_c2[N],
//! recv_pks[N], recv_delta_c1[N], recv_delta_c2[N]
//! ```
//!
//! # Constraints proved
//!
//! Let `real_pk = sender_pks[sender_idx]`, etc.
//!
//! 1. `sk * G == real_pk`
//! 2. `sk * real_old_c1 + B * G == real_old_c2`   (decrypt old balance)
//! 3. `r_new * G == sender_new_c1[sender_idx]`
//! 4. `r_new * real_pk + BmV * G == sender_new_c2[sender_idx]`
//! 5. For each decoy i: `sender_new_c1[i] == sender_old_c1[i] + r_decoys[i] * G`
//! 6. For each decoy i: `sender_new_c2[i] == sender_old_c2[i] + r_decoys[i] * sender_pks[i]`
//! 7. `r_t * G == recv_delta_c1[recv_idx]`
//! 8. `r_t * real_recv_pk + V * G == recv_delta_c2[recv_idx]`
//! 9. For each decoy j: `recv_delta_c1[j] == r_recvs[j] * G`
//! 10. For each decoy j: `recv_delta_c2[j] == r_recvs[j] * recv_pks[j]`
//! 11. `B == V + BmV`   (arithmetic soundness)
//! 12. `B, V, BmV ∈ [0, 2³²)`   (range checks via bit decomposition)

use ark_bn254::Fr;
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsAffine, Fr as BJJFr};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, groups::CurveVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::gadgets::{
    alloc_bjj_scalar_bits, alloc_u32_bits, bits_to_fpvar, generator_var, one_hot_indicators,
    scalar_mul,
};

// ── Circuit struct ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RingTransferCircuit<const N: usize> {
    // ── private witnesses ───────────────────────────────────────────────────
    pub sk: Option<BJJFr>,
    pub r_new: Option<BJJFr>,
    /// Re-randomness for each ring position. Slot `sender_idx` is not used by
    /// any constraint but must still be provided (can be zero or random).
    pub r_decoys: [Option<BJJFr>; N],
    pub r_t: Option<BJJFr>,
    /// Re-randomness for each receiver ring position. Slot `recv_idx` unused.
    pub r_recvs: [Option<BJJFr>; N],
    pub balance: Option<u32>,
    pub amount: Option<u32>,
    pub new_balance: Option<u32>,
    pub sender_idx: Option<usize>,
    pub recv_idx: Option<usize>,

    // ── public inputs ───────────────────────────────────────────────────────
    pub sender_pks: [Option<EdwardsAffine>; N],
    pub sender_old_c1: [Option<EdwardsAffine>; N],
    pub sender_old_c2: [Option<EdwardsAffine>; N],
    pub sender_new_c1: [Option<EdwardsAffine>; N],
    pub sender_new_c2: [Option<EdwardsAffine>; N],
    pub recv_pks: [Option<EdwardsAffine>; N],
    pub recv_delta_c1: [Option<EdwardsAffine>; N],
    pub recv_delta_c2: [Option<EdwardsAffine>; N],
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Allocate an array of N points as public inputs, in order.
fn alloc_points_public<const N: usize>(
    cs: ConstraintSystemRef<Fr>,
    pts: &[Option<EdwardsAffine>; N],
) -> Result<[EdwardsVar; N], SynthesisError> {
    let v: Vec<EdwardsVar> = pts
        .iter()
        .map(|p| EdwardsVar::new_input(cs.clone(), || p.ok_or(SynthesisError::AssignmentMissing)))
        .collect::<Result<_, _>>()?;
    Ok(v.try_into().unwrap_or_else(|_| unreachable!()))
}

/// Select from an array of EdwardsVar using one-hot indicators.
fn select_by_hot<const N: usize>(
    hot: &[Boolean<Fr>; N],
    points: &[EdwardsVar; N],
) -> Result<EdwardsVar, SynthesisError> {
    let identity = EdwardsVar::zero();
    let mut result = identity.clone();
    for i in 0..N {
        let sel = EdwardsVar::conditionally_select(&hot[i], &points[i], &identity)?;
        result = result + sel;
    }
    Ok(result)
}

// ── ConstraintSynthesizer ─────────────────────────────────────────────────────

impl<const N: usize> ConstraintSynthesizer<Fr> for RingTransferCircuit<N> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── 1. Allocate public inputs (order defines the public input vector) ──
        let pk_vars = alloc_points_public(cs.clone(), &self.sender_pks)?;
        let old_c1_vars = alloc_points_public(cs.clone(), &self.sender_old_c1)?;
        let old_c2_vars = alloc_points_public(cs.clone(), &self.sender_old_c2)?;
        let new_c1_vars = alloc_points_public(cs.clone(), &self.sender_new_c1)?;
        let new_c2_vars = alloc_points_public(cs.clone(), &self.sender_new_c2)?;
        let recv_pk_vars = alloc_points_public(cs.clone(), &self.recv_pks)?;
        let recv_dc1_vars = alloc_points_public(cs.clone(), &self.recv_delta_c1)?;
        let recv_dc2_vars = alloc_points_public(cs.clone(), &self.recv_delta_c2)?;

        // ── 2. Allocate private witnesses ──────────────────────────────────────
        let sk_bits = alloc_bjj_scalar_bits(cs.clone(), self.sk)?;
        let r_new_bits = alloc_bjj_scalar_bits(cs.clone(), self.r_new)?;
        let r_t_bits = alloc_bjj_scalar_bits(cs.clone(), self.r_t)?;

        let mut r_decoy_bits: Vec<Vec<Boolean<Fr>>> = Vec::with_capacity(N);
        for i in 0..N {
            r_decoy_bits.push(alloc_bjj_scalar_bits(cs.clone(), self.r_decoys[i])?);
        }

        let mut r_recv_bits: Vec<Vec<Boolean<Fr>>> = Vec::with_capacity(N);
        for i in 0..N {
            r_recv_bits.push(alloc_bjj_scalar_bits(cs.clone(), self.r_recvs[i])?);
        }

        let b_bits = alloc_u32_bits(cs.clone(), self.balance)?;
        let v_bits = alloc_u32_bits(cs.clone(), self.amount)?;
        let bmv_bits = alloc_u32_bits(cs.clone(), self.new_balance)?;

        let b_fp = bits_to_fpvar(&b_bits);
        let v_fp = bits_to_fpvar(&v_bits);
        let bmv_fp = bits_to_fpvar(&bmv_bits);

        // ── 3. Constraint: B == V + BmV ────────────────────────────────────────
        b_fp.enforce_equal(&(v_fp + &bmv_fp))?;

        // ── 4. Sender index one-hot indicators ─────────────────────────────────
        let sender_idx_fp = FpVar::new_witness(cs.clone(), || {
            self.sender_idx
                .map(|i| Fr::from(i as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let sender_hot = one_hot_indicators::<N>(&sender_idx_fp)?;

        // ── 5. Select real sender's public key and old ciphertext ──────────────
        let real_pk = select_by_hot(&sender_hot, &pk_vars)?;
        let real_old_c1 = select_by_hot(&sender_hot, &old_c1_vars)?;
        let real_old_c2 = select_by_hot(&sender_hot, &old_c2_vars)?;
        let real_new_c1 = select_by_hot(&sender_hot, &new_c1_vars)?;
        let real_new_c2 = select_by_hot(&sender_hot, &new_c2_vars)?;

        let g = generator_var();

        // ── 6. Constraint: sk * G == real_pk ───────────────────────────────────
        let computed_pk = scalar_mul(&g, &sk_bits)?;
        computed_pk.enforce_equal(&real_pk)?;

        // ── 7. Constraint: sk * real_old_c1 + B * G == real_old_c2 ────────────
        let sk_c1 = scalar_mul(&real_old_c1, &sk_bits)?;
        let b_g = scalar_mul(&g, &b_bits)?;
        let computed_old_c2 = sk_c1 + b_g;
        computed_old_c2.enforce_equal(&real_old_c2)?;

        // ── 8. Constraint: r_new * G == sender_new_c1[sender_idx] ─────────────
        let r_new_g = scalar_mul(&g, &r_new_bits)?;
        r_new_g.enforce_equal(&real_new_c1)?;

        // ── 9. Constraint: r_new * real_pk + BmV * G == sender_new_c2[sender_idx]
        let rn_pk = scalar_mul(&real_pk, &r_new_bits)?;
        let bmv_g = scalar_mul(&g, &bmv_bits)?;
        let computed_new_c2 = rn_pk + bmv_g;
        computed_new_c2.enforce_equal(&real_new_c2)?;

        // ── 10. Decoy sender constraints ───────────────────────────────────────
        // For each position i: if NOT real sender, enforce re-randomization.
        // We compute the decoy value for every position and select the right
        // one to compare with the public new ciphertext.
        for i in 0..N {
            // decoy_new_c1[i] = old_c1[i] + r_decoys[i] * G
            let rd_g = scalar_mul(&g, &r_decoy_bits[i])?;
            let decoy_new_c1_i = old_c1_vars[i].clone() + rd_g;

            // decoy_new_c2[i] = old_c2[i] + r_decoys[i] * pk[i]
            let rd_pk = scalar_mul(&pk_vars[i], &r_decoy_bits[i])?;
            let decoy_new_c2_i = old_c2_vars[i].clone() + rd_pk;

            // expected_new_c1[i] = if sender_hot[i] then r_new_g else decoy_new_c1[i]
            let expected_c1 =
                EdwardsVar::conditionally_select(&sender_hot[i], &r_new_g, &decoy_new_c1_i)?;
            expected_c1.enforce_equal(&new_c1_vars[i])?;

            // expected_new_c2[i] = if sender_hot[i] then computed_new_c2 else decoy_new_c2[i]
            let expected_c2 = EdwardsVar::conditionally_select(
                &sender_hot[i],
                &computed_new_c2,
                &decoy_new_c2_i,
            )?;
            expected_c2.enforce_equal(&new_c2_vars[i])?;
        }

        // ── 11. Receiver index one-hot indicators ──────────────────────────────
        let recv_idx_fp = FpVar::new_witness(cs.clone(), || {
            self.recv_idx
                .map(|i| Fr::from(i as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let recv_hot = one_hot_indicators::<N>(&recv_idx_fp)?;

        let real_recv_pk = select_by_hot(&recv_hot, &recv_pk_vars)?;
        let real_recv_dc1 = select_by_hot(&recv_hot, &recv_dc1_vars)?;
        let real_recv_dc2 = select_by_hot(&recv_hot, &recv_dc2_vars)?;

        // ── 12. Constraint: r_t * G == recv_delta_c1[recv_idx] ────────────────
        let r_t_g = scalar_mul(&g, &r_t_bits)?;
        r_t_g.enforce_equal(&real_recv_dc1)?;

        // ── 13. Constraint: r_t * real_recv_pk + V * G == recv_delta_c2[recv_idx]
        let rt_pk = scalar_mul(&real_recv_pk, &r_t_bits)?;
        let v_g = scalar_mul(&g, &v_bits)?;
        let computed_dc2 = rt_pk + v_g;
        computed_dc2.enforce_equal(&real_recv_dc2)?;

        // ── 14. Decoy receiver constraints ─────────────────────────────────────
        for i in 0..N {
            // recv_delta_c1[i] = r_recvs[i] * G
            let rr_g = scalar_mul(&g, &r_recv_bits[i])?;

            // recv_delta_c2[i] = r_recvs[i] * recv_pks[i]
            let rr_pk = scalar_mul(&recv_pk_vars[i], &r_recv_bits[i])?;

            let expected_dc1 = EdwardsVar::conditionally_select(&recv_hot[i], &r_t_g, &rr_g)?;
            expected_dc1.enforce_equal(&recv_dc1_vars[i])?;

            let expected_dc2 =
                EdwardsVar::conditionally_select(&recv_hot[i], &computed_dc2, &rr_pk)?;
            expected_dc2.enforce_equal(&recv_dc2_vars[i])?;
        }

        Ok(())
    }
}
