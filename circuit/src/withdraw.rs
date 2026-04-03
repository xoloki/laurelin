//! Withdraw circuit.
//!
//! Proves knowledge of a secret key and sufficient balance to withdraw a
//! publicly known amount of SOL lamports.
//!
//! # Private witnesses
//!
//! - `sk`          — account BJJ secret key
//! - `r_new`       — randomness for the post-withdraw ciphertext
//! - `old_balance` — plaintext balance before withdrawal (u32)
//! - `new_balance` — `old_balance − amount` (u32); range-checked ≥ 0
//!
//! # Public inputs (11 native Fr elements)
//!
//! - `pk`     — account BJJ public key       (2 Fr)
//! - `old_c1` — current ciphertext C1        (2 Fr)
//! - `old_c2` — current ciphertext C2        (2 Fr)
//! - `new_c1` — replacement ciphertext C1    (2 Fr)
//! - `new_c2` — replacement ciphertext C2    (2 Fr)
//! - `amount` — lamports withdrawn           (1 Fr, native u32)
//!
//! Total: 11 Fr public inputs, IC length = 12.
//!
//! # Constraints
//!
//! 1. `pk     = Sk * G`
//! 2. `old_c2 = Sk * old_c1 + OldBalance * G`
//! 3. `new_c1 = RNew * G`
//! 4. `new_c2 = RNew * Pk + NewBalance * G`
//! 5. `old_balance = amount + new_balance`
//! 6. `old_balance, new_balance, amount ∈ [0, 2³²)`

use ark_bn254::Fr;
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsAffine, Fr as BJJFr};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::gadgets::{
    alloc_bjj_scalar_bits, alloc_u32_bits, bits_to_fpvar, generator_var, scalar_mul,
};

#[derive(Clone)]
pub struct WithdrawCircuit {
    // private
    pub sk: Option<BJJFr>,
    pub r_new: Option<BJJFr>,
    pub old_balance: Option<u32>,
    pub new_balance: Option<u32>,

    // public
    pub pk: Option<EdwardsAffine>,
    pub old_c1: Option<EdwardsAffine>,
    pub old_c2: Option<EdwardsAffine>,
    pub new_c1: Option<EdwardsAffine>,
    pub new_c2: Option<EdwardsAffine>,
    pub amount: Option<u32>,
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Public inputs ──────────────────────────────────────────────────────
        let pk_var = EdwardsVar::new_input(cs.clone(), || {
            self.pk.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let old_c1_var = EdwardsVar::new_input(cs.clone(), || {
            self.old_c1.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let old_c2_var = EdwardsVar::new_input(cs.clone(), || {
            self.old_c2.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let new_c1_var = EdwardsVar::new_input(cs.clone(), || {
            self.new_c1.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let new_c2_var = EdwardsVar::new_input(cs.clone(), || {
            self.new_c2.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let amount_fp = FpVar::new_input(cs.clone(), || {
            self.amount
                .map(|a| Fr::from(a as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ── Private witnesses ──────────────────────────────────────────────────
        let sk_bits = alloc_bjj_scalar_bits(cs.clone(), self.sk)?;
        let r_new_bits = alloc_bjj_scalar_bits(cs.clone(), self.r_new)?;

        let old_bal_bits = alloc_u32_bits(cs.clone(), self.old_balance)?;
        let new_bal_bits = alloc_u32_bits(cs.clone(), self.new_balance)?;
        let amount_bits = alloc_u32_bits(cs.clone(), self.amount)?;

        let old_bal_fp = bits_to_fpvar(&old_bal_bits);
        let new_bal_fp = bits_to_fpvar(&new_bal_bits);
        let amount_fp_reconstructed = bits_to_fpvar(&amount_bits);

        // Verify public amount matches private bit decomposition
        amount_fp.enforce_equal(&amount_fp_reconstructed)?;

        // ── Constraint 5: old_balance = amount + new_balance ──────────────────
        old_bal_fp.enforce_equal(&(amount_fp_reconstructed + &new_bal_fp))?;

        // ── Constraint 1: pk = Sk * G ──────────────────────────────────────────
        let g = generator_var();
        let computed_pk = scalar_mul(&g, &sk_bits)?;
        computed_pk.enforce_equal(&pk_var)?;

        // ── Constraint 2: old_c2 = Sk * old_c1 + OldBalance * G ───────────────
        let sk_c1 = scalar_mul(&old_c1_var, &sk_bits)?;
        let old_bal_g = scalar_mul(&g, &old_bal_bits)?;
        let computed_old_c2 = sk_c1 + old_bal_g;
        computed_old_c2.enforce_equal(&old_c2_var)?;

        // ── Constraint 3: new_c1 = RNew * G ───────────────────────────────────
        let computed_new_c1 = scalar_mul(&g, &r_new_bits)?;
        computed_new_c1.enforce_equal(&new_c1_var)?;

        // ── Constraint 4: new_c2 = RNew * Pk + NewBalance * G ─────────────────
        let rn_pk = scalar_mul(&pk_var, &r_new_bits)?;
        let new_bal_g = scalar_mul(&g, &new_bal_bits)?;
        let computed_new_c2 = rn_pk + new_bal_g;
        computed_new_c2.enforce_equal(&new_c2_var)?;

        Ok(())
    }
}
