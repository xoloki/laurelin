//! Deposit circuit.
//!
//! Proves that a delta ciphertext correctly encrypts a publicly known deposit
//! amount under the account's Baby JubJub public key.
//!
//! # Private witnesses
//!
//! - `r` — randomness used to construct the delta ciphertext
//!
//! # Public inputs (6 native Fr elements)
//!
//! - `pk`       — account BJJ public key   (2 Fr)
//! - `delta_c1` — delta ciphertext C1      (2 Fr)
//! - `delta_c2` — delta ciphertext C2      (2 Fr)
//! - `amount`   — lamports deposited       (1 Fr, native u32)
//!
//! Total: 7 Fr public inputs, IC length = 8.
//!
//! # Constraints
//!
//! 1. `delta_c1 = R * G`
//! 2. `delta_c2 = R * Pk + Amount * G`
//! 3. `Amount ∈ [0, 2³²)`

use ark_bn254::Fr;
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsAffine, Fr as BJJFr};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::gadgets::{alloc_bjj_scalar_bits, alloc_u32_bits, generator_var, scalar_mul};

#[derive(Clone)]
pub struct DepositCircuit {
    // private
    pub r: Option<BJJFr>,

    // public
    pub pk: Option<EdwardsAffine>,
    pub delta_c1: Option<EdwardsAffine>,
    pub delta_c2: Option<EdwardsAffine>,
    pub amount: Option<u32>,
}

impl ConstraintSynthesizer<Fr> for DepositCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Public inputs ──────────────────────────────────────────────────────
        let pk_var = EdwardsVar::new_input(cs.clone(), || {
            self.pk.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let c1_var = EdwardsVar::new_input(cs.clone(), || {
            self.delta_c1.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let c2_var = EdwardsVar::new_input(cs.clone(), || {
            self.delta_c2.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // Amount as a native field element
        let amount_fp = FpVar::new_input(cs.clone(), || {
            self.amount
                .map(|a| Fr::from(a as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ── Private witnesses ──────────────────────────────────────────────────
        let r_bits = alloc_bjj_scalar_bits(cs.clone(), self.r)?;

        // Range check amount ∈ [0, 2^32) by allocating as 32 witness bits and
        // verifying they reconstruct the public amount field element.
        let amount_bits = alloc_u32_bits(cs.clone(), self.amount)?;
        let amount_reconstructed = crate::gadgets::bits_to_fpvar(&amount_bits);
        amount_fp.enforce_equal(&amount_reconstructed)?;

        // ── Constraints ────────────────────────────────────────────────────────
        let g = generator_var();

        // 1. delta_c1 = R * G
        let computed_c1 = scalar_mul(&g, &r_bits)?;
        computed_c1.enforce_equal(&c1_var)?;

        // 2. delta_c2 = R * Pk + Amount * G
        let r_pk = scalar_mul(&pk_var, &r_bits)?;
        let amt_g = scalar_mul(&g, &amount_bits)?;
        let computed_c2 = r_pk + amt_g;
        computed_c2.enforce_equal(&c2_var)?;

        Ok(())
    }
}
