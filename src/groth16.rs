use crate::bn254::{g1_add, g1_mul, g1_negate, pairing_check};
use crate::state::{G1Point, G2Point, Groth16Proof, Scalar};
use solana_program::log::sol_log_compute_units;
use solana_program::msg;

pub struct VerificationKey {
    pub alpha: G1Point,
    pub beta: G2Point,
    pub gamma: G2Point,
    pub delta: G2Point,
    /// IC[0] + sum(public_inputs[i] * IC[i+1])
    /// Length must equal n_public_inputs + 1
    pub ic: &'static [G1Point],
}

/// Verify a Groth16 proof (gnark v0.10 style with one BSB22 commitment).
///
/// Checks: e(A,B) · e(-α,β) · e(-vk_x,γ) · e(-C,δ) = 1
///
/// vk_x = IC[0]
///       + Σ(public_inputs[i] * IC[i+1])   — 56 limbs + commit_hash at [56]
///       + commitment                        — proof.Commitments[0] added directly
///
/// public_inputs must have exactly vk.ic.len() - 1 elements.
/// commitment is proof.Commitments[0] in uncompressed G1 format.
pub fn verify(
    vk: &VerificationKey,
    proof: &Groth16Proof,
    public_inputs: &[Scalar],
    commitment: &G1Point,
) -> Result<bool, ()> {
    if public_inputs.len() + 1 != vk.ic.len() {
        return Ok(false);
    }

    // vk_x = IC[0] + Σ(pub_inputs[i] * IC[i+1])
    msg!("groth16: starting g1_mul loop");
    sol_log_compute_units();
    let mut vk_x = vk.ic[0];
    for (i, input) in public_inputs.iter().enumerate() {
        let term = g1_mul(&vk.ic[i + 1], input)?;
        vk_x = g1_add(&vk_x, &term)?;
    }
    msg!("groth16: g1_mul loop done");
    sol_log_compute_units();

    // Add commitment point directly (gnark BSB22: kSum += proof.Commitments[0])
    vk_x = g1_add(&vk_x, commitment)?;
    msg!("groth16: commitment added, starting pairing check");
    sol_log_compute_units();

    let neg_alpha = g1_negate(&vk.alpha);
    let neg_vk_x = g1_negate(&vk_x);
    let neg_c = g1_negate(&proof.c);

    let result = pairing_check(&[
        (&proof.a,   &proof.b),
        (&neg_alpha, &vk.beta),
        (&neg_vk_x,  &vk.gamma),
        (&neg_c,     &vk.delta),
    ]);
    msg!("groth16: pairing check done");
    sol_log_compute_units();
    result
}
