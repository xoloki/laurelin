//! Shared gadget helpers used across circuits.

use ark_bn254::Fr;
use ark_ed_on_bn254::{constraints::EdwardsVar, Fr as BJJFr};
use ark_ff::{BigInteger, One, PrimeField};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, groups::CurveVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

// ── Scalar allocation ─────────────────────────────────────────────────────────

/// Allocate a BJJ scalar (251-bit) as a vector of LE witness bits.
pub fn alloc_bjj_scalar_bits(
    cs: ConstraintSystemRef<Fr>,
    s: Option<BJJFr>,
) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    let bit_count = BJJFr::MODULUS_BIT_SIZE as usize;
    (0..bit_count)
        .map(|i| {
            Boolean::new_witness(cs.clone(), || {
                Ok(s.map(|v| v.into_bigint().get_bit(i)).unwrap_or(false))
            })
        })
        .collect()
}

/// Allocate a u32 balance/amount value as 32 LE witness bits, which
/// simultaneously serves as the range proof (witness is constrained to 32 bits).
pub fn alloc_u32_bits(
    cs: ConstraintSystemRef<Fr>,
    val: Option<u32>,
) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    (0..32)
        .map(|i| {
            Boolean::new_witness(cs.clone(), || {
                Ok(val.map(|v| (v >> i) & 1 == 1).unwrap_or(false))
            })
        })
        .collect()
}

/// Reconstruct a field element from little-endian bits (no extra constraints
/// beyond what was already in the Boolean allocation).
pub fn bits_to_fpvar(bits: &[Boolean<Fr>]) -> FpVar<Fr> {
    let two = Fr::from(2u64);
    let mut coeff = Fr::one(); // ark_ff::One brings this into scope via import
    let mut result = FpVar::zero();
    for bit in bits {
        let bit_fp = FpVar::from(bit.clone());
        result = result + bit_fp * FpVar::constant(coeff);
        coeff *= two;
    }
    result
}

// ── Point helpers ─────────────────────────────────────────────────────────────

/// Return the BJJ generator G as a constant circuit point.
pub fn generator_var() -> EdwardsVar {
    use ark_ec::twisted_edwards::TECurveConfig;
    use ark_ed_on_bn254::{EdwardsAffine, EdwardsConfig};
    let g: EdwardsAffine = EdwardsConfig::GENERATOR;
    EdwardsVar::constant(g.into())
}

/// Scalar-multiply a point variable by LE bits: returns `point * scalar`.
pub fn scalar_mul(point: &EdwardsVar, bits: &[Boolean<Fr>]) -> Result<EdwardsVar, SynthesisError> {
    point.scalar_mul_le(bits.iter())
}

// ── One-hot select ────────────────────────────────────────────────────────────

/// Select among `N` points using a private index.
///
/// Allocates one Boolean indicator per position, enforces that exactly one is
/// set (sum == 1), and returns the selected point.
///
/// The `idx_var` is a `FpVar<Fr>` that holds a value in `0..N`.
pub fn one_hot_select<const N: usize>(
    idx_var: &FpVar<Fr>,
    points: &[EdwardsVar; N],
) -> Result<EdwardsVar, SynthesisError> {
    // Compute hot[i] = (idx_var == i) for each i
    let mut hot = Vec::with_capacity(N);
    for i in 0..N {
        let i_const = FpVar::constant(Fr::from(i as u64));
        hot.push(idx_var.is_eq(&i_const)?);
    }

    // Enforce exactly one is set: sum(hot) == 1
    let mut sum = FpVar::<Fr>::zero();
    for h in &hot {
        sum += FpVar::from(h.clone());
    }
    sum.enforce_equal(&FpVar::one())?;

    // Accumulate: result = Σ hot[i] * points[i]  (others get identity)
    let identity = EdwardsVar::zero();
    let mut result = identity.clone();
    for i in 0..N {
        let selected = EdwardsVar::conditionally_select(&hot[i], &points[i], &identity)?;
        result = result + selected;
    }
    Ok(result)
}

/// For each position `i`, select between two candidates using `hot[i]`.
///
/// Returns `[if_true[i] if hot[i] else if_false[i]; N]`.
pub fn per_position_select<const N: usize>(
    hot: &[Boolean<Fr>; N],
    if_true: &[EdwardsVar; N],
    if_false: &[EdwardsVar; N],
) -> Result<[EdwardsVar; N], SynthesisError> {
    // Can't use array::try_from_fn on stable, so build via Vec
    let v: Vec<EdwardsVar> = (0..N)
        .map(|i| EdwardsVar::conditionally_select(&hot[i], &if_true[i], &if_false[i]))
        .collect::<Result<_, _>>()?;
    // SAFETY: we know v.len() == N
    Ok(v.try_into().unwrap_or_else(|_| unreachable!()))
}

/// Compute the one-hot indicators for an index variable without selecting a
/// point — used when we need both the selected point AND the indicators for
/// per-position work.
pub fn one_hot_indicators<const N: usize>(
    idx_var: &FpVar<Fr>,
) -> Result<[Boolean<Fr>; N], SynthesisError> {
    let v: Vec<Boolean<Fr>> = (0..N)
        .map(|i| {
            let i_const = FpVar::constant(Fr::from(i as u64));
            idx_var.is_eq(&i_const)
        })
        .collect::<Result<_, _>>()?;

    // Enforce sum == 1
    let mut sum = FpVar::<Fr>::zero();
    for h in &v {
        sum += FpVar::from(h.clone());
    }
    sum.enforce_equal(&FpVar::one())?;

    Ok(v.try_into().unwrap_or_else(|_| unreachable!()))
}
