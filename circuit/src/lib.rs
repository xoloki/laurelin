//! Laurelin ZK circuit crate — Baby JubJub / ark-groth16
//!
//! All three circuits (deposit, transfer, withdraw) use Baby JubJub ElGamal:
//! the curve is the twisted Edwards curve defined over BN254's Fr, so its
//! affine coordinates are native field elements — no emulated arithmetic.
//!
//! # Circuit public-input layout (ring transfer, ring size N)
//!
//! Public inputs are allocated in `generate_constraints` in this order,
//! 2 Fr elements per BJJ point (x then y):
//!
//!   sender_pks[0..N]       (2N inputs)
//!   sender_old_c1[0..N]    (2N inputs)
//!   sender_old_c2[0..N]    (2N inputs)
//!   sender_new_c1[0..N]    (2N inputs)
//!   sender_new_c2[0..N]    (2N inputs)
//!   recv_pks[0..N]         (2N inputs)
//!   recv_delta_c1[0..N]    (2N inputs)
//!   recv_delta_c2[0..N]    (2N inputs)
//!
//! Total: 16N native Fr public inputs.  IC length = 16N + 1.

pub mod deposit;
pub mod gadgets;
pub mod transfer;
pub mod withdraw;

pub use ark_bn254::Fr;
pub use ark_ed_on_bn254::{EdwardsAffine, Fr as BJJFr};

#[cfg(test)]
mod tests {
    #[test]
    fn print_bjj_constants() {
        use ark_bn254::Fr as BN254Fr;
        use ark_ec::twisted_edwards::TECurveConfig;
        use ark_ed_on_bn254::{EdwardsAffine, EdwardsConfig, Fr as BJJFr};
        use ark_ff::PrimeField;

        let g: EdwardsAffine = EdwardsConfig::GENERATOR;
        eprintln!("GEN_X (LE u64): {:?}", g.x.into_bigint().0);
        eprintln!("GEN_Y (LE u64): {:?}", g.y.into_bigint().0);
        eprintln!(
            "COEFF_A (LE u64): {:?}",
            EdwardsConfig::COEFF_A.into_bigint().0
        );
        eprintln!(
            "COEFF_D (LE u64): {:?}",
            EdwardsConfig::COEFF_D.into_bigint().0
        );
        eprintln!("BJJFr MODULUS (LE u64): {:?}", BJJFr::MODULUS.0);

        // BN254 Fr constants needed for on-chain field arithmetic
        eprintln!("BN254Fr MODULUS (LE u64): {:?}", BN254Fr::MODULUS.0);
        // Montgomery constant: -p0^{-1} mod 2^64, computed via Newton lifting
        let p0: u64 = BN254Fr::MODULUS.0[0];
        let mut inv: u64 = 1;
        for _ in 0..63 {
            inv = inv.wrapping_mul(inv);
            inv = inv.wrapping_mul(p0);
        }
        inv = inv.wrapping_neg(); // -p0^{-1}
        eprintln!("BN254Fr Montgomery inv (-p0^{{-1}} mod 2^64): 0x{inv:016x}");
        // R^2 mod p (= 2 in Montgomery form, useful for converting to Montgomery)
        let two = BN254Fr::from(2u64);
        eprintln!("BN254Fr 2 (canonical BigInt): {:?}", two.into_bigint().0);
        // Verify: (p0 * inv) mod 2^64 should be 2^64 - 1 = 0xffffffffffffffff
        eprintln!(
            "p0 * inv mod 2^64 = 0x{:016x} (should be 0xffffffffffffffff)",
            p0.wrapping_mul(inv)
        );
        // R^2 mod p: needed for Montgomery to-form conversion
        use ark_ff::MontConfig;
        eprintln!("BN254Fr R2 (LE u64): {:?}", ark_bn254::FrConfig::R2.0);
    }
}
