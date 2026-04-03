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
