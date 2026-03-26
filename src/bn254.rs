#[cfg(not(test))]
use alloc::{vec, vec::Vec};

use solana_program::alt_bn128::prelude::{
    alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing,
};

use crate::state::{G1Point, G2Point};

// BN254 base field prime p (big-endian)
const FIELD_PRIME: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// Negate a G1 point: (x, y) -> (x, p - y)
pub fn g1_negate(point: &G1Point) -> G1Point {
    let mut result = *point;
    let y = &point[32..64];
    // if point is identity (all zeros), return identity
    if point.iter().all(|&b| b == 0) {
        return [0u8; 64];
    }
    result[32..64].copy_from_slice(&field_neg(y));
    result
}

/// Compute (p - x) mod p for a 32-byte big-endian field element
fn field_neg(x: &[u8]) -> [u8; 32] {
    if x.iter().all(|&b| b == 0) {
        return [0u8; 32];
    }
    let mut result = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let diff = (FIELD_PRIME[i] as u16)
            .wrapping_sub(x[i] as u16)
            .wrapping_sub(borrow);
        result[i] = diff as u8;
        borrow = if diff > 0xff { 1 } else { 0 };
    }
    result
}

pub fn g1_add(a: &G1Point, b: &G1Point) -> Result<G1Point, ()> {
    let mut input = [0u8; 128];
    input[0..64].copy_from_slice(a);
    input[64..128].copy_from_slice(b);
    alt_bn128_addition(&input)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
}

pub fn g1_mul(point: &G1Point, scalar: &[u8; 32]) -> Result<G1Point, ()> {
    let mut input = [0u8; 96];
    input[0..64].copy_from_slice(point);
    input[64..96].copy_from_slice(scalar);
    alt_bn128_multiplication(&input)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
}

/// Check that the product of pairings equals 1 in GT.
/// pairs: slice of (G1, G2). G2 uses EIP-197 encoding: x_c1||x_c0||y_c1||y_c0.
pub fn pairing_check(pairs: &[(&G1Point, &G2Point)]) -> Result<bool, ()> {
    let mut input = vec![0u8; pairs.len() * 192];
    for (i, (g1, g2)) in pairs.iter().enumerate() {
        let off = i * 192;
        input[off..off + 64].copy_from_slice(*g1);
        input[off + 64..off + 192].copy_from_slice(*g2);
    }
    let result = alt_bn128_pairing(&input).map_err(|_| ())?;
    Ok(result[31] == 1 && result[..31].iter().all(|&b| b == 0))
}
