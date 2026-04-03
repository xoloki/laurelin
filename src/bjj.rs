//! Pure-Rust (no_std) Baby JubJub arithmetic for the Solana on-chain program.
//!
//! Baby JubJub is a twisted Edwards curve over BN254's Fr field with:
//!   a = 1,  d = D_CANONICAL
//!   x3 = (x1·y2 + y1·x2) / (1 + d·x1·x2·y1·y2)
//!   y3 = (y1·y2 − x1·x2) / (1 − d·x1·x2·y1·y2)
//!
//! Uses the extended projective addition formula to avoid field inversions
//! during the main computation (only 1 inversion for the final affine output).
//!
//! Points are serialised as X||Y (32+32 bytes, big-endian BN254 Fr elements).
//! The identity is (0, 1).

// ── BN254 Fr constants ────────────────────────────────────────────────────────

/// BN254 Fr modulus p, little-endian u64.
const P: [u64; 4] = [
    4891460686036598785,
    2896914383306846353,
    13281191951274694749,
    3486998266802970665,
];

/// Montgomery constant μ = −p₀⁻¹ mod 2⁶⁴.
const MU: u64 = 0xc2e1f593efffffff;

/// R² mod p in canonical (non-Montgomery) form, little-endian u64.
const R2: [u64; 4] = [
    1997599621687373223,
    6052339484930628067,
    10108755138030829701,
    150537098327114917,
];

/// BJJ curve parameter d, canonical form, little-endian u64.
const D: [u64; 4] = [
    8317069920829969523,
    2637067513619392553,
    8817998450223498849,
    1546350411002156736,
];

// ── 256-bit Montgomery arithmetic ─────────────────────────────────────────────

/// Montgomery multiplication: a·b·R⁻¹ mod p.
/// Inputs are plain 256-bit integers in [0, p); no Montgomery encoding assumed.
/// Uses CIOS algorithm with 4 limbs.
fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 5];

    for i in 0..4 {
        // Add a[i] * b to t
        let mut carry: u128 = 0;
        for j in 0..4 {
            let prod = (a[i] as u128) * (b[j] as u128) + (t[j] as u128) + carry;
            t[j] = prod as u64;
            carry = prod >> 64;
        }
        t[4] = t[4].wrapping_add(carry as u64);

        // Reduction: m = t[0] * MU mod 2^64; t += m * P
        let m = t[0].wrapping_mul(MU);
        let mut carry: u128 = 0;
        for j in 0..4 {
            let prod = (m as u128) * (P[j] as u128) + (t[j] as u128) + carry;
            t[j] = prod as u64;
            carry = prod >> 64;
        }
        t[4] = t[4].wrapping_add(carry as u64);

        // Shift right one limb (t[0] is now 0 by the Montgomery property)
        t.copy_within(1..5, 0);
        t[4] = 0;
    }

    let r = [t[0], t[1], t[2], t[3]];
    cond_sub_p(r)
}

/// Conditionally subtract p if r >= p.
fn cond_sub_p(r: [u64; 4]) -> [u64; 4] {
    if !ge_p(&r) {
        return r;
    }
    let mut out = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d, b1) = r[i].overflowing_sub(P[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        out[i] = d;
        borrow = (b1 as u64) + (b2 as u64);
    }
    out
}

/// Return true if a >= p.
fn ge_p(a: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > P[i] {
            return true;
        }
        if a[i] < P[i] {
            return false;
        }
    }
    true
}

// ── Field operations (canonical form in, canonical form out) ──────────────────

/// a + b mod p, inputs and output canonical.
fn field_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut carry: u64 = 0;
    for i in 0..4 {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(carry);
        r[i] = s;
        carry = (c1 as u64) + (c2 as u64);
    }
    cond_sub_p(r)
}

/// a − b mod p, inputs and output canonical.
fn field_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        r[i] = d;
        borrow = (b1 as u64) + (b2 as u64);
    }
    if borrow != 0 {
        // Add p back
        let mut carry: u64 = 0;
        for i in 0..4 {
            let (s, c1) = r[i].overflowing_add(P[i]);
            let (s, c2) = s.overflowing_add(carry);
            r[i] = s;
            carry = (c1 as u64) + (c2 as u64);
        }
    }
    r
}

/// a * b mod p, inputs and output canonical.
///
/// Uses 2 mont_mul calls: to_mont(a) = mont_mul(a, R2), then the product
/// mont_mul(a*R, b) = a*b*R⁻¹*R = a*b. Wait, let me spell it out:
///   mont_mul(a, R2) = a * R2 * R⁻¹ = a * R  (= Montgomery form of a)
///   mont_mul(a*R, b) = (a*R) * b * R⁻¹ = a*b mod p  (canonical)
fn field_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let am = mont_mul(a, &R2); // a·R mod p
    mont_mul(&am, b) // (a·R)·b·R⁻¹ = a·b mod p
}

/// a⁻¹ mod p via Fermat's little theorem (a^{p−2}).
/// Input and output canonical. Uses ~380 mont_mul calls.
fn field_inv(a: &[u64; 4]) -> [u64; 4] {
    // p − 2 in little-endian u64
    let pm2 = [P[0].wrapping_sub(2), P[1], P[2], P[3]];

    // Work in Montgomery form throughout to avoid repeated to/from conversions.
    // base = a in Montgomery form (= a·R)
    let mut base = mont_mul(a, &R2);
    // result = 1 in Montgomery form (= R mod p)
    // mont_mul([1,0,0,0], R2) = 1·R2·R⁻¹ = R
    let one = [1u64, 0, 0, 0];
    let mut result = mont_mul(&one, &R2);

    for &limb in &pm2 {
        for bit in 0..64 {
            if (limb >> bit) & 1 == 1 {
                result = mont_mul(&result, &base);
            }
            base = mont_mul(&base, &base);
        }
    }

    // result is a^{p−2}·R in Montgomery form; convert to canonical
    mont_mul(&result, &one)
}

// ── Byte conversions ──────────────────────────────────────────────────────────

/// Parse a 32-byte big-endian field element into little-endian u64 limbs.
fn fr_from_be(b: &[u8; 32]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in 0..4 {
        let off = (3 - i) * 8;
        r[i] = u64::from_be_bytes([
            b[off],
            b[off + 1],
            b[off + 2],
            b[off + 3],
            b[off + 4],
            b[off + 5],
            b[off + 6],
            b[off + 7],
        ]);
    }
    r
}

/// Serialize little-endian u64 limbs to a 32-byte big-endian field element.
fn fr_to_be(a: &[u64; 4]) -> [u8; 32] {
    let mut r = [0u8; 32];
    for i in 0..4 {
        let off = (3 - i) * 8;
        let bytes = a[i].to_be_bytes();
        r[off..off + 8].copy_from_slice(&bytes);
    }
    r
}

// ── BJJ point addition ─────────────────────────────────────────────────────────

/// Add two Baby JubJub points given as X||Y (64-byte, big-endian coordinates).
/// Returns the result as a 64-byte X||Y big-endian array, or Err(()) on error.
pub fn bjj_add(a: &[u8; 64], b: &[u8; 64]) -> Result<[u8; 64], ()> {
    let ax = fr_from_be(a[0..32].try_into().map_err(|_| ())?);
    let ay = fr_from_be(a[32..64].try_into().map_err(|_| ())?);
    let bx = fr_from_be(b[0..32].try_into().map_err(|_| ())?);
    let by = fr_from_be(b[32..64].try_into().map_err(|_| ())?);

    // Identity = (0, 1)
    let zero = [0u64; 4];
    let one = [1u64, 0, 0, 0];
    if ax == zero && ay == one {
        return Ok(*b);
    }
    if bx == zero && by == one {
        return Ok(*a);
    }

    // Extended projective unified addition for twisted Edwards a=1 (Bernstein et al.):
    //   A = x1·x2,  B = y1·y2,  C = d·T1·T2  (T = x·y for affine Z=1)
    //   E = (x1+y1)·(x2+y2) − A − B  (= x1·y2 + y1·x2)
    //   F = 1 − C,  G = 1 + C,  H = B − A
    //   X3 = E·F,  Y3 = G·H,  Z3 = F·G
    //   Affine: x3 = E/G,  y3 = H/F
    let a_t = field_mul(&ax, &bx); // A = x1·x2
    let b_t = field_mul(&ay, &by); // B = y1·y2
    let ab = field_mul(&a_t, &b_t); // A·B = T1·T2 (for affine inputs)
    let c = field_mul(&D, &ab); // C = d·T1·T2

    let sum1 = field_add(&ax, &ay); // x1+y1
    let sum2 = field_add(&bx, &by); // x2+y2
    let prod = field_mul(&sum1, &sum2); // (x1+y1)·(x2+y2)
    let e = field_sub(&field_sub(&prod, &a_t), &b_t); // E = prod − A − B

    let f = field_sub(&one, &c); // F = 1 − C
    let g = field_add(&one, &c); // G = 1 + C
    let h = field_sub(&b_t, &a_t); // H = B − A

    let x3_proj = field_mul(&e, &f); // E·F
    let y3_proj = field_mul(&g, &h); // G·H
    let z3 = field_mul(&f, &g); // F·G

    if z3 == zero {
        return Err(()); // degenerate (shouldn't happen with valid curve points)
    }

    // Convert to affine: divide by Z3
    let z3_inv = field_inv(&z3);
    let x3 = field_mul(&x3_proj, &z3_inv);
    let y3 = field_mul(&y3_proj, &z3_inv);

    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&fr_to_be(&x3));
    out[32..64].copy_from_slice(&fr_to_be(&y3));
    Ok(out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// BJJ generator point (from ark-ed-on-bn254 GENERATOR constant).
    fn gen_x() -> [u64; 4] {
        [
            6472377509509295154,
            16410064374334370893,
            2108221045001065086,
            3138161842686642915,
        ]
    }

    fn gen_y() -> [u64; 4] {
        [
            14012664558248429087,
            3061340632283930986,
            10424967955126647670,
            3074388600315977886,
        ]
    }

    fn gen_point() -> [u8; 64] {
        let mut p = [0u8; 64];
        p[0..32].copy_from_slice(&fr_to_be(&gen_x()));
        p[32..64].copy_from_slice(&fr_to_be(&gen_y()));
        p
    }

    fn identity() -> [u8; 64] {
        let mut p = [0u8; 64];
        // X = 0
        // Y = 1
        p[63] = 1;
        p
    }

    #[test]
    fn identity_plus_gen_is_gen() {
        let id = identity();
        let g = gen_point();
        let result = bjj_add(&id, &g).unwrap();
        assert_eq!(result, g, "id + G should be G");
    }

    #[test]
    fn gen_plus_identity_is_gen() {
        let id = identity();
        let g = gen_point();
        let result = bjj_add(&g, &id).unwrap();
        assert_eq!(result, g, "G + id should be G");
    }

    #[test]
    fn gen_plus_gen_is_2g() {
        // 2G must be a valid point: just check it doesn't error and both coords < p
        let g = gen_point();
        let two_g = bjj_add(&g, &g).unwrap();
        let x = fr_from_be(two_g[0..32].try_into().unwrap());
        let y = fr_from_be(two_g[32..64].try_into().unwrap());
        // Verify 2G satisfies the curve equation: x^2 + y^2 = 1 + d*x^2*y^2
        let x2 = field_mul(&x, &x);
        let y2 = field_mul(&y, &y);
        let lhs = field_add(&x2, &y2);
        let x2y2 = field_mul(&x2, &y2);
        let rhs = field_add(&[1, 0, 0, 0], &field_mul(&D, &x2y2));
        assert_eq!(lhs, rhs, "2G must satisfy the curve equation");
    }

    #[test]
    fn field_mul_commutative() {
        let a = [7u64, 3, 1, 5];
        let b = [11u64, 2, 8, 1];
        assert_eq!(field_mul(&a, &b), field_mul(&b, &a));
    }

    #[test]
    fn field_inv_roundtrip() {
        let a = [42u64, 0, 0, 0];
        let inv = field_inv(&a);
        let product = field_mul(&a, &inv);
        assert_eq!(product, [1u64, 0, 0, 0], "a * a^{{-1}} should be 1");
    }

    #[test]
    fn field_mul_by_one() {
        let a = gen_x();
        let one = [1u64, 0, 0, 0];
        assert_eq!(field_mul(&a, &one), a);
    }
}
