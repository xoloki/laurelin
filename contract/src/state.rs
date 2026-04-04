/// Baby JubJub point: X||Y, 64 bytes big-endian. Identity = (0, 1).
pub type BJJPoint = [u8; 64];
/// BN254 G1 point: X||Y, 64 bytes big-endian (used in Groth16 proofs).
pub type G1Point = [u8; 64];
/// BN254 G2 point: x.c1||x.c0||y.c1||y.c0, 128 bytes big-endian EIP-197.
pub type G2Point = [u8; 128];
/// BN254 Fr scalar, 32 bytes big-endian (BJJ coordinates are also BN254 Fr).
pub type Scalar = [u8; 32];

/// On-chain account state stored in a PDA.
/// Total: 192 bytes
pub struct AccountState {
    pub pubkey: BJJPoint, // account's BJJ public key P = sk*G
    pub c1: BJJPoint,     // ElGamal C1 = r*G
    pub c2: BJJPoint,     // ElGamal C2 = r*P + v*G
}

impl AccountState {
    pub const LEN: usize = 64 + 64 + 64;

    pub fn try_from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::LEN {
            return None;
        }
        let mut pubkey = [0u8; 64];
        let mut c1 = [0u8; 64];
        let mut c2 = [0u8; 64];
        pubkey.copy_from_slice(&data[0..64]);
        c1.copy_from_slice(&data[64..128]);
        c2.copy_from_slice(&data[128..192]);
        Some(Self { pubkey, c1, c2 })
    }

    pub fn write_to(&self, data: &mut [u8]) {
        data[0..64].copy_from_slice(&self.pubkey);
        data[64..128].copy_from_slice(&self.c1);
        data[128..192].copy_from_slice(&self.c2);
    }
}

/// Groth16 proof: A (G1, 64B) || B (G2, 128B) || C (G1, 64B) = 256 bytes
pub struct Groth16Proof {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
}

impl Groth16Proof {
    pub const LEN: usize = 64 + 128 + 64;

    pub fn try_from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::LEN {
            return None;
        }
        let mut a = [0u8; 64];
        let mut b = [0u8; 128];
        let mut c = [0u8; 64];
        a.copy_from_slice(&data[0..64]);
        b.copy_from_slice(&data[64..192]);
        c.copy_from_slice(&data[192..256]);
        Some(Self { a, b, c })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_state_round_trip() {
        let mut data = [0u8; 192];
        for i in 0..192 {
            data[i] = i as u8;
        }
        let state = AccountState::try_from_bytes(&data).unwrap();
        assert_eq!(&state.pubkey[..], &data[0..64]);
        assert_eq!(&state.c1[..], &data[64..128]);
        assert_eq!(&state.c2[..], &data[128..192]);
        let mut out = [0u8; 192];
        state.write_to(&mut out);
        assert_eq!(data, out);
    }

    #[test]
    fn account_state_too_short() {
        assert!(AccountState::try_from_bytes(&[0u8; 191]).is_none());
    }

    #[test]
    fn account_state_exact_length() {
        assert!(AccountState::try_from_bytes(&[0u8; 192]).is_some());
    }

    #[test]
    fn groth16_proof_round_trip() {
        let mut data = [0u8; 256];
        for i in 0..256 {
            data[i] = i as u8;
        }
        let proof = Groth16Proof::try_from_bytes(&data).unwrap();
        assert_eq!(&proof.a[..], &data[0..64]);
        assert_eq!(&proof.b[..], &data[64..192]);
        assert_eq!(&proof.c[..], &data[192..256]);
    }

    #[test]
    fn groth16_proof_too_short() {
        assert!(Groth16Proof::try_from_bytes(&[0u8; 255]).is_none());
    }

    #[test]
    fn groth16_proof_exact_length() {
        assert!(Groth16Proof::try_from_bytes(&[0u8; 256]).is_some());
    }
}
