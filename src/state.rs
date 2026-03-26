pub type G1Point = [u8; 64];
pub type G2Point = [u8; 128];
pub type Scalar = [u8; 32];

/// On-chain account state stored in a PDA.
/// Total: 192 bytes
pub struct AccountState {
    pub pubkey: G1Point, // account's BN254 public key P = sk*G
    pub c1: G1Point,     // r*G
    pub c2: G1Point,     // r*P + v*G
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
