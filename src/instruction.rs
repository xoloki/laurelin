use crate::state::{G1Point, Groth16Proof, Scalar};

#[cfg(not(test))]
use alloc::vec::Vec;

pub enum LaurelinInstruction {
    /// opcode 0 — create a new account PDA
    /// data: pubkey (64) || c1 (64) || c2 (64)
    CreateAccount {
        pubkey: G1Point,
        c1: G1Point,
        c2: G1Point,
    },

    /// opcode 1 — ring transfer with Groth16 balance proof
    /// data: proof (256) || new_sender_c1 (64) || new_sender_c2 (64)
    ///       || new_recv_c1 (64) || new_recv_c2 (64)
    /// accounts: [sender_pda (write), receiver_pda (write), ring_0..n (read)]
    Transfer {
        proof: Groth16Proof,
        new_sender_c1: G1Point,
        new_sender_c2: G1Point,
        new_recv_c1: G1Point,
        new_recv_c2: G1Point,
    },

    /// opcode 2 — standalone proof verifier (useful for testing)
    /// data: proof (256) || n_inputs (1) || inputs (n * 32)
    VerifyProof {
        proof: Groth16Proof,
        public_inputs: Vec<Scalar>,
    },
}

impl LaurelinInstruction {
    pub fn try_from_bytes(data: &[u8]) -> Option<Self> {
        let (&opcode, rest) = data.split_first()?;
        match opcode {
            0 => {
                if rest.len() < 192 {
                    return None;
                }
                let mut pubkey = [0u8; 64];
                let mut c1 = [0u8; 64];
                let mut c2 = [0u8; 64];
                pubkey.copy_from_slice(&rest[0..64]);
                c1.copy_from_slice(&rest[64..128]);
                c2.copy_from_slice(&rest[128..192]);
                Some(Self::CreateAccount { pubkey, c1, c2 })
            }
            1 => {
                // proof (256) + 4 * G1Point (4*64 = 256) = 512 bytes
                if rest.len() < 512 {
                    return None;
                }
                let proof = Groth16Proof::try_from_bytes(&rest[0..256])?;
                let mut new_sender_c1 = [0u8; 64];
                let mut new_sender_c2 = [0u8; 64];
                let mut new_recv_c1 = [0u8; 64];
                let mut new_recv_c2 = [0u8; 64];
                new_sender_c1.copy_from_slice(&rest[256..320]);
                new_sender_c2.copy_from_slice(&rest[320..384]);
                new_recv_c1.copy_from_slice(&rest[384..448]);
                new_recv_c2.copy_from_slice(&rest[448..512]);
                Some(Self::Transfer {
                    proof,
                    new_sender_c1,
                    new_sender_c2,
                    new_recv_c1,
                    new_recv_c2,
                })
            }
            2 => {
                // proof (256) + n (1) + n*32
                if rest.len() < 257 {
                    return None;
                }
                let proof = Groth16Proof::try_from_bytes(&rest[0..256])?;
                let n = rest[256] as usize;
                if rest.len() < 257 + n * 32 {
                    return None;
                }
                let mut public_inputs = Vec::with_capacity(n);
                for i in 0..n {
                    let mut s = [0u8; 32];
                    s.copy_from_slice(&rest[257 + i * 32..257 + (i + 1) * 32]);
                    public_inputs.push(s);
                }
                Some(Self::VerifyProof { proof, public_inputs })
            }
            _ => None,
        }
    }
}
