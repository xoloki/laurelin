use crate::state::{G1Point, Groth16Proof, Scalar};

pub enum LaurelinInstruction {
    /// opcode 0 — create a new account PDA
    /// data: pubkey (64) || c1 (64) || c2 (64)
    CreateAccount {
        pubkey: G1Point,
        c1: G1Point,
        c2: G1Point,
    },

    /// opcode 1 — ring transfer with Groth16 balance proof
    /// data: proof (256) || commitment (64) || commit_hash (32)
    ///       || new_sender_c1 (64) || new_sender_c2 (64)
    ///       || new_recv_c1 (64) || new_recv_c2 (64)
    /// = 608 bytes payload
    ///
    /// commitment  — proof.Commitments[0] in uncompressed G1 format (x||y)
    /// commit_hash — H(commitment || limb_0 || … || limb_55) hashed with
    ///               gnark's bsb22 hash-to-field (ExpandMsgXMD/SHA-256),
    ///               pre-computed by the prover; goes into IC[57] slot.
    Transfer {
        proof: Groth16Proof,
        commitment: G1Point,
        commit_hash: Scalar,
        new_sender_c1: G1Point,
        new_sender_c2: G1Point,
        new_recv_c1: G1Point,
        new_recv_c2: G1Point,
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
                // proof(256) + commitment(64) + commit_hash(32) + 4×G1(256) = 608
                if rest.len() < 608 {
                    return None;
                }
                let proof = Groth16Proof::try_from_bytes(&rest[0..256])?;
                let mut commitment = [0u8; 64];
                let mut commit_hash = [0u8; 32];
                let mut new_sender_c1 = [0u8; 64];
                let mut new_sender_c2 = [0u8; 64];
                let mut new_recv_c1 = [0u8; 64];
                let mut new_recv_c2 = [0u8; 64];
                commitment.copy_from_slice(&rest[256..320]);
                commit_hash.copy_from_slice(&rest[320..352]);
                new_sender_c1.copy_from_slice(&rest[352..416]);
                new_sender_c2.copy_from_slice(&rest[416..480]);
                new_recv_c1.copy_from_slice(&rest[480..544]);
                new_recv_c2.copy_from_slice(&rest[544..608]);
                Some(Self::Transfer {
                    proof,
                    commitment,
                    commit_hash,
                    new_sender_c1,
                    new_sender_c2,
                    new_recv_c1,
                    new_recv_c2,
                })
            }
            _ => None,
        }
    }
}
