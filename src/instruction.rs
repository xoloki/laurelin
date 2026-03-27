use crate::state::{G1Point, Groth16Proof, Scalar};

pub enum LaurelinInstruction {
    /// opcode 0 — create a new account PDA
    /// data: pubkey (64) || c1 (64) || c2 (64)
    CreateAccount {
        pubkey: G1Point,
        c1: G1Point,
        c2: G1Point,
    },

    /// opcode 1 — 2+2 ring transfer with Groth16 balance proof
    ///
    /// data layout (864 byte payload, 865 bytes total):
    ///   proof (256) || commitment (64) || commit_hash (32)
    ///   || sender_new_c1[0] (64) || sender_new_c2[0] (64)
    ///   || sender_new_c1[1] (64) || sender_new_c2[1] (64)
    ///   || recv_delta_c1[0] (64) || recv_delta_c2[0] (64)
    ///   || recv_delta_c1[1] (64) || recv_delta_c2[1] (64)
    ///
    /// commitment  — proof.Commitments[0] (G1, x||y big-endian)
    /// commit_hash — BSB22 hash H(commitment || limb_0..127), IC[129] slot
    ///
    /// accounts: [senderPDA0 (write), senderPDA1 (write),
    ///            recvPDA0   (write), recvPDA1   (write)]
    RingTransfer {
        proof: Groth16Proof,
        commitment: G1Point,
        commit_hash: Scalar,
        /// New sender ciphertexts (both ring members updated)
        sender_new_c1: [G1Point; 2],
        sender_new_c2: [G1Point; 2],
        /// Receiver deltas (slot i added to recvPDA[i])
        recv_delta_c1: [G1Point; 2],
        recv_delta_c2: [G1Point; 2],
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
                // proof(256) + commitment(64) + commit_hash(32) + 8×G1(512) = 864
                if rest.len() < 864 {
                    return None;
                }
                let proof = Groth16Proof::try_from_bytes(&rest[0..256])?;
                let mut commitment  = [0u8; 64];
                let mut commit_hash = [0u8; 32];
                commitment.copy_from_slice(&rest[256..320]);
                commit_hash.copy_from_slice(&rest[320..352]);

                let mut sender_new_c1 = [[0u8; 64]; 2];
                let mut sender_new_c2 = [[0u8; 64]; 2];
                let mut recv_delta_c1 = [[0u8; 64]; 2];
                let mut recv_delta_c2 = [[0u8; 64]; 2];

                let off = 352;
                sender_new_c1[0].copy_from_slice(&rest[off..off+64]);
                sender_new_c2[0].copy_from_slice(&rest[off+64..off+128]);
                sender_new_c1[1].copy_from_slice(&rest[off+128..off+192]);
                sender_new_c2[1].copy_from_slice(&rest[off+192..off+256]);
                recv_delta_c1[0].copy_from_slice(&rest[off+256..off+320]);
                recv_delta_c2[0].copy_from_slice(&rest[off+320..off+384]);
                recv_delta_c1[1].copy_from_slice(&rest[off+384..off+448]);
                recv_delta_c2[1].copy_from_slice(&rest[off+448..off+512]);

                Some(Self::RingTransfer {
                    proof,
                    commitment,
                    commit_hash,
                    sender_new_c1,
                    sender_new_c2,
                    recv_delta_c1,
                    recv_delta_c2,
                })
            }
            _ => None,
        }
    }
}
