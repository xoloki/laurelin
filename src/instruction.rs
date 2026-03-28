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

    /// opcode 2 — deposit lamports into an account with Groth16 delta proof
    ///
    /// data layout (392 byte payload, 393 bytes total):
    ///   proof (256) || commitment (64) || commit_hash (32)
    ///   || delta_c1 (64) || delta_c2 (64) || amount (8, u64 LE)
    ///
    /// The proof establishes that delta_c1 = R*G and delta_c2 = R*Pk + amount*G
    /// for a consistent R. The program adds the delta homomorphically to the
    /// stored ciphertext, then transfers amount lamports from payer to the pool PDA.
    ///
    /// accounts: [payer (write, signer), pda (write), vault_pda (write), system_program]
    Deposit {
        proof: Groth16Proof,
        commitment: G1Point,
        commit_hash: Scalar,
        delta_c1: G1Point,
        delta_c2: G1Point,
        amount: u64,
    },

    /// opcode 3 — withdraw lamports with Groth16 balance proof
    ///
    /// data layout (488 byte payload, 489 bytes total):
    ///   proof (256) || commitment (64) || commit_hash (32)
    ///   || new_c1 (64) || new_c2 (64) || amount (8, u64 LE)
    ///
    /// accounts: [pda (write), vault_pda (write), destination (write)]
    Withdraw {
        proof: Groth16Proof,
        commitment: G1Point,
        commit_hash: Scalar,
        new_c1: G1Point,
        new_c2: G1Point,
        amount: u64,
    },

}

/// Parse a CreateAccount payload (no opcode byte): pubkey(64) || c1(64) || c2(64)
pub fn parse_create_account(data: &[u8]) -> Option<LaurelinInstruction> {
    if data.len() < 192 { return None; }
    let mut pubkey = [0u8; 64];
    let mut c1     = [0u8; 64];
    let mut c2     = [0u8; 64];
    pubkey.copy_from_slice(&data[0..64]);
    c1.copy_from_slice(&data[64..128]);
    c2.copy_from_slice(&data[128..192]);
    Some(LaurelinInstruction::CreateAccount { pubkey, c1, c2 })
}

/// Parse a RingTransfer payload (no opcode byte):
/// proof(256) || commitment(64) || commit_hash(32) || 8×G1(512)
pub fn parse_ring_transfer(data: &[u8]) -> Option<LaurelinInstruction> {
    if data.len() < 864 { return None; }
    let proof = Groth16Proof::try_from_bytes(&data[0..256])?;
    let mut commitment  = [0u8; 64];
    let mut commit_hash = [0u8; 32];
    commitment.copy_from_slice(&data[256..320]);
    commit_hash.copy_from_slice(&data[320..352]);
    let mut sender_new_c1 = [[0u8; 64]; 2];
    let mut sender_new_c2 = [[0u8; 64]; 2];
    let mut recv_delta_c1 = [[0u8; 64]; 2];
    let mut recv_delta_c2 = [[0u8; 64]; 2];
    let off = 352;
    sender_new_c1[0].copy_from_slice(&data[off..off+64]);
    sender_new_c2[0].copy_from_slice(&data[off+64..off+128]);
    sender_new_c1[1].copy_from_slice(&data[off+128..off+192]);
    sender_new_c2[1].copy_from_slice(&data[off+192..off+256]);
    recv_delta_c1[0].copy_from_slice(&data[off+256..off+320]);
    recv_delta_c2[0].copy_from_slice(&data[off+320..off+384]);
    recv_delta_c1[1].copy_from_slice(&data[off+384..off+448]);
    recv_delta_c2[1].copy_from_slice(&data[off+448..off+512]);
    Some(LaurelinInstruction::RingTransfer {
        proof, commitment, commit_hash,
        sender_new_c1, sender_new_c2,
        recv_delta_c1, recv_delta_c2,
    })
}

/// Parse a Deposit payload (no opcode byte):
/// proof(256) || commitment(64) || commit_hash(32) || delta_c1(64) || delta_c2(64) || amount(8)
pub fn parse_deposit(data: &[u8]) -> Option<LaurelinInstruction> {
    if data.len() < 488 { return None; }
    let proof = Groth16Proof::try_from_bytes(&data[0..256])?;
    let mut commitment  = [0u8; 64];
    let mut commit_hash = [0u8; 32];
    let mut delta_c1    = [0u8; 64];
    let mut delta_c2    = [0u8; 64];
    commitment.copy_from_slice(&data[256..320]);
    commit_hash.copy_from_slice(&data[320..352]);
    delta_c1.copy_from_slice(&data[352..416]);
    delta_c2.copy_from_slice(&data[416..480]);
    let amount = u64::from_le_bytes(data[480..488].try_into().ok()?);
    Some(LaurelinInstruction::Deposit { proof, commitment, commit_hash, delta_c1, delta_c2, amount })
}

/// Parse a Withdraw payload (no opcode byte):
/// proof(256) || commitment(64) || commit_hash(32) || new_c1(64) || new_c2(64) || amount(8)
pub fn parse_withdraw(data: &[u8]) -> Option<LaurelinInstruction> {
    if data.len() < 488 { return None; }
    let proof = Groth16Proof::try_from_bytes(&data[0..256])?;
    let mut commitment  = [0u8; 64];
    let mut commit_hash = [0u8; 32];
    let mut new_c1      = [0u8; 64];
    let mut new_c2      = [0u8; 64];
    commitment.copy_from_slice(&data[256..320]);
    commit_hash.copy_from_slice(&data[320..352]);
    new_c1.copy_from_slice(&data[352..416]);
    new_c2.copy_from_slice(&data[416..480]);
    let amount = u64::from_le_bytes(data[480..488].try_into().ok()?);
    Some(LaurelinInstruction::Withdraw { proof, commitment, commit_hash, new_c1, new_c2, amount })
}

impl LaurelinInstruction {
    pub fn try_from_bytes(data: &[u8]) -> Option<Self> {
        let (&opcode, rest) = data.split_first()?;
        match opcode {
            0 => parse_create_account(rest),
            1 => parse_ring_transfer(rest),
            2 => parse_deposit(rest),
            3 => parse_withdraw(rest),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_none() {
        assert!(LaurelinInstruction::try_from_bytes(&[]).is_none());
    }

    #[test]
    fn unknown_opcode_returns_none() {
        assert!(LaurelinInstruction::try_from_bytes(&[42u8; 300]).is_none());
    }

    #[test]
    fn create_account_parses_correctly() {
        let mut data = [0u8; 193];
        data[0] = 0;
        for i in 1..193 { data[i] = i as u8; }
        match LaurelinInstruction::try_from_bytes(&data).unwrap() {
            LaurelinInstruction::CreateAccount { pubkey, c1, c2 } => {
                assert_eq!(&pubkey[..], &data[1..65]);
                assert_eq!(&c1[..], &data[65..129]);
                assert_eq!(&c2[..], &data[129..193]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn create_account_too_short_returns_none() {
        // opcode byte + 191 payload = 192 total; need 193
        let mut data = [0u8; 192];
        data[0] = 0;
        assert!(LaurelinInstruction::try_from_bytes(&data).is_none());
    }

    #[test]
    fn ring_transfer_parses_correctly() {
        let mut data = [0u8; 865];
        data[0] = 1;
        for i in 1..865 { data[i] = (i % 251) as u8; }
        match LaurelinInstruction::try_from_bytes(&data).unwrap() {
            LaurelinInstruction::RingTransfer {
                proof, commitment, commit_hash,
                sender_new_c1, sender_new_c2,
                recv_delta_c1, recv_delta_c2,
            } => {
                // proof: rest[0..256] = data[1..257]
                assert_eq!(&proof.a[..], &data[1..65]);
                assert_eq!(&proof.b[..], &data[65..193]);
                assert_eq!(&proof.c[..], &data[193..257]);
                // commitment: rest[256..320] = data[257..321]
                assert_eq!(&commitment[..], &data[257..321]);
                // commit_hash: rest[320..352] = data[321..353]
                assert_eq!(&commit_hash[..], &data[321..353]);
                // ciphertexts: rest[352..] = data[353..]
                assert_eq!(&sender_new_c1[0][..], &data[353..417]);
                assert_eq!(&sender_new_c2[0][..], &data[417..481]);
                assert_eq!(&sender_new_c1[1][..], &data[481..545]);
                assert_eq!(&sender_new_c2[1][..], &data[545..609]);
                assert_eq!(&recv_delta_c1[0][..], &data[609..673]);
                assert_eq!(&recv_delta_c2[0][..], &data[673..737]);
                assert_eq!(&recv_delta_c1[1][..], &data[737..801]);
                assert_eq!(&recv_delta_c2[1][..], &data[801..865]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn ring_transfer_too_short_returns_none() {
        // opcode byte + 863 payload = 864 total; need 865
        let mut data = [0u8; 864];
        data[0] = 1;
        assert!(LaurelinInstruction::try_from_bytes(&data).is_none());
    }

    #[test]
    fn deposit_parses_correctly() {
        let mut data = [0u8; 489];
        data[0] = 2;
        for i in 1..489 { data[i] = (i % 251) as u8; }
        let expected_amount = u64::from_le_bytes(data[481..489].try_into().unwrap());
        match LaurelinInstruction::try_from_bytes(&data).unwrap() {
            LaurelinInstruction::Deposit { proof, commitment, commit_hash, delta_c1, delta_c2, amount } => {
                assert_eq!(&proof.a[..],     &data[1..65]);
                assert_eq!(&proof.b[..],     &data[65..193]);
                assert_eq!(&proof.c[..],     &data[193..257]);
                assert_eq!(&commitment[..],  &data[257..321]);
                assert_eq!(&commit_hash[..], &data[321..353]);
                assert_eq!(&delta_c1[..],    &data[353..417]);
                assert_eq!(&delta_c2[..],    &data[417..481]);
                assert_eq!(amount, expected_amount);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn deposit_too_short_returns_none() {
        let mut data = [0u8; 488];
        data[0] = 2;
        assert!(LaurelinInstruction::try_from_bytes(&data).is_none());
    }

    #[test]
    fn withdraw_parses_correctly() {
        let mut data = [0u8; 489];
        data[0] = 3;
        for i in 1..489 { data[i] = (i % 251) as u8; }
        let expected_amount = u64::from_le_bytes(data[481..489].try_into().unwrap());
        match LaurelinInstruction::try_from_bytes(&data).unwrap() {
            LaurelinInstruction::Withdraw { proof, commitment, commit_hash, new_c1, new_c2, amount } => {
                assert_eq!(&proof.a[..],    &data[1..65]);
                assert_eq!(&proof.b[..],    &data[65..193]);
                assert_eq!(&proof.c[..],    &data[193..257]);
                assert_eq!(&commitment[..], &data[257..321]);
                assert_eq!(&commit_hash[..],&data[321..353]);
                assert_eq!(&new_c1[..],     &data[353..417]);
                assert_eq!(&new_c2[..],     &data[417..481]);
                assert_eq!(amount, expected_amount);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn withdraw_too_short_returns_none() {
        let mut data = [0u8; 488];
        data[0] = 3;
        assert!(LaurelinInstruction::try_from_bytes(&data).is_none());
    }
}
