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
    /// data layout (768 byte payload, 769 bytes total):
    ///   proof (256)
    ///   || sender_new_c1[0] (64) || sender_new_c2[0] (64)
    ///   || sender_new_c1[1] (64) || sender_new_c2[1] (64)
    ///   || recv_delta_c1[0] (64) || recv_delta_c2[0] (64)
    ///   || recv_delta_c1[1] (64) || recv_delta_c2[1] (64)
    ///
    /// accounts: [senderPDA0 (write), senderPDA1 (write),
    ///            recvPDA0   (write), recvPDA1   (write)]
    RingTransfer {
        proof: Groth16Proof,
        /// New sender ciphertexts (both ring members updated)
        sender_new_c1: [G1Point; 2],
        sender_new_c2: [G1Point; 2],
        /// Receiver deltas (slot i added to recvPDA[i])
        recv_delta_c1: [G1Point; 2],
        recv_delta_c2: [G1Point; 2],
    },

    /// opcode 2 — deposit lamports with Groth16 delta proof
    ///
    /// data layout (392 byte payload, 393 bytes total):
    ///   proof (256) || delta_c1 (64) || delta_c2 (64) || amount (8, u64 LE)
    ///
    /// accounts: [payer (write, signer), pda (write), vault_pda (write), system_program]
    Deposit {
        proof: Groth16Proof,
        delta_c1: G1Point,
        delta_c2: G1Point,
        amount: u64,
    },

    /// opcode 3 — withdraw lamports with Groth16 balance proof
    ///
    /// data layout (392 byte payload, 393 bytes total):
    ///   proof (256) || new_c1 (64) || new_c2 (64) || amount (8, u64 LE)
    ///
    /// accounts: [pda (write), vault_pda (write), destination (write)]
    Withdraw {
        proof: Groth16Proof,
        new_c1: G1Point,
        new_c2: G1Point,
        amount: u64,
    },
}

/// Parse a CreateAccount payload (no opcode byte): pubkey(64) || c1(64) || c2(64)
pub fn parse_create_account(data: &[u8]) -> Option<LaurelinInstruction> {
    if data.len() < 192 {
        return None;
    }
    let mut pubkey = [0u8; 64];
    let mut c1 = [0u8; 64];
    let mut c2 = [0u8; 64];
    pubkey.copy_from_slice(&data[0..64]);
    c1.copy_from_slice(&data[64..128]);
    c2.copy_from_slice(&data[128..192]);
    Some(LaurelinInstruction::CreateAccount { pubkey, c1, c2 })
}

/// Parse a RingTransfer payload (no opcode byte):
/// proof(256) || 8×G1(512)  = 768 bytes
pub fn parse_ring_transfer(data: &[u8]) -> Option<LaurelinInstruction> {
    if data.len() < 768 {
        return None;
    }
    let proof = Groth16Proof::try_from_bytes(&data[0..256])?;
    let mut sender_new_c1 = [[0u8; 64]; 2];
    let mut sender_new_c2 = [[0u8; 64]; 2];
    let mut recv_delta_c1 = [[0u8; 64]; 2];
    let mut recv_delta_c2 = [[0u8; 64]; 2];
    let off = 256;
    sender_new_c1[0].copy_from_slice(&data[off..off + 64]);
    sender_new_c2[0].copy_from_slice(&data[off + 64..off + 128]);
    sender_new_c1[1].copy_from_slice(&data[off + 128..off + 192]);
    sender_new_c2[1].copy_from_slice(&data[off + 192..off + 256]);
    recv_delta_c1[0].copy_from_slice(&data[off + 256..off + 320]);
    recv_delta_c2[0].copy_from_slice(&data[off + 320..off + 384]);
    recv_delta_c1[1].copy_from_slice(&data[off + 384..off + 448]);
    recv_delta_c2[1].copy_from_slice(&data[off + 448..off + 512]);
    Some(LaurelinInstruction::RingTransfer {
        proof,
        sender_new_c1,
        sender_new_c2,
        recv_delta_c1,
        recv_delta_c2,
    })
}

/// Parse a Deposit payload (no opcode byte):
/// proof(256) || delta_c1(64) || delta_c2(64) || amount(8)  = 392 bytes
pub fn parse_deposit(data: &[u8]) -> Option<LaurelinInstruction> {
    if data.len() < 392 {
        return None;
    }
    let proof = Groth16Proof::try_from_bytes(&data[0..256])?;
    let mut delta_c1 = [0u8; 64];
    let mut delta_c2 = [0u8; 64];
    delta_c1.copy_from_slice(&data[256..320]);
    delta_c2.copy_from_slice(&data[320..384]);
    let amount = u64::from_le_bytes(data[384..392].try_into().ok()?);
    Some(LaurelinInstruction::Deposit {
        proof,
        delta_c1,
        delta_c2,
        amount,
    })
}

/// Parse a Withdraw payload (no opcode byte):
/// proof(256) || new_c1(64) || new_c2(64) || amount(8)  = 392 bytes
pub fn parse_withdraw(data: &[u8]) -> Option<LaurelinInstruction> {
    if data.len() < 392 {
        return None;
    }
    let proof = Groth16Proof::try_from_bytes(&data[0..256])?;
    let mut new_c1 = [0u8; 64];
    let mut new_c2 = [0u8; 64];
    new_c1.copy_from_slice(&data[256..320]);
    new_c2.copy_from_slice(&data[320..384]);
    let amount = u64::from_le_bytes(data[384..392].try_into().ok()?);
    Some(LaurelinInstruction::Withdraw {
        proof,
        new_c1,
        new_c2,
        amount,
    })
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
        for i in 1..193 {
            data[i] = i as u8;
        }
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
        let mut data = [0u8; 192];
        data[0] = 0;
        assert!(LaurelinInstruction::try_from_bytes(&data).is_none());
    }

    #[test]
    fn ring_transfer_parses_correctly() {
        // opcode(1) + proof(256) + 8*G1(512) = 769 bytes
        let mut data = [0u8; 769];
        data[0] = 1;
        for i in 1..769 {
            data[i] = (i % 251) as u8;
        }
        match LaurelinInstruction::try_from_bytes(&data).unwrap() {
            LaurelinInstruction::RingTransfer {
                proof,
                sender_new_c1,
                sender_new_c2,
                recv_delta_c1,
                recv_delta_c2,
            } => {
                assert_eq!(&proof.a[..], &data[1..65]);
                assert_eq!(&proof.b[..], &data[65..193]);
                assert_eq!(&proof.c[..], &data[193..257]);
                // ciphertexts start at offset 257 (1 + 256)
                assert_eq!(&sender_new_c1[0][..], &data[257..321]);
                assert_eq!(&sender_new_c2[0][..], &data[321..385]);
                assert_eq!(&sender_new_c1[1][..], &data[385..449]);
                assert_eq!(&sender_new_c2[1][..], &data[449..513]);
                assert_eq!(&recv_delta_c1[0][..], &data[513..577]);
                assert_eq!(&recv_delta_c2[0][..], &data[577..641]);
                assert_eq!(&recv_delta_c1[1][..], &data[641..705]);
                assert_eq!(&recv_delta_c2[1][..], &data[705..769]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn ring_transfer_too_short_returns_none() {
        let mut data = [0u8; 768];
        data[0] = 1;
        assert!(LaurelinInstruction::try_from_bytes(&data).is_none());
    }

    #[test]
    fn deposit_parses_correctly() {
        // opcode(1) + proof(256) + c1(64) + c2(64) + amount(8) = 393 bytes
        let mut data = [0u8; 393];
        data[0] = 2;
        for i in 1..393 {
            data[i] = (i % 251) as u8;
        }
        let expected_amount = u64::from_le_bytes(data[385..393].try_into().unwrap());
        match LaurelinInstruction::try_from_bytes(&data).unwrap() {
            LaurelinInstruction::Deposit {
                proof,
                delta_c1,
                delta_c2,
                amount,
            } => {
                assert_eq!(&proof.a[..], &data[1..65]);
                assert_eq!(&proof.b[..], &data[65..193]);
                assert_eq!(&proof.c[..], &data[193..257]);
                assert_eq!(&delta_c1[..], &data[257..321]);
                assert_eq!(&delta_c2[..], &data[321..385]);
                assert_eq!(amount, expected_amount);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn deposit_too_short_returns_none() {
        let mut data = [0u8; 392];
        data[0] = 2;
        assert!(LaurelinInstruction::try_from_bytes(&data).is_none());
    }

    #[test]
    fn withdraw_parses_correctly() {
        let mut data = [0u8; 393];
        data[0] = 3;
        for i in 1..393 {
            data[i] = (i % 251) as u8;
        }
        let expected_amount = u64::from_le_bytes(data[385..393].try_into().unwrap());
        match LaurelinInstruction::try_from_bytes(&data).unwrap() {
            LaurelinInstruction::Withdraw {
                proof,
                new_c1,
                new_c2,
                amount,
            } => {
                assert_eq!(&proof.a[..], &data[1..65]);
                assert_eq!(&proof.b[..], &data[65..193]);
                assert_eq!(&proof.c[..], &data[193..257]);
                assert_eq!(&new_c1[..], &data[257..321]);
                assert_eq!(&new_c2[..], &data[321..385]);
                assert_eq!(amount, expected_amount);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn withdraw_too_short_returns_none() {
        let mut data = [0u8; 392];
        data[0] = 3;
        assert!(LaurelinInstruction::try_from_bytes(&data).is_none());
    }
}
