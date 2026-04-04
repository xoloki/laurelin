//! Laurelin on-chain instruction builders.
//!
//! Byte layouts match the Go client and on-chain program exactly.

use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program,
};

use crate::prover::ProofBytes;

// ── Compute budget ────────────────────────────────────────────────────────────

/// SetComputeUnitLimit instruction (opcode 2).
pub fn set_compute_unit_limit(units: u32) -> Instruction {
    let program_id: Pubkey = "ComputeBudget111111111111111111111111111111"
        .parse()
        .unwrap();
    let data = vec![
        2u8,
        units as u8,
        (units >> 8) as u8,
        (units >> 16) as u8,
        (units >> 24) as u8,
    ];
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

// ── Proof block serialisation ─────────────────────────────────────────────────

/// Serialise ProofBytes into the standard 256-byte block:
/// proofA(64) || proofB(128) || proofC(64)
fn proof_block(proof: &ProofBytes) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&proof.proof_a);
    out.extend_from_slice(&proof.proof_b);
    out.extend_from_slice(&proof.proof_c);
    out
}

// ── Instruction builders ──────────────────────────────────────────────────────

/// opcode 0x00: CreateAccount
/// data: 0x00 || pubkey(64) || c1(64) || c2(64) = 193 bytes
pub fn create_account(
    program_id: &Pubkey,
    payer: &Pubkey,
    pda: &Pubkey,
    bn254_pk: &[u8; 64],
    c1: &[u8; 64],
    c2: &[u8; 64],
) -> Instruction {
    let mut data = Vec::with_capacity(193);
    data.push(0x00);
    data.extend_from_slice(bn254_pk);
    data.extend_from_slice(c1);
    data.extend_from_slice(c2);
    debug_assert_eq!(data.len(), 193);

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*pda, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

/// opcode 0x02: Deposit
/// data: 0x02 || proof(256) || deltaC1(64) || deltaC2(64) || amount(8 LE) = 393 bytes
pub fn deposit(
    program_id: &Pubkey,
    payer: &Pubkey,
    pda: &Pubkey,
    vault: &Pubkey,
    proof: &ProofBytes,
    delta_c1: &[u8; 64],
    delta_c2: &[u8; 64],
    amount: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(393);
    data.push(0x02);
    data.extend_from_slice(&proof_block(proof));
    data.extend_from_slice(delta_c1);
    data.extend_from_slice(delta_c2);
    data.extend_from_slice(&amount.to_le_bytes());
    debug_assert_eq!(data.len(), 393);

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*pda, false),
            AccountMeta::new(*vault, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

/// opcode 0x01: RingTransfer
/// data: 0x01 || proof(256)
///     || senderNewC1[0](64) || senderNewC2[0](64)
///     || senderNewC1[1](64) || senderNewC2[1](64)
///     || recvDeltaC1[0](64) || recvDeltaC2[0](64)
///     || recvDeltaC1[1](64) || recvDeltaC2[1](64)
/// = 769 bytes
#[allow(clippy::too_many_arguments)]
pub fn ring_transfer(
    program_id: &Pubkey,
    sender_pda_0: &Pubkey,
    sender_pda_1: &Pubkey,
    recv_pda_0: &Pubkey,
    recv_pda_1: &Pubkey,
    proof: &ProofBytes,
    sender_new_c1_0: &[u8; 64],
    sender_new_c2_0: &[u8; 64],
    sender_new_c1_1: &[u8; 64],
    sender_new_c2_1: &[u8; 64],
    recv_delta_c1_0: &[u8; 64],
    recv_delta_c2_0: &[u8; 64],
    recv_delta_c1_1: &[u8; 64],
    recv_delta_c2_1: &[u8; 64],
) -> Instruction {
    let mut data = Vec::with_capacity(769);
    data.push(0x01);
    data.extend_from_slice(&proof_block(proof));
    data.extend_from_slice(sender_new_c1_0);
    data.extend_from_slice(sender_new_c2_0);
    data.extend_from_slice(sender_new_c1_1);
    data.extend_from_slice(sender_new_c2_1);
    data.extend_from_slice(recv_delta_c1_0);
    data.extend_from_slice(recv_delta_c2_0);
    data.extend_from_slice(recv_delta_c1_1);
    data.extend_from_slice(recv_delta_c2_1);
    debug_assert_eq!(data.len(), 769);

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*sender_pda_0, false),
            AccountMeta::new(*sender_pda_1, false),
            AccountMeta::new(*recv_pda_0, false),
            AccountMeta::new(*recv_pda_1, false),
        ],
        data,
    }
}

/// opcode 0x03: Withdraw
/// data: 0x03 || proof(256) || newC1(64) || newC2(64) || amount(8 LE) = 393 bytes
pub fn withdraw(
    program_id: &Pubkey,
    pda: &Pubkey,
    vault: &Pubkey,
    destination: &Pubkey,
    proof: &ProofBytes,
    new_c1: &[u8; 64],
    new_c2: &[u8; 64],
    amount: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(393);
    data.push(0x03);
    data.extend_from_slice(&proof_block(proof));
    data.extend_from_slice(new_c1);
    data.extend_from_slice(new_c2);
    data.extend_from_slice(&amount.to_le_bytes());
    debug_assert_eq!(data.len(), 393);

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*pda, false),
            AccountMeta::new(*vault, false),
            AccountMeta::new(*destination, false),
        ],
        data,
    }
}

/// Derive the vault PDA: seed = b"vault".
pub fn vault_pda(program_id: &Pubkey) -> Pubkey {
    let (pda, _) = Pubkey::find_program_address(&[b"vault"], program_id);
    pda
}
