#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
extern crate alloc;
#[cfg(not(test))]
use alloc::format;

pub mod bn254;
pub mod groth16;
pub mod instruction;
pub mod state;

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    program::invoke_signed,
    sysvar::Sysvar,
};

use groth16::{verify, VerificationKey};
use instruction::LaurelinInstruction;
use state::{AccountState, G1Point};

#[cfg(not(test))]
use solana_program::entrypoint;
#[cfg(not(test))]
entrypoint!(process_instruction);

// BN254 G1 generator
pub const G1_X: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 1;
    b
};
pub const G1_Y: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 2;
    b
};
pub const GENERATOR: G1Point = {
    let mut g = [0u8; 64];
    let mut i = 0;
    while i < 32 { g[i] = G1_X[i]; i += 1; }
    let mut i = 0;
    while i < 32 { g[32 + i] = G1_Y[i]; i += 1; }
    g
};

include!("vk_generated.rs");

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let ix = LaurelinInstruction::try_from_bytes(instruction_data)
        .ok_or(ProgramError::InvalidInstructionData)?;

    match ix {
        LaurelinInstruction::CreateAccount { pubkey, c1, c2 } => {
            process_create_account(program_id, accounts, pubkey, c1, c2)
        }
        LaurelinInstruction::RingTransfer {
            proof,
            commitment,
            commit_hash,
            sender_new_c1,
            sender_new_c2,
            recv_delta_c1,
            recv_delta_c2,
        } => process_ring_transfer(
            program_id,
            accounts,
            proof,
            commitment,
            commit_hash,
            sender_new_c1,
            sender_new_c2,
            recv_delta_c1,
            recv_delta_c2,
        ),
    }
}

fn process_create_account(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    pubkey: G1Point,
    c1: G1Point,
    c2: G1Point,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let payer = &accounts[0];
    let pda = &accounts[1];
    let system_program = &accounts[2];

    // PDA seed: first 32 bytes of the account's pubkey (the x coordinate)
    let seed = &pubkey[0..32];
    let (expected_pda, bump) =
        Pubkey::find_program_address(&[seed], program_id);

    if pda.key != &expected_pda {
        msg!("PDA mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(AccountState::LEN);

    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            pda.key,
            lamports,
            AccountState::LEN as u64,
            program_id,
        ),
        &[payer.clone(), pda.clone(), system_program.clone()],
        &[&[seed, &[bump]]],
    )?;

    let state = AccountState { pubkey, c1, c2 };
    state.write_to(&mut pda.data.borrow_mut());
    Ok(())
}

/// 2+2 ring transfer: 2 senders, 2 receivers.
///
/// accounts: [senderPDA0 (write), senderPDA1 (write),
///            recvPDA0   (write), recvPDA1   (write)]
fn process_ring_transfer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    proof: state::Groth16Proof,
    commitment: G1Point,
    commit_hash: state::Scalar,
    sender_new_c1: [G1Point; 2],
    sender_new_c2: [G1Point; 2],
    recv_delta_c1: [G1Point; 2],
    recv_delta_c2: [G1Point; 2],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let sender_pda = [&accounts[0], &accounts[1]];
    let recv_pda   = [&accounts[2], &accounts[3]];

    for pda in sender_pda.iter().chain(recv_pda.iter()) {
        if pda.owner != program_id {
            return Err(ProgramError::IncorrectProgramId);
        }
    }

    let sender_state = [
        AccountState::try_from_bytes(&sender_pda[0].data.borrow())
            .ok_or(ProgramError::InvalidAccountData)?,
        AccountState::try_from_bytes(&sender_pda[1].data.borrow())
            .ok_or(ProgramError::InvalidAccountData)?,
    ];
    let recv_state = [
        AccountState::try_from_bytes(&recv_pda[0].data.borrow())
            .ok_or(ProgramError::InvalidAccountData)?,
        AccountState::try_from_bytes(&recv_pda[1].data.borrow())
            .ok_or(ProgramError::InvalidAccountData)?,
    ];

    let public_inputs = build_ring_public_inputs(
        &sender_state,
        &recv_state,
        &sender_new_c1,
        &sender_new_c2,
        &recv_delta_c1,
        &recv_delta_c2,
        &commit_hash,
    );

    let ok = verify(&REAL_VK, &proof, &public_inputs, &commitment)
        .map_err(|_| ProgramError::InvalidArgument)?;
    if !ok {
        msg!("balance proof invalid");
        return Err(ProgramError::InvalidArgument);
    }

    // Update sender ciphertexts (both ring members)
    for i in 0..2 {
        let mut data = sender_pda[i].data.borrow_mut();
        data[64..128].copy_from_slice(&sender_new_c1[i]);
        data[128..192].copy_from_slice(&sender_new_c2[i]);
    }

    // Update receiver ciphertexts homomorphically (add delta to each)
    for i in 0..2 {
        let new_c1 = bn254::g1_add(&recv_state[i].c1, &recv_delta_c1[i])
            .map_err(|_| ProgramError::InvalidArgument)?;
        let new_c2 = bn254::g1_add(&recv_state[i].c2, &recv_delta_c2[i])
            .map_err(|_| ProgramError::InvalidArgument)?;
        let mut data = recv_pda[i].data.borrow_mut();
        data[64..128].copy_from_slice(&new_c1);
        data[128..192].copy_from_slice(&new_c2);
    }

    msg!("ring transfer complete");
    Ok(())
}

/// Build the 129 public inputs for the ring Groth16 proof.
///
/// Points in circuit struct declaration order (16 G1 points × 8 scalars = 128):
///   SenderPk0,  SenderPk1
///   SenderOldC10, SenderOldC11
///   SenderOldC20, SenderOldC21
///   SenderNewC10, SenderNewC11
///   SenderNewC20, SenderNewC21
///   RecvPk0,    RecvPk1
///   RecvDeltaC10, RecvDeltaC20
///   RecvDeltaC11, RecvDeltaC21
/// Plus commit_hash at index 128 → IC[129].
/// Total: 129 inputs, IC.len() = 130.
fn build_ring_public_inputs(
    sender_state: &[AccountState; 2],
    recv_state:   &[AccountState; 2],
    sender_new_c1: &[G1Point; 2],
    sender_new_c2: &[G1Point; 2],
    recv_delta_c1: &[G1Point; 2],
    recv_delta_c2: &[G1Point; 2],
    commit_hash: &state::Scalar,
) -> alloc::vec::Vec<state::Scalar> {
    let mut inputs = alloc::vec::Vec::with_capacity(129);

    let points: [&G1Point; 16] = [
        &sender_state[0].pubkey, &sender_state[1].pubkey,
        &sender_state[0].c1,     &sender_state[1].c1,
        &sender_state[0].c2,     &sender_state[1].c2,
        &sender_new_c1[0],       &sender_new_c1[1],
        &sender_new_c2[0],       &sender_new_c2[1],
        &recv_state[0].pubkey,   &recv_state[1].pubkey,
        &recv_delta_c1[0],       &recv_delta_c2[0],
        &recv_delta_c1[1],       &recv_delta_c2[1],
    ];

    for point in &points {
        for coord_off in [0usize, 32] {
            let coord = &point[coord_off..coord_off + 32];
            for limb_idx in 0..4 {
                let byte_off = 24 - limb_idx * 8;
                let mut limb = [0u8; 32];
                limb[24..32].copy_from_slice(&coord[byte_off..byte_off + 8]);
                inputs.push(limb);
            }
        }
    }
    inputs.push(*commit_hash);
    inputs
}
