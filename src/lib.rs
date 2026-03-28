#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
extern crate alloc;
#[cfg(not(test))]
use alloc::format;
#[cfg(not(test))]
use alloc::vec::Vec;
#[cfg(test)]
use std::vec::Vec;

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
    program::{invoke, invoke_signed},
    sysvar::Sysvar,
};

use groth16::{verify, VerificationKey};
use instruction::{parse_create_account, parse_deposit, parse_ring_transfer, parse_withdraw, LaurelinInstruction};
use state::{AccountState, G1Point};

#[cfg(not(test))]
use solana_program::entrypoint;
#[cfg(not(test))]
entrypoint!(process_instruction);

pub const VAULT_SEED: &[u8] = b"vault";

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

#[cfg(not(test))]
include!("transfer_vk_generated.rs");
#[cfg(not(test))]
include!("deposit_vk_generated.rs");
#[cfg(not(test))]
include!("withdraw_vk_generated.rs");

#[cfg(test)]
static TRANSFER_VK: VerificationKey = VerificationKey {
    alpha: [0u8; 64],
    beta:  [0u8; 128],
    gamma: [0u8; 128],
    delta: [0u8; 128],
    ic:    &[],
};
#[cfg(test)]
static DEPOSIT_VK: VerificationKey = VerificationKey {
    alpha: [0u8; 64],
    beta:  [0u8; 128],
    gamma: [0u8; 128],
    delta: [0u8; 128],
    ic:    &[],
};
#[cfg(test)]
static WITHDRAW_VK: VerificationKey = VerificationKey {
    alpha: [0u8; 64],
    beta:  [0u8; 128],
    gamma: [0u8; 128],
    delta: [0u8; 128],
    ic:    &[],
};

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (&opcode, rest) = instruction_data.split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match opcode {
        0 => process_create_account(program_id, accounts, rest),
        1 => process_ring_transfer(program_id, accounts, rest),
        2 => process_deposit(program_id, accounts, rest),
        3 => process_withdraw(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_create_account(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let LaurelinInstruction::CreateAccount { pubkey, c1, c2 } =
        parse_create_account(data).ok_or(ProgramError::InvalidInstructionData)?
    else { return Err(ProgramError::InvalidInstructionData) };
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
    data: &[u8],
) -> ProgramResult {
    let LaurelinInstruction::RingTransfer { proof, commitment, commit_hash, sender_new_c1, sender_new_c2, recv_delta_c1, recv_delta_c2 } =
        parse_ring_transfer(data).ok_or(ProgramError::InvalidInstructionData)?
    else { return Err(ProgramError::InvalidInstructionData) };
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

    let ok = verify(&TRANSFER_VK, &proof, &public_inputs, &commitment)
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

/// Deposit: proves the delta ciphertext correctly encrypts the deposit amount
/// under the account's public key, then transfers lamports into the vault.
/// The vault PDA is created on first deposit if it does not yet exist.
///
/// accounts: [payer (write, signer), pda (write), vault_pda (write), system_program]
fn process_deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let LaurelinInstruction::Deposit { proof, commitment, commit_hash, delta_c1, delta_c2, amount } =
        parse_deposit(data).ok_or(ProgramError::InvalidInstructionData)?
    else { return Err(ProgramError::InvalidInstructionData) };
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let payer          = &accounts[0];
    let pda            = &accounts[1];
    let vault_pda      = &accounts[2];
    let system_program = &accounts[3];

    if pda.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (expected_vault, bump) = Pubkey::find_program_address(&[VAULT_SEED], program_id);
    if vault_pda.key != &expected_vault {
        msg!("vault PDA mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    let state = AccountState::try_from_bytes(&pda.data.borrow())
        .ok_or(ProgramError::InvalidAccountData)?;

    let public_inputs = build_deposit_public_inputs(
        &state.pubkey, &delta_c1, &delta_c2, amount, &commit_hash,
    );

    let ok = verify(&DEPOSIT_VK, &proof, &public_inputs, &commitment)
        .map_err(|_| ProgramError::InvalidArgument)?;
    if !ok {
        msg!("deposit proof invalid");
        return Err(ProgramError::InvalidArgument);
    }

    // Lazily create the vault on first deposit.
    if vault_pda.lamports() == 0 {
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(0);
        invoke_signed(
            &system_instruction::create_account(payer.key, vault_pda.key, lamports, 0, program_id),
            &[payer.clone(), vault_pda.clone(), system_program.clone()],
            &[&[VAULT_SEED, &[bump]]],
        )?;
    }

    invoke(
        &system_instruction::transfer(payer.key, vault_pda.key, amount),
        &[payer.clone(), vault_pda.clone(), system_program.clone()],
    )?;

    let new_c1 = bn254::g1_add(&state.c1, &delta_c1)
        .map_err(|_| ProgramError::InvalidArgument)?;
    let new_c2 = bn254::g1_add(&state.c2, &delta_c2)
        .map_err(|_| ProgramError::InvalidArgument)?;

    let mut data = pda.data.borrow_mut();
    data[64..128].copy_from_slice(&new_c1);
    data[128..192].copy_from_slice(&new_c2);

    msg!("deposit complete");
    Ok(())
}

/// Build the 26 public inputs for the deposit Groth16 proof.
///
/// Points in DepositCircuit declaration order (3 G1 points × 8 scalars = 24):
///   Pk, DeltaC1, DeltaC2
/// Plus Amount scalar at index 24, commit_hash at index 25.
/// Total: 26 inputs, IC.len() = 27.
fn build_deposit_public_inputs(
    pk: &G1Point,
    delta_c1: &G1Point,
    delta_c2: &G1Point,
    amount: u64,
    commit_hash: &state::Scalar,
) -> Vec<state::Scalar> {
    let mut inputs = Vec::with_capacity(26);

    let points: [&G1Point; 3] = [pk, delta_c1, delta_c2];

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

    let mut amount_scalar = [0u8; 32];
    amount_scalar[24..32].copy_from_slice(&amount.to_be_bytes());
    inputs.push(amount_scalar);

    inputs.push(*commit_hash);
    inputs
}

/// Withdraw: proves knowledge of sk and that new ciphertext correctly encrypts
/// old_balance − amount. Lamports are paid from the shared vault.
///
/// accounts: [pda (write), vault_pda (write), destination (write)]
fn process_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let LaurelinInstruction::Withdraw { proof, commitment, commit_hash, new_c1, new_c2, amount } =
        parse_withdraw(data).ok_or(ProgramError::InvalidInstructionData)?
    else { return Err(ProgramError::InvalidInstructionData) };
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let pda         = &accounts[0];
    let vault_pda   = &accounts[1];
    let destination = &accounts[2];

    if pda.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (expected_vault, _) = Pubkey::find_program_address(&[VAULT_SEED], program_id);
    if vault_pda.key != &expected_vault {
        msg!("vault PDA mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    let state = AccountState::try_from_bytes(&pda.data.borrow())
        .ok_or(ProgramError::InvalidAccountData)?;

    let public_inputs = build_withdraw_public_inputs(
        &state, &new_c1, &new_c2, amount, &commit_hash,
    );

    let ok = verify(&WITHDRAW_VK, &proof, &public_inputs, &commitment)
        .map_err(|_| ProgramError::InvalidArgument)?;
    if !ok {
        msg!("withdraw proof invalid");
        return Err(ProgramError::InvalidArgument);
    }

    // Keep the vault above its rent-exempt minimum (0-data account).
    let rent = Rent::get()?;
    let rent_exempt = rent.minimum_balance(0);
    let available = vault_pda.lamports().saturating_sub(rent_exempt);
    if available < amount {
        msg!("insufficient vault balance");
        return Err(ProgramError::InsufficientFunds);
    }

    **vault_pda.lamports.borrow_mut()   -= amount;
    **destination.lamports.borrow_mut() += amount;

    let mut data = pda.data.borrow_mut();
    data[64..128].copy_from_slice(&new_c1);
    data[128..192].copy_from_slice(&new_c2);

    msg!("withdraw complete");
    Ok(())
}

/// Build the 42 public inputs for the withdraw Groth16 proof.
///
/// Points in WithdrawCircuit declaration order (5 G1 points × 8 scalars = 40):
///   Pk, OldC1, OldC2, NewC1, NewC2
/// Plus Amount scalar at index 40, commit_hash at index 41.
/// Total: 42 inputs, IC.len() = 43.
fn build_withdraw_public_inputs(
    state: &AccountState,
    new_c1: &G1Point,
    new_c2: &G1Point,
    amount: u64,
    commit_hash: &state::Scalar,
) -> Vec<state::Scalar> {
    let mut inputs = Vec::with_capacity(42);

    let points: [&G1Point; 5] = [
        &state.pubkey,
        &state.c1,
        &state.c2,
        new_c1,
        new_c2,
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

    // Amount as a native field element (big-endian u64 in a 32-byte scalar)
    let mut amount_scalar = [0u8; 32];
    amount_scalar[24..32].copy_from_slice(&amount.to_be_bytes());
    inputs.push(amount_scalar);

    inputs.push(*commit_hash);
    inputs
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
) -> Vec<state::Scalar> {
    let mut inputs = Vec::with_capacity(129);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_point(x_lsb: u8) -> state::G1Point {
        let mut p = [0u8; 64];
        p[31] = x_lsb;
        p
    }

    fn make_state(pk: u8, c1: u8, c2: u8) -> state::AccountState {
        state::AccountState { pubkey: make_point(pk), c1: make_point(c1), c2: make_point(c2) }
    }

    #[test]
    fn deposit_public_inputs_count() {
        let z = [0u8; 64];
        let inputs = build_deposit_public_inputs(&z, &z, &z, 400, &[0u8; 32]);
        assert_eq!(inputs.len(), 26);
    }

    #[test]
    fn deposit_commit_hash_is_last() {
        let z = [0u8; 64];
        let mut commit_hash = [0u8; 32];
        commit_hash[31] = 0xAB;
        let inputs = build_deposit_public_inputs(&z, &z, &z, 400, &commit_hash);
        assert_eq!(inputs[25], commit_hash);
    }

    #[test]
    fn deposit_amount_scalar_position() {
        let z = [0u8; 64];
        let inputs = build_deposit_public_inputs(&z, &z, &z, 400, &[0u8; 32]);
        let mut expected = [0u8; 32];
        expected[24..32].copy_from_slice(&400u64.to_be_bytes());
        assert_eq!(inputs[24], expected);
    }

    #[test]
    fn withdraw_public_inputs_count() {
        let z = [0u8; 64];
        let state = make_state(0, 0, 0);
        let inputs = build_withdraw_public_inputs(&state, &z, &z, 400, &[0u8; 32]);
        assert_eq!(inputs.len(), 42);
    }

    #[test]
    fn withdraw_commit_hash_is_last() {
        let z = [0u8; 64];
        let state = make_state(0, 0, 0);
        let mut commit_hash = [0u8; 32];
        commit_hash[31] = 0xAB;
        let inputs = build_withdraw_public_inputs(&state, &z, &z, 400, &commit_hash);
        assert_eq!(inputs[41], commit_hash);
    }

    #[test]
    fn withdraw_amount_scalar_position() {
        let z = [0u8; 64];
        let state = make_state(0, 0, 0);
        let inputs = build_withdraw_public_inputs(&state, &z, &z, 400, &[0u8; 32]);
        // 400 = 0x190; stored big-endian in [24..32]
        let mut expected = [0u8; 32];
        expected[24..32].copy_from_slice(&400u64.to_be_bytes());
        assert_eq!(inputs[40], expected);
    }

    #[test]
    fn public_inputs_count() {
        let z = [0u8; 64];
        let sender = [make_state(0, 0, 0), make_state(0, 0, 0)];
        let recv   = [make_state(0, 0, 0), make_state(0, 0, 0)];
        let inputs = build_ring_public_inputs(
            &sender, &recv, &[z; 2], &[z; 2], &[z; 2], &[z; 2], &[0u8; 32],
        );
        assert_eq!(inputs.len(), 129);
    }

    #[test]
    fn commit_hash_is_last() {
        let z = [0u8; 64];
        let sender = [make_state(0, 0, 0), make_state(0, 0, 0)];
        let recv   = [make_state(0, 0, 0), make_state(0, 0, 0)];
        let mut commit_hash = [0u8; 32];
        commit_hash[31] = 0xAB;
        let inputs = build_ring_public_inputs(
            &sender, &recv, &[z; 2], &[z; 2], &[z; 2], &[z; 2], &commit_hash,
        );
        assert_eq!(inputs[128], commit_hash);
    }

    // A coordinate with only byte[31] set maps to limb 0 (byte_off = 24).
    #[test]
    fn limb_decomposition_lsb() {
        let z = [0u8; 64];
        let mut pk = [0u8; 64];
        pk[31] = 0xAB;
        let sender = [
            state::AccountState { pubkey: pk, c1: z, c2: z },
            make_state(0, 0, 0),
        ];
        let recv = [make_state(0, 0, 0), make_state(0, 0, 0)];
        let inputs = build_ring_public_inputs(
            &sender, &recv, &[z; 2], &[z; 2], &[z; 2], &[z; 2], &[0u8; 32],
        );
        // sender_state[0].pubkey = point index 0 → scalar index 0 = limb 0 of X
        assert_eq!(inputs[0][31], 0xAB, "LSB should be in limb 0");
        assert_eq!(inputs[1], [0u8; 32], "limb 1 should be zero");
        assert_eq!(inputs[2], [0u8; 32], "limb 2 should be zero");
        assert_eq!(inputs[3], [0u8; 32], "limb 3 should be zero");
    }

    // A coordinate with only byte[0] set maps to limb 3 (byte_off = 0), at position [24].
    #[test]
    fn limb_decomposition_msb() {
        let z = [0u8; 64];
        let mut pk = [0u8; 64];
        pk[0] = 0xCD; // most significant byte
        let sender = [
            state::AccountState { pubkey: pk, c1: z, c2: z },
            make_state(0, 0, 0),
        ];
        let recv = [make_state(0, 0, 0), make_state(0, 0, 0)];
        let inputs = build_ring_public_inputs(
            &sender, &recv, &[z; 2], &[z; 2], &[z; 2], &[z; 2], &[0u8; 32],
        );
        assert_eq!(inputs[3][24], 0xCD, "MSB should be in limb 3 at byte [24]");
        assert_eq!(inputs[0], [0u8; 32], "limb 0 should be zero");
        assert_eq!(inputs[1], [0u8; 32], "limb 1 should be zero");
        assert_eq!(inputs[2], [0u8; 32], "limb 2 should be zero");
    }

    // Verify the 16 G1 points appear in declaration order.
    // Point order: sender_pk[0,1], sender_old_c1[0,1], sender_old_c2[0,1],
    //              sender_new_c1[0,1], sender_new_c2[0,1], recv_pk[0,1],
    //              recv_delta_c1[0], recv_delta_c2[0], recv_delta_c1[1], recv_delta_c2[1]
    #[test]
    fn point_ordering() {
        let z = [0u8; 64];
        // Give each of the 16 points a unique marker in X[31]
        let mut pts = [[0u8; 64]; 16];
        for i in 0..16usize { pts[i][31] = (i + 1) as u8; }

        let sender = [
            state::AccountState { pubkey: pts[0], c1: pts[2], c2: pts[4] },
            state::AccountState { pubkey: pts[1], c1: pts[3], c2: pts[5] },
        ];
        let recv = [
            state::AccountState { pubkey: pts[10], c1: z, c2: z },
            state::AccountState { pubkey: pts[11], c1: z, c2: z },
        ];
        let inputs = build_ring_public_inputs(
            &sender, &recv,
            &[pts[6], pts[7]], &[pts[8], pts[9]],
            &[pts[12], pts[14]], &[pts[13], pts[15]],
            &[0u8; 32],
        );
        // Each point i contributes 8 scalars; limb 0 of X is at inputs[i*8]
        for i in 0..16usize {
            assert_eq!(
                inputs[i * 8][31], (i + 1) as u8,
                "point {} should have marker {} at limb 0 of X", i, i + 1
            );
        }
    }
}
