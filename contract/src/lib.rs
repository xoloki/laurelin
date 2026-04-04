#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
extern crate alloc;
#[cfg(not(test))]
use alloc::format;
#[cfg(not(test))]
use alloc::vec::Vec;
#[cfg(test)]
use std::vec::Vec;

pub mod bjj;
pub mod bn254;
pub mod groth16;
pub mod instruction;
pub mod state;

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

use groth16::{verify, VerificationKey};
use instruction::{
    parse_create_account, parse_deposit, parse_ring_transfer, parse_withdraw, LaurelinInstruction,
};
use state::{AccountState, G1Point};

#[cfg(not(test))]
use solana_program::entrypoint;
#[cfg(not(test))]
entrypoint!(process_instruction);

pub const VAULT_SEED: &[u8] = b"vault";

#[cfg(not(test))]
include!("transfer_vk_generated.rs");
#[cfg(not(test))]
include!("deposit_vk_generated.rs");
#[cfg(not(test))]
include!("withdraw_vk_generated.rs");

#[cfg(test)]
static TRANSFER_VK: VerificationKey = VerificationKey {
    alpha: [0u8; 64],
    beta: [0u8; 128],
    gamma: [0u8; 128],
    delta: [0u8; 128],
    ic: &[],
};
#[cfg(test)]
static DEPOSIT_VK: VerificationKey = VerificationKey {
    alpha: [0u8; 64],
    beta: [0u8; 128],
    gamma: [0u8; 128],
    delta: [0u8; 128],
    ic: &[],
};
#[cfg(test)]
static WITHDRAW_VK: VerificationKey = VerificationKey {
    alpha: [0u8; 64],
    beta: [0u8; 128],
    gamma: [0u8; 128],
    delta: [0u8; 128],
    ic: &[],
};

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (&opcode, rest) = instruction_data
        .split_first()
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
    else {
        return Err(ProgramError::InvalidInstructionData);
    };
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let payer = &accounts[0];
    let pda = &accounts[1];
    let system_program = &accounts[2];

    // PDA seed: first 32 bytes of the account's pubkey (the x coordinate)
    let seed = &pubkey[0..32];
    let (expected_pda, bump) = Pubkey::find_program_address(&[seed], program_id);

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
fn process_ring_transfer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let LaurelinInstruction::RingTransfer {
        proof,
        sender_new_c1,
        sender_new_c2,
        recv_delta_c1,
        recv_delta_c2,
    } = parse_ring_transfer(data).ok_or(ProgramError::InvalidInstructionData)?
    else {
        return Err(ProgramError::InvalidInstructionData);
    };
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let sender_pda = [&accounts[0], &accounts[1]];
    let recv_pda = [&accounts[2], &accounts[3]];

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
    );

    let ok =
        verify(&TRANSFER_VK, &proof, &public_inputs).map_err(|_| ProgramError::InvalidArgument)?;
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

    // Update receiver ciphertexts homomorphically (add delta to each).
    // Batch all 4 additions (2 receivers × c1,c2) into a single field inversion.
    let recv_results = bjj::bjj_add_batch4([
        (&recv_state[0].c1, &recv_delta_c1[0]),
        (&recv_state[0].c2, &recv_delta_c2[0]),
        (&recv_state[1].c1, &recv_delta_c1[1]),
        (&recv_state[1].c2, &recv_delta_c2[1]),
    ])
    .map_err(|_| ProgramError::InvalidArgument)?;

    {
        let mut data = recv_pda[0].data.borrow_mut();
        data[64..128].copy_from_slice(&recv_results[0]);
        data[128..192].copy_from_slice(&recv_results[1]);
    }
    {
        let mut data = recv_pda[1].data.borrow_mut();
        data[64..128].copy_from_slice(&recv_results[2]);
        data[128..192].copy_from_slice(&recv_results[3]);
    }

    msg!("ring transfer complete");
    Ok(())
}

/// Deposit: proves the delta ciphertext correctly encrypts the deposit amount.
fn process_deposit(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let LaurelinInstruction::Deposit {
        proof,
        delta_c1,
        delta_c2,
        amount,
    } = parse_deposit(data).ok_or(ProgramError::InvalidInstructionData)?
    else {
        return Err(ProgramError::InvalidInstructionData);
    };
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let payer = &accounts[0];
    let pda = &accounts[1];
    let vault_pda = &accounts[2];
    let system_program = &accounts[3];

    if pda.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (expected_vault, bump) = Pubkey::find_program_address(&[VAULT_SEED], program_id);
    if vault_pda.key != &expected_vault {
        msg!("vault PDA mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    let state =
        AccountState::try_from_bytes(&pda.data.borrow()).ok_or(ProgramError::InvalidAccountData)?;

    let public_inputs = build_deposit_public_inputs(&state.pubkey, &delta_c1, &delta_c2, amount);

    let ok =
        verify(&DEPOSIT_VK, &proof, &public_inputs).map_err(|_| ProgramError::InvalidArgument)?;
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

    let (new_c1, new_c2) = bjj::bjj_add_batch(&state.c1, &delta_c1, &state.c2, &delta_c2)
        .map_err(|_| ProgramError::InvalidArgument)?;

    let mut data = pda.data.borrow_mut();
    data[64..128].copy_from_slice(&new_c1);
    data[128..192].copy_from_slice(&new_c2);

    msg!("deposit complete");
    Ok(())
}

/// Withdraw: proves sk ownership and sufficient balance.
fn process_withdraw(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let LaurelinInstruction::Withdraw {
        proof,
        new_c1,
        new_c2,
        amount,
    } = parse_withdraw(data).ok_or(ProgramError::InvalidInstructionData)?
    else {
        return Err(ProgramError::InvalidInstructionData);
    };
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let pda = &accounts[0];
    let vault_pda = &accounts[1];
    let destination = &accounts[2];

    if pda.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (expected_vault, _) = Pubkey::find_program_address(&[VAULT_SEED], program_id);
    if vault_pda.key != &expected_vault {
        msg!("vault PDA mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    let state =
        AccountState::try_from_bytes(&pda.data.borrow()).ok_or(ProgramError::InvalidAccountData)?;

    let public_inputs = build_withdraw_public_inputs(&state, &new_c1, &new_c2, amount);

    let ok =
        verify(&WITHDRAW_VK, &proof, &public_inputs).map_err(|_| ProgramError::InvalidArgument)?;
    if !ok {
        msg!("withdraw proof invalid");
        return Err(ProgramError::InvalidArgument);
    }

    let rent = Rent::get()?;
    let rent_exempt = rent.minimum_balance(0);
    let available = vault_pda.lamports().saturating_sub(rent_exempt);
    if available < amount {
        msg!("insufficient vault balance");
        return Err(ProgramError::InsufficientFunds);
    }

    **vault_pda.lamports.borrow_mut() -= amount;
    **destination.lamports.borrow_mut() += amount;

    let mut data = pda.data.borrow_mut();
    data[64..128].copy_from_slice(&new_c1);
    data[128..192].copy_from_slice(&new_c2);

    msg!("withdraw complete");
    Ok(())
}

// ── Public input builders ─────────────────────────────────────────────────────
//
// BJJ points are serialised as X||Y (64 bytes, big-endian BN254 Fr coords).
// Each coordinate is a native BN254 Fr element → passed as a 32-byte Scalar.
// No limb decomposition needed (BJJ coords are the native field elements).

/// Push a BJJ point's X and Y coordinates as two 32-byte scalars.
fn push_point(inputs: &mut Vec<state::Scalar>, pt: &G1Point) {
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&pt[0..32]);
    y.copy_from_slice(&pt[32..64]);
    inputs.push(x);
    inputs.push(y);
}

/// Build the 7 public inputs for the deposit Groth16 proof.
///
/// Circuit public input order (DepositCircuit):
///   pk (2 Fr), delta_c1 (2 Fr), delta_c2 (2 Fr), amount (1 Fr)
/// Total: 7, IC.len() = 8.
fn build_deposit_public_inputs(
    pk: &G1Point,
    delta_c1: &G1Point,
    delta_c2: &G1Point,
    amount: u64,
) -> Vec<state::Scalar> {
    let mut inputs = Vec::with_capacity(7);
    push_point(&mut inputs, pk);
    push_point(&mut inputs, delta_c1);
    push_point(&mut inputs, delta_c2);
    let mut amount_scalar = [0u8; 32];
    amount_scalar[24..32].copy_from_slice(&amount.to_be_bytes());
    inputs.push(amount_scalar);
    inputs
}

/// Build the 11 public inputs for the withdraw Groth16 proof.
///
/// Circuit public input order (WithdrawCircuit):
///   pk (2 Fr), old_c1 (2 Fr), old_c2 (2 Fr), new_c1 (2 Fr), new_c2 (2 Fr), amount (1 Fr)
/// Total: 11, IC.len() = 12.
fn build_withdraw_public_inputs(
    state: &AccountState,
    new_c1: &G1Point,
    new_c2: &G1Point,
    amount: u64,
) -> Vec<state::Scalar> {
    let mut inputs = Vec::with_capacity(11);
    push_point(&mut inputs, &state.pubkey);
    push_point(&mut inputs, &state.c1);
    push_point(&mut inputs, &state.c2);
    push_point(&mut inputs, new_c1);
    push_point(&mut inputs, new_c2);
    let mut amount_scalar = [0u8; 32];
    amount_scalar[24..32].copy_from_slice(&amount.to_be_bytes());
    inputs.push(amount_scalar);
    inputs
}

/// Build the 32 public inputs for the ring Groth16 proof (N=2).
///
/// Circuit public input order (RingTransferCircuit<2>):
///   sender_pks[0..2]      (4 Fr)
///   sender_old_c1[0..2]   (4 Fr)
///   sender_old_c2[0..2]   (4 Fr)
///   sender_new_c1[0..2]   (4 Fr)
///   sender_new_c2[0..2]   (4 Fr)
///   recv_pks[0..2]        (4 Fr)
///   recv_delta_c1[0..2]   (4 Fr)
///   recv_delta_c2[0..2]   (4 Fr)
/// Total: 32, IC.len() = 33.
fn build_ring_public_inputs(
    sender_state: &[AccountState; 2],
    recv_state: &[AccountState; 2],
    sender_new_c1: &[G1Point; 2],
    sender_new_c2: &[G1Point; 2],
    recv_delta_c1: &[G1Point; 2],
    recv_delta_c2: &[G1Point; 2],
) -> Vec<state::Scalar> {
    let mut inputs = Vec::with_capacity(32);

    for s in sender_state {
        push_point(&mut inputs, &s.pubkey);
    }
    for s in sender_state {
        push_point(&mut inputs, &s.c1);
    }
    for s in sender_state {
        push_point(&mut inputs, &s.c2);
    }
    for c in sender_new_c1 {
        push_point(&mut inputs, c);
    }
    for c in sender_new_c2 {
        push_point(&mut inputs, c);
    }
    for r in recv_state {
        push_point(&mut inputs, &r.pubkey);
    }
    for c in recv_delta_c1 {
        push_point(&mut inputs, c);
    }
    for c in recv_delta_c2 {
        push_point(&mut inputs, c);
    }

    inputs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_point(x_lsb: u8, y_lsb: u8) -> state::G1Point {
        let mut p = [0u8; 64];
        p[31] = x_lsb;
        p[63] = y_lsb;
        p
    }

    fn make_state(pk: u8, c1: u8, c2: u8) -> state::AccountState {
        state::AccountState {
            pubkey: make_point(pk, pk),
            c1: make_point(c1, c1),
            c2: make_point(c2, c2),
        }
    }

    #[test]
    fn deposit_public_inputs_count() {
        let z = [0u8; 64];
        let inputs = build_deposit_public_inputs(&z, &z, &z, 400);
        assert_eq!(inputs.len(), 7);
    }

    #[test]
    fn deposit_amount_is_last() {
        let z = [0u8; 64];
        let inputs = build_deposit_public_inputs(&z, &z, &z, 400);
        let mut expected = [0u8; 32];
        expected[24..32].copy_from_slice(&400u64.to_be_bytes());
        assert_eq!(inputs[6], expected);
    }

    #[test]
    fn withdraw_public_inputs_count() {
        let z = [0u8; 64];
        let state = make_state(0, 0, 0);
        let inputs = build_withdraw_public_inputs(&state, &z, &z, 400);
        assert_eq!(inputs.len(), 11);
    }

    #[test]
    fn withdraw_amount_is_last() {
        let z = [0u8; 64];
        let state = make_state(0, 0, 0);
        let inputs = build_withdraw_public_inputs(&state, &z, &z, 400);
        let mut expected = [0u8; 32];
        expected[24..32].copy_from_slice(&400u64.to_be_bytes());
        assert_eq!(inputs[10], expected);
    }

    #[test]
    fn ring_public_inputs_count() {
        let z = [0u8; 64];
        let sender = [make_state(0, 0, 0), make_state(0, 0, 0)];
        let recv = [make_state(0, 0, 0), make_state(0, 0, 0)];
        let inputs = build_ring_public_inputs(&sender, &recv, &[z; 2], &[z; 2], &[z; 2], &[z; 2]);
        assert_eq!(inputs.len(), 32);
    }

    #[test]
    fn ring_point_ordering() {
        // Each point contributes X at [2*i] and Y at [2*i+1].
        // Point order: sender_pk[0,1], sender_c1[0,1], sender_c2[0,1],
        //              sender_new_c1[0,1], sender_new_c2[0,1],
        //              recv_pk[0,1], recv_delta_c1[0,1], recv_delta_c2[0,1]
        let z = [0u8; 64];
        let mut pts = [[0u8; 64]; 16];
        for i in 0..16usize {
            pts[i][31] = (i + 1) as u8; // X last byte = marker
            pts[i][63] = (i + 1) as u8; // Y last byte = marker
        }
        let sender = [
            state::AccountState {
                pubkey: pts[0],
                c1: pts[2],
                c2: pts[4],
            },
            state::AccountState {
                pubkey: pts[1],
                c1: pts[3],
                c2: pts[5],
            },
        ];
        let recv = [
            state::AccountState {
                pubkey: pts[10],
                c1: z,
                c2: z,
            },
            state::AccountState {
                pubkey: pts[11],
                c1: z,
                c2: z,
            },
        ];
        let inputs = build_ring_public_inputs(
            &sender,
            &recv,
            &[pts[6], pts[7]],
            &[pts[8], pts[9]],
            &[pts[12], pts[13]],
            &[pts[14], pts[15]],
        );
        // Each point i: X at inputs[2*i][31], Y at inputs[2*i+1][63]
        for i in 0..16 {
            assert_eq!(
                inputs[2 * i][31],
                (i + 1) as u8,
                "point {i} X should have marker {}",
                i + 1
            );
        }
    }
}
