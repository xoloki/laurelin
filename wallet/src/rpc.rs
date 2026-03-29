//! Solana RPC helpers wrapping solana-client 1.18.

use anyhow::Context;
use ark_bn254::G1Affine;
use solana_account_decoder::UiAccountEncoding;
use solana_client::{
    rpc_client::RpcClient,
    rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig, RpcSendTransactionConfig},
    rpc_filter::RpcFilterType,
};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::Instruction,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::Transaction,
};
use solana_transaction_status::UiTransactionEncoding;

use crate::bn254::{g1_from_bytes, Ciphertext};

/// Create a new RPC client.
pub fn new_client(url: &str) -> RpcClient {
    RpcClient::new_with_commitment(url.to_owned(), CommitmentConfig::confirmed())
}

/// Build, sign, and send a transaction.  Returns the signature.
pub fn send_instructions(
    client: &RpcClient,
    payer: &Keypair,
    instructions: &[Instruction],
) -> anyhow::Result<Signature> {
    let blockhash = client
        .get_latest_blockhash()
        .context("get latest blockhash")?;
    let msg = Message::new(instructions, Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer], msg, blockhash);
    let sig = client
        .send_and_confirm_transaction_with_spinner_and_config(
            &tx,
            CommitmentConfig::confirmed(),
            RpcSendTransactionConfig {
                encoding: Some(UiTransactionEncoding::Base64),
                preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
                ..Default::default()
            },
        )
        .context("send transaction")?;
    Ok(sig)
}

/// Account data fetched from a Laurelin PDA.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LaurelinkAccount {
    pub pubkey: Pubkey,
    pub laurelin_pk: G1Affine,
    pub laurelin_pk_bytes: [u8; 64],
    pub ciphertext: Ciphertext,
}

/// Fetch a single Laurelin account by its PDA.
pub fn get_laurelin_account(client: &RpcClient, pda: &Pubkey) -> anyhow::Result<LaurelinkAccount> {
    let data = client
        .get_account_data(pda)
        .with_context(|| format!("get account {pda}"))?;
    parse_account_data(*pda, &data)
}

/// Return all Laurelin accounts for a program (size == 192 bytes).
pub fn get_all_accounts(
    client: &RpcClient,
    program_id: &Pubkey,
) -> anyhow::Result<Vec<LaurelinkAccount>> {
    let config = RpcProgramAccountsConfig {
        filters: Some(vec![RpcFilterType::DataSize(192)]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            commitment: Some(CommitmentConfig::confirmed()),
            ..Default::default()
        },
        ..Default::default()
    };

    let accounts = client
        .get_program_accounts_with_config(program_id, config)
        .context("getProgramAccounts")?;

    accounts
        .into_iter()
        .map(|(pk, acc)| parse_account_data(pk, &acc.data))
        .collect()
}

/// Parse 192-byte Laurelin account data.
/// Layout: laurelin_pk(64) || c1(64) || c2(64)
fn parse_account_data(pubkey: Pubkey, data: &[u8]) -> anyhow::Result<LaurelinkAccount> {
    anyhow::ensure!(
        data.len() >= 192,
        "account {pubkey}: data too short ({})",
        data.len()
    );

    let mut pk_bytes = [0u8; 64];
    pk_bytes.copy_from_slice(&data[0..64]);

    let mut c1_bytes = [0u8; 64];
    c1_bytes.copy_from_slice(&data[64..128]);

    let mut c2_bytes = [0u8; 64];
    c2_bytes.copy_from_slice(&data[128..192]);

    let laurelin_pk =
        g1_from_bytes(&pk_bytes).with_context(|| format!("parse laurelin_pk for {pubkey}"))?;
    let c1 = g1_from_bytes(&c1_bytes).with_context(|| format!("parse c1 for {pubkey}"))?;
    let c2 = g1_from_bytes(&c2_bytes).with_context(|| format!("parse c2 for {pubkey}"))?;

    Ok(LaurelinkAccount {
        pubkey,
        laurelin_pk,
        laurelin_pk_bytes: pk_bytes,
        ciphertext: Ciphertext { c1, c2 },
    })
}

/// Build, sign, and send a transaction with multiple signers.
pub fn send_instructions_signed(
    client: &RpcClient,
    payer: &Keypair,
    extra_signers: &[&Keypair],
    instructions: &[Instruction],
) -> anyhow::Result<Signature> {
    let blockhash = client
        .get_latest_blockhash()
        .context("get latest blockhash")?;
    let msg = Message::new(instructions, Some(&payer.pubkey()));
    let mut all: Vec<&Keypair> = vec![payer];
    all.extend_from_slice(extra_signers);
    let tx = Transaction::new(&all, msg, blockhash);
    let sig = client
        .send_and_confirm_transaction_with_spinner_and_config(
            &tx,
            CommitmentConfig::confirmed(),
            RpcSendTransactionConfig {
                encoding: Some(UiTransactionEncoding::Base64),
                preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
                ..Default::default()
            },
        )
        .context("send transaction")?;
    Ok(sig)
}

/// SOL balance in lamports.
pub fn get_sol_balance(client: &RpcClient, pubkey: &Pubkey) -> anyhow::Result<u64> {
    client
        .get_balance(pubkey)
        .with_context(|| format!("get balance {pubkey}"))
}
