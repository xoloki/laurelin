use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcTransactionConfig;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Signer},
    transaction::Transaction,
};
use solana_transaction_status::UiTransactionEncoding;
use std::str::FromStr;

// BN254 G1 generator (x=1, y=2), big-endian
const G1_X: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 1;
    b
};
const G1_Y: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 2;
    b
};

fn scalar_mul(point: &[u8; 64], scalar: &[u8; 32]) -> [u8; 64] {
    use solana_program::alt_bn128::prelude::alt_bn128_multiplication;
    let mut input = [0u8; 96];
    input[0..64].copy_from_slice(point);
    input[64..96].copy_from_slice(scalar);
    alt_bn128_multiplication(&input)
        .expect("BN254 multiplication failed")
        .try_into()
        .expect("unexpected output length")
}

fn generator() -> [u8; 64] {
    let mut g = [0u8; 64];
    g[0..32].copy_from_slice(&G1_X);
    g[32..64].copy_from_slice(&G1_Y);
    g
}

fn main() {
    let program_id_str = std::env::args().nth(1).expect("usage: client <PROGRAM_ID>");

    let rpc_url = "http://localhost:8899";
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let payer =
        read_keypair_file("accounts/account1.json").expect("failed to read accounts/account1.json");

    let program_id = Pubkey::from_str(&program_id_str).expect("invalid program ID");

    // build instruction data: point (64) || scalar (32) || expected (64) = 160 bytes
    let g = generator();
    let mut scalar = [0u8; 32];
    scalar[31] = 7; // scalar = 7
    let expected = scalar_mul(&g, &scalar); // 7 * G

    let mut instruction_data = Vec::with_capacity(160);
    instruction_data.extend_from_slice(&g);
    instruction_data.extend_from_slice(&scalar);
    instruction_data.extend_from_slice(&expected);

    let instruction = Instruction {
        program_id,
        accounts: vec![AccountMeta::new(payer.pubkey(), true)],
        data: instruction_data,
    };

    let recent_blockhash = client
        .get_latest_blockhash()
        .expect("failed to get blockhash");

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let sig = match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => {
            println!("transaction confirmed: {}", sig);
            sig
        }
        Err(e) => {
            eprintln!("transaction failed: {}", e);
            return;
        }
    };

    match client.get_transaction_with_config(
        &sig,
        RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Json),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        },
    ) {
        Ok(tx) => {
            if let Some(meta) = tx.transaction.meta {
                let logs: Vec<String> = Option::from(meta.log_messages).unwrap_or_default();
                println!("program logs:");
                for line in logs {
                    println!("  {}", line);
                }
            }
        }
        Err(e) => eprintln!("failed to fetch transaction: {}", e),
    }
}
