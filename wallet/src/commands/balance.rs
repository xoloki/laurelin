//! `balance` — show SOL balance and confidential (encrypted) balance.
//!
//! The confidential balance is decrypted via BSGS over the range [0, 2^32).
//! Building the BSGS table takes a few seconds on first run.

use solana_sdk::{pubkey::Pubkey, signature::Signer};

use crate::{
    bn254::{bsgs_decrypt, BsgsTable},
    config::ResolvedConfig,
    rpc::{get_laurelin_account, get_sol_balance, new_client},
    wallet::Wallet,
};

pub fn run(wallet: &Wallet, cfg: &ResolvedConfig) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let program_id: Pubkey = cfg.program_id.parse()?;
    let pda = wallet.pda(&program_id);
    let sk = wallet.bn254_sk_fr();

    // SOL balance
    let lamports = get_sol_balance(&client, &kp.pubkey())?;
    println!(
        "SOL balance:           {} lamports  ({:.9} SOL)",
        lamports,
        lamports as f64 / 1e9
    );

    // Confidential balance
    let account = get_laurelin_account(&client, &pda)?;
    eprintln!("Building BSGS table (range 0..2^32)…");
    let table = BsgsTable::build();
    let balance = bsgs_decrypt(&account.ciphertext, &sk, &table)
        .ok_or_else(|| anyhow::anyhow!("BSGS: balance out of [0, 2^32) range"))?;
    println!("Confidential balance:  {} lamports", balance);

    Ok(())
}
