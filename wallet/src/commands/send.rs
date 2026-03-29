//! `send <lamports> --to <pubkey>` — plain SOL transfer.

use solana_sdk::{pubkey::Pubkey, signature::Signer, system_instruction};

use crate::{
    config::ResolvedConfig,
    rpc::{new_client, send_instructions},
    wallet::Wallet,
};

pub fn run(wallet: &Wallet, cfg: &ResolvedConfig, lamports: u64, to: &str) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let to_pubkey: Pubkey = to
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid pubkey: {to}"))?;

    let ix = system_instruction::transfer(&kp.pubkey(), &to_pubkey, lamports);
    let sig = send_instructions(&client, &kp, &[ix])?;
    println!("Sent {} lamports to {to_pubkey}", lamports);
    println!("Signature: {sig}");
    Ok(())
}
