//! `create-account` — register this wallet's PDA on-chain.

use solana_sdk::{pubkey::Pubkey, signature::Signer};

use crate::{
    config::ResolvedConfig,
    instructions::{create_account, set_compute_unit_limit},
    rpc::{new_client, send_instructions},
    wallet::Wallet,
};

pub fn run(wallet: &Wallet, cfg: &ResolvedConfig) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let program_id: Pubkey = cfg.program_id.parse()?;
    let pda = wallet.pda(&program_id);

    let zero = [0u8; 64];
    let ix = create_account(
        &program_id,
        &kp.pubkey(),
        &pda,
        &wallet.laurelin_pk_bytes,
        &zero,
        &zero,
    );

    let sig = send_instructions(&client, &kp, &[set_compute_unit_limit(100_000), ix])?;
    println!("Account created: {pda}");
    println!("Signature: {sig}");
    Ok(())
}
