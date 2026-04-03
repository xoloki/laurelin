//! `accounts` — list all Laurelin PDAs on-chain.

use solana_sdk::pubkey::Pubkey;

use crate::{
    bjj::coord_to_bytes,
    config::ResolvedConfig,
    rpc::{get_all_accounts, new_client},
};

pub fn run(cfg: &ResolvedConfig) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let program_id: Pubkey = cfg.program_id.parse()?;
    let accounts = get_all_accounts(&client, &program_id)?;

    if accounts.is_empty() {
        println!("No Laurelin accounts found.");
        return Ok(());
    }

    println!("{} account(s) found:", accounts.len());
    for acc in &accounts {
        let pk_x = coord_to_bytes(&acc.laurelin_pk.x);
        println!(
            "  PDA: {}  Laurelin pubkey: {}",
            acc.pubkey,
            bs58::encode(pk_x).into_string()
        );
    }
    Ok(())
}
