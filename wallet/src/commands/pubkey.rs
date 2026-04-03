//! `pubkey` — show Solana pubkey and Laurelin pubkey.
//! With --verbose: also shows the Laurelin PDA.

use solana_sdk::{pubkey::Pubkey, signature::Signer};

use crate::{bjj::coord_to_bytes, config::ResolvedConfig, wallet::Wallet};

pub fn run(wallet: &Wallet, cfg: &ResolvedConfig, verbose: bool) -> anyhow::Result<()> {
    let kp = wallet.solana_keypair()?;
    let pk_x = coord_to_bytes(&wallet.laurelin_pk.x);

    println!("Solana pubkey:   {}", kp.pubkey());
    println!("Laurelin pubkey: {}", bs58::encode(pk_x).into_string());

    if verbose {
        let program_id: Pubkey = cfg.program_id.parse()?;
        let pda = wallet.pda(&program_id);
        println!("Laurelin PDA:    {pda}");
    }
    Ok(())
}
