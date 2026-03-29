//! `pubkey` — show Solana pubkey and BN254 pubkey X coordinate.
//! With --verbose: also shows the Laurelin PDA.

use solana_sdk::{pubkey::Pubkey, signature::Signer};

use crate::{bn254::fq_to_bytes, config::ResolvedConfig, wallet::Wallet};

pub fn run(wallet: &Wallet, cfg: &ResolvedConfig, verbose: bool) -> anyhow::Result<()> {
    let kp = wallet.solana_keypair()?;
    let pk_x = fq_to_bytes(&wallet.bn254_pk.x);

    println!("Solana pubkey:   {}", kp.pubkey());
    println!("BN254 pubkey X:  {}", hex::encode(pk_x));

    if verbose {
        let program_id: Pubkey = cfg.program_id.parse()?;
        let pda = wallet.pda(&program_id);
        println!("Laurelin PDA:    {pda}");
    }
    Ok(())
}
