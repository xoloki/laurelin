//! `init` — generate a new Solana + BN254 keypair and save to wallet file.

use std::path::Path;

use ark_bn254::Fr;
use ark_std::UniformRand;
use solana_sdk::signature::{Keypair, Signer};
use zeroize::Zeroizing;

use crate::{bn254::fr_to_bytes, wallet::Wallet};

pub fn run(wallet_path: &Path, insecure: bool) -> anyhow::Result<()> {
    if wallet_path.exists() {
        anyhow::bail!(
            "wallet file already exists at {}.  Delete it first to re-initialise.",
            wallet_path.display()
        );
    }

    // Solana keypair
    let kp = Keypair::new();
    let kp_bytes: [u8; 64] = kp.to_bytes();

    // BN254 secret key
    let mut rng = rand::thread_rng();
    let sk = Fr::rand(&mut rng);
    let sk_bytes = fr_to_bytes(&sk);

    if insecure {
        Wallet::save_plaintext(wallet_path, &kp_bytes, &sk_bytes)?;
    } else {
        let password = prompt_new_password()?;
        Wallet::save_encrypted(wallet_path, &kp_bytes, &sk_bytes, password.as_bytes())?;
    }

    println!("Wallet created at {}", wallet_path.display());
    println!("Solana pubkey:  {}", kp.pubkey());
    println!("\nRun `laurelin-wallet pubkey` to see your BN254 pubkey and PDA.");
    Ok(())
}

fn prompt_new_password() -> anyhow::Result<Zeroizing<String>> {
    let pw1 = Zeroizing::new(rpassword::prompt_password("New wallet password: ")?);
    let pw2 = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
    anyhow::ensure!(*pw1 == *pw2, "passwords do not match");
    Ok(pw1)
}
