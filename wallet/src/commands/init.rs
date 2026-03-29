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

    // Solana: generate keypair, extract the 32-byte Ed25519 seed
    let kp = Keypair::new();
    let kp_bytes = kp.to_bytes(); // 64 bytes: seed (32) || pubkey (32)
    let solana_sk: [u8; 32] = kp_bytes[..32].try_into().unwrap();

    // Laurelin: random BN254 scalar
    let mut rng = rand::thread_rng();
    let laurelin_sk_fr = Fr::rand(&mut rng);
    let laurelin_sk = fr_to_bytes(&laurelin_sk_fr);

    if insecure {
        Wallet::save_plaintext(wallet_path, &solana_sk, &laurelin_sk)?;
    } else {
        let password = prompt_new_password()?;
        Wallet::save_encrypted(wallet_path, &solana_sk, &laurelin_sk, password.as_bytes())?;
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
