//! `deposit <lamports>` — deposit SOL into the confidential balance.

use solana_sdk::{pubkey::Pubkey, signature::Signer};

use crate::{
    bn254::{elgamal_encrypt, g1_to_bytes},
    config::ResolvedConfig,
    instructions::{deposit, set_compute_unit_limit, vault_pda},
    prover::prove_deposit,
    rpc::{new_client, send_instructions},
    wallet::Wallet,
};

pub fn run(wallet: &Wallet, cfg: &ResolvedConfig, lamports: u64) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let program_id: Pubkey = cfg.program_id.parse()?;
    let pda = wallet.pda(&program_id);
    let vault = vault_pda(&program_id);

    let pk_path = cfg.pk_dir.join("deposit_pk.bin");
    let pk_path_str = pk_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("pk_dir path is not valid UTF-8"))?;

    // ElGamal encrypt the deposit amount
    let (delta_ct, r) = elgamal_encrypt(&wallet.bn254_pk, lamports);

    eprintln!("Proving deposit ({lamports} lamports)…");
    let proof = prove_deposit(
        &cfg.prover,
        pk_path_str,
        &r,
        &wallet.bn254_pk,
        &delta_ct.c1,
        &delta_ct.c2,
        lamports,
    )?;

    let ix = deposit(
        &program_id,
        &kp.pubkey(),
        &pda,
        &vault,
        &proof,
        &g1_to_bytes(&delta_ct.c1),
        &g1_to_bytes(&delta_ct.c2),
        lamports,
    );

    let sig = send_instructions(&client, &kp, &[set_compute_unit_limit(500_000), ix])?;
    println!("Deposit confirmed. Signature: {sig}");
    Ok(())
}
