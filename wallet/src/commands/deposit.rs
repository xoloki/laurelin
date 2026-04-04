//! `deposit <lamports>` — deposit SOL into the confidential balance.

use solana_sdk::{pubkey::Pubkey, signature::Signer};

use crate::{
    bjj::{elgamal_encrypt, point_to_bytes, MAX_CONFIDENTIAL_LAMPORTS},
    config::ResolvedConfig,
    instructions::{deposit, set_compute_unit_limit, vault_pda},
    prover::prove_deposit,
    rpc::{new_client, send_instructions},
    wallet::Wallet,
};

pub fn run(wallet: &Wallet, cfg: &ResolvedConfig, lamports: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        lamports <= MAX_CONFIDENTIAL_LAMPORTS,
        "amount {} lamports exceeds the maximum confidential balance ({} lamports, ~4.3 SOL)",
        lamports,
        MAX_CONFIDENTIAL_LAMPORTS,
    );
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let program_id: Pubkey = cfg.program_id.parse()?;
    let pda = wallet.pda(&program_id);
    let vault = vault_pda(&program_id);

    let pk_path = cfg.pk_dir.join("deposit_pk.bin");

    // ElGamal encrypt the deposit amount
    let (delta_ct, r) = elgamal_encrypt(&wallet.laurelin_pk, lamports);

    eprintln!("Proving deposit ({lamports} lamports)…");
    let proof = prove_deposit(
        &pk_path,
        &r,
        &wallet.laurelin_pk,
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
        &point_to_bytes(&delta_ct.c1),
        &point_to_bytes(&delta_ct.c2),
        lamports,
    );

    let sig = send_instructions(&client, &kp, &[set_compute_unit_limit(1_400_000), ix])?;
    println!("Deposit confirmed. Signature: {sig}");
    Ok(())
}
