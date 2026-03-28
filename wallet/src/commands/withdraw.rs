//! `withdraw <lamports>` — withdraw from the confidential balance to SOL.

use ark_bn254::Fr;
use ark_std::UniformRand;
use solana_sdk::{pubkey::Pubkey, signature::Signer};

use crate::{
    bn254::{bsgs_decrypt, g1_to_bytes, generator, point_add, scalar_mul, BsgsTable},
    config::ResolvedConfig,
    instructions::{set_compute_unit_limit, vault_pda, withdraw},
    prover::prove_withdraw,
    rpc::{get_laurelin_account, new_client, send_instructions},
    wallet::Wallet,
};

pub fn run(wallet: &Wallet, cfg: &ResolvedConfig, lamports: u64) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let program_id: Pubkey = cfg.program_id.parse()?;
    let pda = wallet.pda(&program_id);
    let vault = vault_pda(&program_id);
    let sk = wallet.bn254_sk_fr();

    // Fetch current on-chain ciphertext
    let account = get_laurelin_account(&client, &pda)?;
    let old_ct = &account.ciphertext;

    // Decrypt current balance to verify we have enough
    eprintln!("Building BSGS table…");
    let table = BsgsTable::build();
    let old_balance = bsgs_decrypt(old_ct, &sk, &table)
        .ok_or_else(|| anyhow::anyhow!("BSGS: current balance out of range"))?;

    anyhow::ensure!(
        lamports <= old_balance,
        "insufficient confidential balance: have {old_balance}, want {lamports}"
    );

    let new_balance = old_balance - lamports;

    // Re-encrypt new balance
    let mut rng = rand::thread_rng();
    let r_new = Fr::rand(&mut rng);
    let g = generator();
    let new_c1 = scalar_mul(&g, &r_new);
    let new_c2 = point_add(
        &scalar_mul(&wallet.bn254_pk, &r_new),
        &scalar_mul(&g, &Fr::from(new_balance)),
    );

    let pk_path = cfg.pk_dir.join("withdraw_pk.bin");
    let pk_path_str = pk_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("pk_dir path is not valid UTF-8"))?;

    eprintln!("Proving withdrawal ({lamports} lamports, remaining {new_balance})…");
    let proof = prove_withdraw(
        pk_path_str,
        &sk,
        &r_new,
        old_balance,
        new_balance,
        &wallet.bn254_pk,
        &old_ct.c1,
        &old_ct.c2,
        &new_c1,
        &new_c2,
        lamports,
    )?;

    let ix = withdraw(
        &program_id,
        &pda,
        &vault,
        &kp.pubkey(),
        &proof,
        &g1_to_bytes(&new_c1),
        &g1_to_bytes(&new_c2),
        lamports,
    );

    let sig = send_instructions(&client, &kp, &[set_compute_unit_limit(800_000), ix])?;
    println!("Withdrawal confirmed. Remaining confidential balance: {new_balance} lamports");
    println!("Signature: {sig}");
    Ok(())
}
