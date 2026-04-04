//! `withdraw <lamports>` — withdraw from the confidential balance to SOL.

use ark_ed_on_bn254::Fr as BJJFr;
use ark_std::UniformRand;
use solana_sdk::{pubkey::Pubkey, signature::Signer};

use crate::{
    bjj::{
        bsgs_decrypt, generator, point_add, point_to_bytes, scalar_mul, BsgsTable,
        MAX_CONFIDENTIAL_LAMPORTS,
    },
    config::ResolvedConfig,
    instructions::{set_compute_unit_limit, vault_pda, withdraw},
    prover::prove_withdraw,
    rpc::{get_laurelin_account, new_client, send_instructions},
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
    let sk = wallet.laurelin_sk_fr();

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
    let r_new = BJJFr::rand(&mut rng);
    let g = generator();
    let new_c1 = scalar_mul(&g, &r_new);
    let new_c2 = point_add(
        &scalar_mul(&wallet.laurelin_pk, &r_new),
        &scalar_mul(&g, &BJJFr::from(new_balance)),
    );

    let pk_path = cfg.pk_dir.join("withdraw_pk.bin");

    eprintln!("Proving withdrawal ({lamports} lamports, remaining {new_balance})…");
    let proof = prove_withdraw(
        &pk_path,
        &sk,
        &r_new,
        old_balance,
        new_balance,
        &wallet.laurelin_pk,
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
        &point_to_bytes(&new_c1),
        &point_to_bytes(&new_c2),
        lamports,
    );

    let sig = send_instructions(&client, &kp, &[set_compute_unit_limit(800_000), ix])?;
    println!("Withdrawal confirmed. Remaining confidential balance: {new_balance} lamports");
    println!("Signature: {sig}");
    Ok(())
}
