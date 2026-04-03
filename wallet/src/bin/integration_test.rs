//! Integration test binary — replaces the old Go client.
//!
//! Creates 4 in-memory wallets, airdrops SOL, then runs the full
//! deposit → transfer → withdraw cycle against a live validator.
//!
//! Usage:
//!   cargo run --release --bin integration-test -- <PROGRAM_ID> <PAYER_KEYPAIR> <PK_DIR>
//!
//! Expects a running solana-test-validator with the program already deployed.

use std::path::PathBuf;

use anyhow::Context;
use ark_ed_on_bn254::Fr as BJJFr;
use ark_std::UniformRand;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use zeroize::Zeroizing;

// Re-use wallet crate internals (same crate, different binary).
use laurelin_wallet::{
    bjj::{
        bsgs_decrypt, coord_to_bytes, elgamal_encrypt, generator, point_add, point_to_bytes,
        scalar_mul, BsgsTable,
    },
    config::ResolvedConfig,
    instructions::{
        create_account, deposit, ring_transfer, set_compute_unit_limit, vault_pda, withdraw,
    },
    prover::{prove_deposit, prove_transfer, prove_withdraw},
    rpc::{
        get_all_accounts, get_laurelin_account, new_client, send_instructions, LaurelinkAccount,
    },
    wallet::Wallet,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Create an in-memory wallet (no file I/O).
fn make_wallet() -> Wallet {
    let kp = Keypair::new();
    let kp_bytes = kp.to_bytes();
    let solana_sk: [u8; 32] = kp_bytes[..32].try_into().unwrap();

    let mut rng = rand::thread_rng();
    let sk_fr = BJJFr::rand(&mut rng);

    use laurelin_wallet::bjj::bjj_fr_to_bytes;
    let laurelin_sk = bjj_fr_to_bytes(&sk_fr);
    let laurelin_pk = scalar_mul(&generator(), &sk_fr);
    let laurelin_pk_bytes = point_to_bytes(&laurelin_pk);

    Wallet {
        solana_sk: Zeroizing::new(solana_sk),
        laurelin_sk: Zeroizing::new(laurelin_sk),
        laurelin_pk,
        laurelin_pk_bytes,
    }
}

fn airdrop(client: &RpcClient, pubkey: &Pubkey, lamports: u64) -> anyhow::Result<()> {
    let sig = client.request_airdrop(pubkey, lamports)?;
    // Wait for confirmation
    loop {
        if client.confirm_transaction(&sig)? {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Ok(())
}

fn check_balance(
    client: &RpcClient,
    wallet: &Wallet,
    program_id: &Pubkey,
    table: &BsgsTable,
    expected: u64,
    label: &str,
) -> anyhow::Result<()> {
    let pda = wallet.pda(program_id);
    let account = get_laurelin_account(client, &pda)?;
    let sk = wallet.laurelin_sk_fr();
    let balance = bsgs_decrypt(&account.ciphertext, &sk, table)
        .ok_or_else(|| anyhow::anyhow!("{label}: BSGS failed (balance out of range)"))?;
    anyhow::ensure!(
        balance == expected,
        "{label}: expected {expected}, got {balance}"
    );
    eprintln!("  PASS {label}: balance = {balance}");
    Ok(())
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: integration-test <PROGRAM_ID> <PAYER_KEYPAIR> <PK_DIR>");
        std::process::exit(1);
    }
    let program_id: Pubkey = args[1].parse().context("parse program_id")?;
    let payer_path = &args[2];
    let pk_dir = PathBuf::from(&args[3]);

    let payer_bytes = std::fs::read(payer_path).context("read payer keypair")?;
    let payer_json: Vec<u8> = serde_json::from_slice(&payer_bytes).context("parse payer JSON")?;
    let payer = Keypair::from_bytes(&payer_json).context("keypair from bytes")?;

    let rpc_url = "http://127.0.0.1:8899";
    let client = new_client(rpc_url);
    let vault = vault_pda(&program_id);

    eprintln!("Program ID: {program_id}");
    eprintln!("PK dir:     {}", pk_dir.display());

    // ── Create wallets ──────────────────────────────────────────────────────
    eprintln!("\n=== Creating 4 wallets ===");
    let wallets: Vec<Wallet> = (0..4).map(|_| make_wallet()).collect();

    for (i, w) in wallets.iter().enumerate() {
        let kp = w.solana_keypair()?;
        eprintln!(
            "  Wallet {}: Solana={} Laurelin={}",
            i,
            kp.pubkey(),
            bs58::encode(coord_to_bytes(&w.laurelin_pk.x)).into_string()
        );
    }

    // ── Airdrop SOL ─────────────────────────────────────────────────────────
    eprintln!("\n=== Airdrop SOL ===");
    for (i, w) in wallets.iter().enumerate() {
        let kp = w.solana_keypair()?;
        airdrop(&client, &kp.pubkey(), 5 * LAMPORTS_PER_SOL)?;
        eprintln!("  Wallet {i}: airdropped 5 SOL");
    }

    // ── Create on-chain accounts ────────────────────────────────────────────
    eprintln!("\n=== Create on-chain accounts ===");
    for (i, w) in wallets.iter().enumerate() {
        let kp = w.solana_keypair()?;
        let pda = w.pda(&program_id);
        let mut identity = [0u8; 64];
        identity[63] = 1; // BJJ identity: (X=0, Y=1)
        let ix = create_account(
            &program_id,
            &kp.pubkey(),
            &pda,
            &w.laurelin_pk_bytes,
            &identity,
            &identity,
        );
        let sig = send_instructions(&client, &kp, &[set_compute_unit_limit(100_000), ix])?;
        eprintln!("  Wallet {i}: account created, PDA={pda}, sig={sig}");
    }

    // ── Deposits ────────────────────────────────────────────────────────────
    eprintln!("\n=== Deposits ===");
    let deposit_amounts: [u64; 4] = [1_000_000, 800_000, 600_000, 400_000];
    let deposit_pk_path = pk_dir.join("deposit_pk.bin");

    for (i, w) in wallets.iter().enumerate() {
        let amount = deposit_amounts[i];
        let kp = w.solana_keypair()?;
        let pda = w.pda(&program_id);

        let (delta_ct, r) = elgamal_encrypt(&w.laurelin_pk, amount);
        let proof = prove_deposit(
            &deposit_pk_path,
            &r,
            &w.laurelin_pk,
            &delta_ct.c1,
            &delta_ct.c2,
            amount,
        )?;

        let ix = deposit(
            &program_id,
            &kp.pubkey(),
            &pda,
            &vault,
            &proof,
            &point_to_bytes(&delta_ct.c1),
            &point_to_bytes(&delta_ct.c2),
            amount,
        );
        let sig = send_instructions(&client, &kp, &[set_compute_unit_limit(1_400_000), ix])?;
        eprintln!("  Wallet {i}: deposited {amount} lamports, sig={sig}");
    }

    // ── Verify balances after deposit ────────────────────────────────────────
    eprintln!("\n=== Balance check (post-deposit) ===");
    eprintln!("  Building BSGS table…");
    let table = BsgsTable::build();
    for (i, w) in wallets.iter().enumerate() {
        check_balance(
            &client,
            w,
            &program_id,
            &table,
            deposit_amounts[i],
            &format!("wallet {i}"),
        )?;
    }

    // ── Ring transfers ────────────────────────────────────────────────────────
    // 4 transfers covering all senderIdx×recvIdx ring slot combinations:
    //   T1: 0→2  200K  senderSlot=0, recvSlot=0
    //   T2: 0→3  150K  senderSlot=0, recvSlot=1
    //   T3: 1→2  100K  senderSlot=1, recvSlot=0
    //   T4: 1→3   80K  senderSlot=1, recvSlot=1
    //
    // After: [650K, 620K, 900K, 630K]

    eprintln!("\n=== T1: transfer 0→2, 200000 (slot 0,0) ===");
    do_transfer(&client, &program_id, &pk_dir, &wallets, 0, 2, 200_000, 0, 0, &table)?;

    let expected: [u64; 4] = [800_000, 800_000, 800_000, 400_000];
    eprintln!("\n=== Balance check (post-T1) ===");
    for (i, w) in wallets.iter().enumerate() {
        check_balance(&client, w, &program_id, &table, expected[i], &format!("wallet {i}"))?;
    }

    eprintln!("\n=== T2: transfer 0→3, 150000 (slot 0,1) ===");
    do_transfer(&client, &program_id, &pk_dir, &wallets, 0, 3, 150_000, 0, 1, &table)?;

    let expected: [u64; 4] = [650_000, 800_000, 800_000, 550_000];
    eprintln!("\n=== Balance check (post-T2) ===");
    for (i, w) in wallets.iter().enumerate() {
        check_balance(&client, w, &program_id, &table, expected[i], &format!("wallet {i}"))?;
    }

    eprintln!("\n=== T3: transfer 1→2, 100000 (slot 1,0) ===");
    do_transfer(&client, &program_id, &pk_dir, &wallets, 1, 2, 100_000, 1, 0, &table)?;

    let expected: [u64; 4] = [650_000, 700_000, 900_000, 550_000];
    eprintln!("\n=== Balance check (post-T3) ===");
    for (i, w) in wallets.iter().enumerate() {
        check_balance(&client, w, &program_id, &table, expected[i], &format!("wallet {i}"))?;
    }

    eprintln!("\n=== T4: transfer 1→3, 80000 (slot 1,1) ===");
    do_transfer(&client, &program_id, &pk_dir, &wallets, 1, 3, 80_000, 1, 1, &table)?;

    let expected: [u64; 4] = [650_000, 620_000, 900_000, 630_000];
    eprintln!("\n=== Balance check (post-T4) ===");
    for (i, w) in wallets.iter().enumerate() {
        check_balance(&client, w, &program_id, &table, expected[i], &format!("wallet {i}"))?;
    }

    // ── Withdrawals ─────────────────────────────────────────────────────────
    eprintln!("\n=== Withdrawals ===");
    let withdraw_pk_path = pk_dir.join("withdraw_pk.bin");

    for (i, w) in wallets.iter().enumerate() {
        let amount = expected[i];
        let kp = w.solana_keypair()?;
        let pda = w.pda(&program_id);
        let sk = w.laurelin_sk_fr();

        let account = get_laurelin_account(&client, &pda)?;
        let old_balance = bsgs_decrypt(&account.ciphertext, &sk, &table)
            .ok_or_else(|| anyhow::anyhow!("wallet {i}: BSGS failed before withdraw"))?;

        anyhow::ensure!(
            old_balance == amount,
            "wallet {i}: pre-withdraw balance mismatch"
        );

        let new_balance = 0u64;
        let mut rng = rand::thread_rng();
        let r_new = BJJFr::rand(&mut rng);
        let g = generator();
        let new_c1 = scalar_mul(&g, &r_new);
        let new_c2 = point_add(
            &scalar_mul(&w.laurelin_pk, &r_new),
            &scalar_mul(&g, &BJJFr::from(new_balance)),
        );

        let proof = prove_withdraw(
            &withdraw_pk_path,
            &sk,
            &r_new,
            old_balance,
            new_balance,
            &w.laurelin_pk,
            &account.ciphertext.c1,
            &account.ciphertext.c2,
            &new_c1,
            &new_c2,
            amount,
        )?;

        let ix = withdraw(
            &program_id,
            &pda,
            &vault,
            &kp.pubkey(),
            &proof,
            &point_to_bytes(&new_c1),
            &point_to_bytes(&new_c2),
            amount,
        );
        let sig = send_instructions(&client, &kp, &[set_compute_unit_limit(800_000), ix])?;
        eprintln!("  Wallet {i}: withdrew {amount} lamports, sig={sig}");
    }

    // ── Final balance check (all zero) ──────────────────────────────────────
    eprintln!("\n=== Balance check (post-withdraw, all zero) ===");
    for (i, w) in wallets.iter().enumerate() {
        check_balance(&client, w, &program_id, &table, 0, &format!("wallet {i}"))?;
    }

    eprintln!("\n=== ALL PASSED ===");
    Ok(())
}

// ── Ring transfer helper ─────────────────────────────────────────────────────

fn do_transfer(
    client: &RpcClient,
    program_id: &Pubkey,
    pk_dir: &PathBuf,
    wallets: &[Wallet],
    sender_idx: usize,
    recv_idx: usize,
    amount: u64,
    ring_sender_slot: usize,
    ring_recv_slot: usize,
    table: &BsgsTable,
) -> anyhow::Result<()> {
    let sender = &wallets[sender_idx];
    let receiver = &wallets[recv_idx];
    let sk = sender.laurelin_sk_fr();
    let kp = sender.solana_keypair()?;
    let sender_pda = sender.pda(program_id);

    // Fetch all accounts
    let all_accounts = get_all_accounts(client, program_id)?;

    let mut sender_acc: Option<LaurelinkAccount> = None;
    let mut recv_acc: Option<LaurelinkAccount> = None;
    let mut decoys: Vec<LaurelinkAccount> = Vec::new();

    let sender_x = coord_to_bytes(&sender.laurelin_pk.x);
    let recv_x = coord_to_bytes(&receiver.laurelin_pk.x);

    for acc in all_accounts {
        let x = coord_to_bytes(&acc.laurelin_pk.x);
        if x == sender_x {
            sender_acc = Some(acc);
        } else if x == recv_x {
            recv_acc = Some(acc);
        } else {
            decoys.push(acc);
        }
    }

    let sender_acc = sender_acc.ok_or_else(|| anyhow::anyhow!("sender not found on-chain"))?;
    let recv_acc = recv_acc.ok_or_else(|| anyhow::anyhow!("receiver not found on-chain"))?;
    anyhow::ensure!(decoys.len() >= 2, "need ≥ 2 decoys, found {}", decoys.len());

    let decoy_sender = &decoys[0];
    let decoy_recv = &decoys[1];

    // Decrypt sender balance
    let my_balance = bsgs_decrypt(&sender_acc.ciphertext, &sk, table)
        .ok_or_else(|| anyhow::anyhow!("BSGS: sender balance out of range"))?;
    let new_balance = my_balance - amount;

    let g = generator();
    let mut rng = rand::thread_rng();
    let r_new = BJJFr::rand(&mut rng);
    let r_decoy = BJJFr::rand(&mut rng);
    let r_t = BJJFr::rand(&mut rng);
    let r_recv = BJJFr::rand(&mut rng);

    // Ring slot assignments: real sender/receiver at the given slot
    let ring_sender_idx = ring_sender_slot;
    let ring_recv_idx = ring_recv_slot;

    let mut sender_accs: [&LaurelinkAccount; 2] = [&sender_acc, decoy_sender];
    if ring_sender_idx == 1 {
        sender_accs = [decoy_sender, &sender_acc];
    }
    let mut recv_accs: [&LaurelinkAccount; 2] = [&recv_acc, decoy_recv];
    if ring_recv_idx == 1 {
        recv_accs = [decoy_recv, &recv_acc];
    }

    // Real sender: fresh ciphertext
    let sender_new_c1_real = scalar_mul(&g, &r_new);
    let sender_new_c2_real = point_add(
        &scalar_mul(&sender.laurelin_pk, &r_new),
        &scalar_mul(&g, &BJJFr::from(new_balance)),
    );

    // Decoy sender: re-randomize
    let sender_new_c1_decoy = point_add(&decoy_sender.ciphertext.c1, &scalar_mul(&g, &r_decoy));
    let sender_new_c2_decoy = point_add(
        &decoy_sender.ciphertext.c2,
        &scalar_mul(&decoy_sender.laurelin_pk, &r_decoy),
    );

    // Real receiver: delta
    let recv_delta_c1_real = scalar_mul(&g, &r_t);
    let recv_delta_c2_real = point_add(
        &scalar_mul(&receiver.laurelin_pk, &r_t),
        &scalar_mul(&g, &BJJFr::from(amount)),
    );

    // Decoy receiver: zero delta
    let recv_delta_c1_decoy = scalar_mul(&g, &r_recv);
    let recv_delta_c2_decoy = scalar_mul(&decoy_recv.laurelin_pk, &r_recv);

    use ark_ed_on_bn254::EdwardsAffine;
    let mut sender_new_c1 = [EdwardsAffine::zero(); 2];
    let mut sender_new_c2 = [EdwardsAffine::zero(); 2];
    let mut recv_delta_c1 = [EdwardsAffine::zero(); 2];
    let mut recv_delta_c2 = [EdwardsAffine::zero(); 2];

    sender_new_c1[ring_sender_idx] = sender_new_c1_real;
    sender_new_c1[1 - ring_sender_idx] = sender_new_c1_decoy;
    sender_new_c2[ring_sender_idx] = sender_new_c2_real;
    sender_new_c2[1 - ring_sender_idx] = sender_new_c2_decoy;
    recv_delta_c1[ring_recv_idx] = recv_delta_c1_real;
    recv_delta_c1[1 - ring_recv_idx] = recv_delta_c1_decoy;
    recv_delta_c2[ring_recv_idx] = recv_delta_c2_real;
    recv_delta_c2[1 - ring_recv_idx] = recv_delta_c2_decoy;

    let transfer_pk_path = pk_dir.join("transfer_pk.bin");

    let proof = prove_transfer(
        &transfer_pk_path,
        &sk,
        &r_new,
        [r_decoy; 2],
        &r_t,
        [r_recv; 2],
        my_balance,
        amount,
        new_balance,
        ring_sender_idx,
        ring_recv_idx,
        [sender_accs[0].laurelin_pk, sender_accs[1].laurelin_pk],
        [sender_accs[0].ciphertext.c1, sender_accs[1].ciphertext.c1],
        [sender_accs[0].ciphertext.c2, sender_accs[1].ciphertext.c2],
        [sender_new_c1[0], sender_new_c1[1]],
        [sender_new_c2[0], sender_new_c2[1]],
        [recv_accs[0].laurelin_pk, recv_accs[1].laurelin_pk],
        [recv_delta_c1[0], recv_delta_c1[1]],
        [recv_delta_c2[0], recv_delta_c2[1]],
    )?;

    let ix = ring_transfer(
        program_id,
        &sender_accs[0].pubkey,
        &sender_accs[1].pubkey,
        &recv_accs[0].pubkey,
        &recv_accs[1].pubkey,
        &proof,
        &point_to_bytes(&sender_new_c1[0]),
        &point_to_bytes(&sender_new_c2[0]),
        &point_to_bytes(&sender_new_c1[1]),
        &point_to_bytes(&sender_new_c2[1]),
        &point_to_bytes(&recv_delta_c1[0]),
        &point_to_bytes(&recv_delta_c2[0]),
        &point_to_bytes(&recv_delta_c1[1]),
        &point_to_bytes(&recv_delta_c2[1]),
    );

    let sig = send_instructions(client, &kp, &[set_compute_unit_limit(1_400_000), ix])?;
    eprintln!("  Transfer {sender_idx}→{recv_idx} ({amount} lamports): sig={sig}");
    Ok(())
}
