//! `transfer <lamports> --to <laurelin-pubkey>` — confidential ring transfer.
//!
//! Auto-discovers decoys from on-chain accounts.  Requires ≥ 4 accounts
//! (self + receiver + 2 decoys).  SenderIdx and RecvIdx are randomised for
//! privacy.

use ark_bn254::{Fr, G1Affine};
use ark_std::UniformRand;
use solana_sdk::pubkey::Pubkey;

use crate::{
    bn254::{bsgs_decrypt, g1_to_bytes, generator, point_add, scalar_mul, BsgsTable, MAX_CONFIDENTIAL_LAMPORTS},
    config::ResolvedConfig,
    instructions::{ring_transfer, set_compute_unit_limit},
    prover::prove_transfer,
    rpc::{
        get_all_accounts, get_laurelin_account, new_client, send_instructions, LaurelinkAccount,
    },
    wallet::Wallet,
};

pub fn run(
    wallet: &Wallet,
    cfg: &ResolvedConfig,
    lamports: u64,
    to: &str,
) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let program_id: Pubkey = cfg.program_id.parse()?;
    let my_pda = wallet.pda(&program_id);
    let sk = wallet.laurelin_sk_fr();

    anyhow::ensure!(
        lamports <= MAX_CONFIDENTIAL_LAMPORTS,
        "amount {} lamports exceeds the maximum confidential balance ({} lamports, ~4.3 SOL)",
        lamports,
        MAX_CONFIDENTIAL_LAMPORTS,
    );

    // Parse receiver Laurelin pubkey (base58-encoded 32-byte X coordinate)
    let recv_pk_x: [u8; 32] = bs58::decode(to)
        .into_vec()
        .map_err(|_| anyhow::anyhow!("--to must be a valid Laurelin pubkey (base58)"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("--to Laurelin pubkey must be exactly 32 bytes"))?;

    // Get all accounts and find receiver + decoys
    let all_accounts = get_all_accounts(&client, &program_id)?;

    // Split into: self, receiver, others
    let mut receiver_acc: Option<LaurelinkAccount> = None;
    let mut others: Vec<LaurelinkAccount> = Vec::new();

    for acc in all_accounts {
        use crate::bn254::fq_to_bytes;
        let x_bytes = fq_to_bytes(&acc.laurelin_pk.x);
        if x_bytes == wallet.laurelin_pk_bytes[..32] {
            // this is self — we'll fetch fresh below
        } else if x_bytes == recv_pk_x {
            receiver_acc = Some(acc);
        } else {
            others.push(acc);
        }
    }

    let receiver_acc = receiver_acc.ok_or_else(|| {
        anyhow::anyhow!("receiver not found on-chain (have they created an account?)")
    })?;

    anyhow::ensure!(
        others.len() >= 2,
        "need at least 2 decoy accounts on-chain, found {} (total accounts ≥ 4 required)",
        others.len()
    );

    // Fetch own account
    let my_account = get_laurelin_account(&client, &my_pda)?;

    // Decrypt own balance to verify sufficient funds
    eprintln!("Building BSGS table…");
    let table = BsgsTable::build();
    let my_balance = bsgs_decrypt(&my_account.ciphertext, &sk, &table)
        .ok_or_else(|| anyhow::anyhow!("BSGS: own balance out of range"))?;

    anyhow::ensure!(
        lamports <= my_balance,
        "insufficient confidential balance: have {my_balance}, want {lamports}"
    );

    // Pick decoys randomly
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    let decoy_sender = others.choose(&mut rng).unwrap().clone();
    let remaining: Vec<_> = others
        .iter()
        .filter(|a| a.pubkey != decoy_sender.pubkey)
        .collect();
    let decoy_recv = remaining
        .choose(&mut rng)
        .ok_or_else(|| anyhow::anyhow!("not enough decoys"))?;

    // Randomly assign senderIdx and recvIdx for privacy
    let sender_idx: usize = rand::random::<bool>() as usize;
    let recv_idx: usize = rand::random::<bool>() as usize;

    // Build sender ring: slots [0] and [1]
    // senders[sender_idx] = self, senders[1-sender_idx] = decoy
    let mut sender_accs: [&LaurelinkAccount; 2] = [&my_account, &decoy_sender];
    if sender_idx == 1 {
        sender_accs = [&decoy_sender, &my_account];
    }

    // Build receiver ring: slots [0] and [1]
    let mut recv_accs: [&LaurelinkAccount; 2] = [&receiver_acc, decoy_recv];
    if recv_idx == 1 {
        recv_accs = [decoy_recv, &receiver_acc];
    }

    let new_balance = my_balance - lamports;
    let g = generator();

    // Randomness
    let r_new = Fr::rand(&mut rng);
    let r_decoy = Fr::rand(&mut rng);
    let r_t = Fr::rand(&mut rng);
    let r_recv = Fr::rand(&mut rng);

    // Real sender: fresh ciphertext encrypting new_balance
    let sender_new_c1_real = scalar_mul(&g, &r_new);
    let sender_new_c2_real = point_add(
        &scalar_mul(&my_account.laurelin_pk, &r_new),
        &scalar_mul(&g, &Fr::from(new_balance)),
    );

    // Decoy sender: re-randomize (additive blinding, same balance)
    let decoy_old_c1 = decoy_sender.ciphertext.c1;
    let decoy_old_c2 = decoy_sender.ciphertext.c2;
    let sender_new_c1_decoy = point_add(&decoy_old_c1, &scalar_mul(&g, &r_decoy));
    let sender_new_c2_decoy = point_add(
        &decoy_old_c2,
        &scalar_mul(&decoy_sender.laurelin_pk, &r_decoy),
    );

    // Real receiver: delta ciphertext encrypting amount
    let recv_delta_c1_real = scalar_mul(&g, &r_t);
    let recv_delta_c2_real = point_add(
        &scalar_mul(&receiver_acc.laurelin_pk, &r_t),
        &scalar_mul(&g, &Fr::from(lamports)),
    );

    // Decoy receiver: zero delta (re-randomized)
    let recv_delta_c1_decoy = scalar_mul(&g, &r_recv);
    let recv_delta_c2_decoy = scalar_mul(&decoy_recv.laurelin_pk, &r_recv);

    // Map to ring slots
    let mut sender_new_c1 = [G1Affine::default(); 2];
    let mut sender_new_c2 = [G1Affine::default(); 2];
    let mut recv_delta_c1 = [G1Affine::default(); 2];
    let mut recv_delta_c2 = [G1Affine::default(); 2];

    sender_new_c1[sender_idx] = sender_new_c1_real;
    sender_new_c2[sender_idx] = sender_new_c2_real;
    sender_new_c1[1 - sender_idx] = sender_new_c1_decoy;
    sender_new_c2[1 - sender_idx] = sender_new_c2_decoy;
    recv_delta_c1[recv_idx] = recv_delta_c1_real;
    recv_delta_c2[recv_idx] = recv_delta_c2_real;
    recv_delta_c1[1 - recv_idx] = recv_delta_c1_decoy;
    recv_delta_c2[1 - recv_idx] = recv_delta_c2_decoy;

    let pk_path = cfg.pk_dir.join("transfer_pk.bin");
    let pk_path_str = pk_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("pk_dir path is not valid UTF-8"))?;

    eprintln!(
        "Proving ring transfer ({lamports} lamports, senderIdx={sender_idx} recvIdx={recv_idx})…"
    );
    let proof = prove_transfer(
        &cfg.prover,
        pk_path_str,
        &sk,
        &r_new,
        &r_decoy,
        &r_t,
        &r_recv,
        my_balance,
        lamports,
        new_balance,
        sender_idx,
        recv_idx,
        [&sender_accs[0].laurelin_pk, &sender_accs[1].laurelin_pk],
        [&sender_accs[0].ciphertext.c1, &sender_accs[1].ciphertext.c1],
        [&sender_accs[0].ciphertext.c2, &sender_accs[1].ciphertext.c2],
        [&sender_new_c1[0], &sender_new_c1[1]],
        [&sender_new_c2[0], &sender_new_c2[1]],
        [&recv_accs[0].laurelin_pk, &recv_accs[1].laurelin_pk],
        [&recv_delta_c1[0], &recv_delta_c1[1]],
        [&recv_delta_c2[0], &recv_delta_c2[1]],
    )?;

    let ix = ring_transfer(
        &program_id,
        &sender_accs[0].pubkey,
        &sender_accs[1].pubkey,
        &recv_accs[0].pubkey,
        &recv_accs[1].pubkey,
        &proof,
        &g1_to_bytes(&sender_new_c1[0]),
        &g1_to_bytes(&sender_new_c2[0]),
        &g1_to_bytes(&sender_new_c1[1]),
        &g1_to_bytes(&sender_new_c2[1]),
        &g1_to_bytes(&recv_delta_c1[0]),
        &g1_to_bytes(&recv_delta_c2[0]),
        &g1_to_bytes(&recv_delta_c1[1]),
        &g1_to_bytes(&recv_delta_c2[1]),
    );

    let sig = send_instructions(&client, &kp, &[set_compute_unit_limit(1_400_000), ix])?;
    println!("Transfer confirmed. Signature: {sig}");
    Ok(())
}
