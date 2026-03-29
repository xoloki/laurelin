//! Native SOL staking commands: create, list, delegate, deactivate, withdraw.

use solana_account_decoder::UiAccountEncoding;
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
use solana_client::rpc_filter::{Memcmp, MemcmpEncodedBytes, RpcFilterType};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    stake::{
        instruction as stake_ix,
        program::id as stake_program_id,
        state::{Authorized, Lockup},
    },
};

use crate::{
    config::ResolvedConfig,
    rpc::{new_client, send_instructions, send_instructions_signed},
    wallet::Wallet,
};

// ── stake create ──────────────────────────────────────────────────────────────

pub fn run_create(wallet: &Wallet, cfg: &ResolvedConfig, lamports: u64) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let authority = kp.pubkey();

    // Generate a fresh keypair for the stake account
    let stake_kp = Keypair::new();
    let stake_pubkey = stake_kp.pubkey();

    let authorized = Authorized {
        staker: authority,
        withdrawer: authority,
    };

    let ixs = stake_ix::create_account(
        &authority,
        &stake_pubkey,
        &authorized,
        &Lockup::default(),
        lamports,
    );

    let sig = send_instructions_signed(&client, &kp, &[&stake_kp], &ixs)?;
    println!("Stake account created: {stake_pubkey}");
    println!("  Staker / withdrawer: {authority}");
    println!("  Funded: {lamports} lamports");
    println!("Signature: {sig}");
    Ok(())
}

// ── stake list ────────────────────────────────────────────────────────────────

/// Staker authority in a stake account's Meta is at byte offset 12:
///   4 bytes  enum variant (1 = Initialized, 2 = Stake)
///   8 bytes  Meta.rent_exempt_reserve
///  32 bytes  Meta.authorized.staker  ← offset 12
pub fn run_list(pubkey: &solana_sdk::pubkey::Pubkey, cfg: &ResolvedConfig) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let staker = *pubkey;

    let config = RpcProgramAccountsConfig {
        filters: Some(vec![RpcFilterType::Memcmp(Memcmp {
            offset: 12,
            bytes: MemcmpEncodedBytes::Bytes(staker.to_bytes().to_vec()),
            encoding: None,
        })]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            commitment: Some(CommitmentConfig::confirmed()),
            ..Default::default()
        },
        ..Default::default()
    };

    let accounts = client
        .get_program_accounts_with_config(&stake_program_id(), config)
        .map_err(|e| anyhow::anyhow!("getProgramAccounts(stake): {e}"))?;

    if accounts.is_empty() {
        println!("No stake accounts found.");
        return Ok(());
    }

    println!(
        "{:<44}  {:>15}  {}",
        "Stake Account", "Balance (SOL)", "State"
    );
    println!("{}", "-".repeat(80));

    for (pubkey, account) in &accounts {
        let sol = account.lamports as f64 / 1e9;
        let state_str = client
            .get_stake_activation(*pubkey, None)
            .map(|a| format!("{:?}", a.state))
            .unwrap_or_else(|_| "unknown".to_owned());
        println!("{pubkey}  {:>15.9}  {state_str}", sol);
    }
    Ok(())
}

// ── stake delegate ────────────────────────────────────────────────────────────

pub fn run_delegate(
    wallet: &Wallet,
    cfg: &ResolvedConfig,
    stake_str: &str,
    vote_str: &str,
) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let stake_pubkey: Pubkey = stake_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid stake account pubkey: {stake_str}"))?;
    let vote_pubkey: Pubkey = vote_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid vote account pubkey: {vote_str}"))?;

    let ix = stake_ix::delegate_stake(&stake_pubkey, &kp.pubkey(), &vote_pubkey);
    let sig = send_instructions(&client, &kp, &[ix])?;
    println!("Delegated {stake_pubkey} to validator {vote_pubkey}");
    println!("Signature: {sig}");
    Ok(())
}

// ── stake deactivate ──────────────────────────────────────────────────────────

pub fn run_deactivate(
    wallet: &Wallet,
    cfg: &ResolvedConfig,
    stake_str: &str,
) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let stake_pubkey: Pubkey = stake_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid stake account pubkey: {stake_str}"))?;

    let ix = stake_ix::deactivate_stake(&stake_pubkey, &kp.pubkey());
    let sig = send_instructions(&client, &kp, &[ix])?;
    println!("Deactivated stake account {stake_pubkey}");
    println!("Signature: {sig}");
    Ok(())
}

// ── stake withdraw ────────────────────────────────────────────────────────────

pub fn run_withdraw(
    wallet: &Wallet,
    cfg: &ResolvedConfig,
    stake_str: &str,
    lamports: u64,
) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let stake_pubkey: Pubkey = stake_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid stake account pubkey: {stake_str}"))?;

    let ix = stake_ix::withdraw(
        &stake_pubkey,
        &kp.pubkey(),
        &kp.pubkey(), // destination: our SOL account
        lamports,
        None, // custodian (lockup)
    );
    let sig = send_instructions(&client, &kp, &[ix])?;
    println!(
        "Withdrew {lamports} lamports from {stake_pubkey} to {}",
        kp.pubkey()
    );
    println!("Signature: {sig}");
    Ok(())
}
