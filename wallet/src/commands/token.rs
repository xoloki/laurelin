//! SPL token commands: `token-list`, `token-send`, `token-close`.

use solana_account_decoder::UiAccountEncoding;
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
use solana_client::rpc_filter::{Memcmp, MemcmpEncodedBytes, RpcFilterType};
use solana_sdk::{
    commitment_config::CommitmentConfig, program_pack::Pack, pubkey::Pubkey, signature::Signer,
};
use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account_idempotent,
};
use spl_token::state::{Account as TokenAccount, Mint};

use crate::{
    config::ResolvedConfig,
    rpc::{new_client, send_instructions},
    wallet::Wallet,
};

// ── token-list ────────────────────────────────────────────────────────────────

pub fn run_list(pubkey: &solana_sdk::pubkey::Pubkey, cfg: &ResolvedConfig) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let owner = *pubkey;

    // getProgramAccounts: token accounts owned by us (owner field at offset 32)
    #[allow(deprecated)]
    let config = RpcProgramAccountsConfig {
        filters: Some(vec![
            RpcFilterType::DataSize(TokenAccount::LEN as u64),
            RpcFilterType::Memcmp(Memcmp {
                offset: 32,
                bytes: MemcmpEncodedBytes::Bytes(owner.to_bytes().to_vec()),
                encoding: None,
            }),
        ]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            commitment: Some(CommitmentConfig::confirmed()),
            ..Default::default()
        },
        ..Default::default()
    };

    let accounts = client
        .get_program_accounts_with_config(&spl_token::id(), config)
        .map_err(|e| anyhow::anyhow!("getProgramAccounts: {e}"))?;

    if accounts.is_empty() {
        println!("No SPL token accounts found.");
        return Ok(());
    }

    println!("{:<44}  {:>20}  {}", "Mint", "Amount", "Token Account");
    println!("{}", "-".repeat(110));
    for (ata_pubkey, account) in &accounts {
        let ta = TokenAccount::unpack(&account.data)
            .map_err(|e| anyhow::anyhow!("unpack token account {ata_pubkey}: {e}"))?;

        // Fetch mint to get decimals
        let decimals = client
            .get_account_data(&ta.mint)
            .ok()
            .and_then(|d| Mint::unpack(&d).ok())
            .map(|m| m.decimals)
            .unwrap_or(0);

        let display = format_amount(ta.amount, decimals);
        println!("{:<44}  {:>20}  {ata_pubkey}", ta.mint, display);
    }
    Ok(())
}

// ── token-send ────────────────────────────────────────────────────────────────

pub fn run_send(
    wallet: &Wallet,
    cfg: &ResolvedConfig,
    mint_str: &str,
    amount: u64,
    to: &str,
) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let mint: Pubkey = mint_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid mint pubkey: {mint_str}"))?;
    let recipient: Pubkey = to
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid recipient pubkey: {to}"))?;

    // Fetch mint decimals
    let mint_data = client
        .get_account_data(&mint)
        .map_err(|e| anyhow::anyhow!("fetch mint {mint}: {e}"))?;
    let mint_info =
        Mint::unpack(&mint_data).map_err(|e| anyhow::anyhow!("unpack mint {mint}: {e}"))?;

    let source = get_associated_token_address(&kp.pubkey(), &mint);
    let dest = get_associated_token_address(&recipient, &mint);

    let ixs = vec![
        // create dest ATA if it doesn't exist (idempotent = no-op if already present)
        create_associated_token_account_idempotent(
            &kp.pubkey(),
            &recipient,
            &mint,
            &spl_token::id(),
        ),
        spl_token::instruction::transfer_checked(
            &spl_token::id(),
            &source,
            &mint,
            &dest,
            &kp.pubkey(),
            &[],
            amount,
            mint_info.decimals,
        )
        .map_err(|e| anyhow::anyhow!("build transfer_checked: {e}"))?,
    ];

    let sig = send_instructions(&client, &kp, &ixs)?;
    let display = format_amount(amount, mint_info.decimals);
    println!("Sent {display} tokens (mint {mint}) to {recipient}");
    println!("Signature: {sig}");
    Ok(())
}

// ── token-close ───────────────────────────────────────────────────────────────

pub fn run_close(wallet: &Wallet, cfg: &ResolvedConfig, mint_str: &str) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);
    let kp = wallet.solana_keypair()?;
    let mint: Pubkey = mint_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid mint pubkey: {mint_str}"))?;

    let ata = get_associated_token_address(&kp.pubkey(), &mint);

    // Verify zero balance so the error is clear
    let ata_data = client
        .get_account_data(&ata)
        .map_err(|e| anyhow::anyhow!("fetch token account {ata}: {e}"))?;
    let ta = TokenAccount::unpack(&ata_data)
        .map_err(|e| anyhow::anyhow!("unpack token account {ata}: {e}"))?;
    anyhow::ensure!(
        ta.amount == 0,
        "token account {ata} still holds {} tokens — transfer them out first",
        ta.amount
    );

    let ix = spl_token::instruction::close_account(
        &spl_token::id(),
        &ata,
        &kp.pubkey(), // reclaim rent to our Solana account
        &kp.pubkey(),
        &[],
    )
    .map_err(|e| anyhow::anyhow!("build close_account: {e}"))?;

    let sig = send_instructions(&client, &kp, &[ix])?;
    println!(
        "Closed token account {ata} (mint {mint}); rent returned to {}",
        kp.pubkey()
    );
    println!("Signature: {sig}");
    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn format_amount(amount: u64, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let divisor = 10u64.pow(decimals as u32);
    let whole = amount / divisor;
    let frac = amount % divisor;
    format!("{whole}.{frac:0>width$}", width = decimals as usize)
}
