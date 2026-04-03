mod bjj;
mod bn254;
mod commands;
mod config;
mod instructions;
mod prover;
mod rpc;
mod wallet;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::{
    config::{default_config_path, Config, ResolvedConfig},
    wallet::{default_wallet_path, Wallet},
};

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "laurelin-wallet",
    about = "Solana wallet with confidential transfers via Laurelin"
)]
struct Cli {
    /// Solana RPC endpoint (overrides config)
    #[arg(long, global = true)]
    url: Option<String>,

    /// Laurelin program ID (overrides config)
    #[arg(long, global = true)]
    program: Option<String>,

    /// Wallet file path (default: ~/.laurelin/wallet.json)
    #[arg(long, global = true)]
    wallet: Option<PathBuf>,

    /// Config file path (default: ~/.laurelin/config.json)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Solana + BN254 keypair and save to the wallet file
    Init {
        /// Store keys in plaintext (no password). For testing only.
        #[arg(long)]
        insecure: bool,
    },

    /// Show Solana pubkey and Laurelin pubkey
    Pubkey {
        /// Also show the Laurelin PDA
        #[arg(long)]
        verbose: bool,
        /// Show only the Solana pubkey (no password needed)
        #[arg(long)]
        sol: bool,
    },

    /// Show SOL balance and confidential (encrypted) balance
    Balance {
        /// Show only the SOL balance (no password needed)
        #[arg(long)]
        sol: bool,
    },

    /// List all Laurelin accounts on-chain
    Accounts,

    /// Register this wallet's PDA on-chain
    CreateAccount,

    /// Deposit SOL lamports into the confidential balance
    Deposit { lamports: u64 },

    /// Confidential ring transfer to another account
    Transfer {
        lamports: u64,
        /// Recipient's Laurelin pubkey (base58, from `pubkey` command)
        #[arg(long)]
        to: String,
    },

    /// Withdraw lamports from the confidential balance to SOL
    Withdraw { lamports: u64 },

    /// Send SOL to another address
    Send {
        lamports: u64,
        /// Recipient's Solana pubkey (base58)
        #[arg(long)]
        to: String,
    },

    /// List SPL token balances
    TokenList,

    /// Send SPL tokens to another address
    TokenSend {
        /// Token mint address (base58)
        #[arg(long)]
        mint: String,
        /// Amount in base units (smallest denomination)
        amount: u64,
        /// Recipient's Solana pubkey (base58)
        #[arg(long)]
        to: String,
    },

    /// Close an empty SPL token account and reclaim rent
    TokenClose {
        /// Token mint address (base58)
        #[arg(long)]
        mint: String,
    },

    /// Native SOL staking operations
    #[command(subcommand)]
    Stake(StakeCmd),

    /// Show recent transaction history
    History {
        /// Number of transactions to show (default: 20)
        #[arg(long, default_value = "20")]
        limit: usize,
    },

    /// Manage config file settings
    #[command(subcommand)]
    Config(ConfigCmd),
}

#[derive(Subcommand)]
enum StakeCmd {
    /// Create and fund a new stake account
    Create { lamports: u64 },
    /// List your stake accounts
    List,
    /// Delegate a stake account to a validator
    Delegate {
        /// Stake account pubkey (base58)
        stake: String,
        /// Validator vote account pubkey (base58)
        vote: String,
    },
    /// Begin deactivating a stake account
    Deactivate {
        /// Stake account pubkey (base58)
        stake: String,
    },
    /// Withdraw lamports from a deactivated stake account
    Withdraw {
        /// Stake account pubkey (base58)
        stake: String,
        lamports: u64,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Set the Laurelin program ID
    SetProgram { id: String },
    /// Set the Solana RPC URL
    SetUrl { url: String },
    /// Set the directory containing proving key files
    SetPkDir { path: String },
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config_path = cli.config.unwrap_or_else(default_config_path);
    let wallet_path = cli.wallet.unwrap_or_else(default_wallet_path);

    // Config subcommands don't need a wallet or resolved config
    if let Commands::Config(ref cmd) = cli.command {
        return match cmd {
            ConfigCmd::SetProgram { id } => commands::config::set_program(&config_path, id),
            ConfigCmd::SetUrl { url } => commands::config::set_url(&config_path, url),
            ConfigCmd::SetPkDir { path } => commands::config::set_pk_dir(&config_path, path),
        };
    }

    // Init doesn't need a pre-existing wallet or program
    if let Commands::Init { insecure } = cli.command {
        return commands::init::run(&wallet_path, insecure);
    }

    // All other commands need a loaded config and wallet
    let cfg_file = Config::load(&config_path)?;
    let cfg = ResolvedConfig::resolve(&cfg_file, cli.url.as_deref(), cli.program.as_deref());

    match cli.command {
        Commands::Pubkey { verbose, sol } => {
            if sol {
                let pubkey = Wallet::load_pubkey(&wallet_path)?;
                println!("{pubkey}");
                return Ok(());
            }
            // pubkey doesn't strictly need program_id unless --verbose
            let cfg = if verbose {
                cfg?
            } else {
                // Build a dummy resolved config so we can skip the program_id requirement
                ResolvedConfig {
                    program_id: cfg_file.program_id.clone().unwrap_or_default(),
                    rpc_url: cli
                        .url
                        .as_deref()
                        .map(str::to_owned)
                        .or_else(|| cfg_file.rpc_url.clone())
                        .unwrap_or_else(|| config::DEFAULT_RPC_URL.to_owned()),
                    pk_dir: cfg_file
                        .pk_dir
                        .as_deref()
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| std::path::PathBuf::from(".")),
                }
            };
            let wallet = Wallet::load(&wallet_path)?;
            commands::pubkey::run(&wallet, &cfg, verbose)
        }

        Commands::Balance { sol } => {
            let cfg = cfg?;
            if sol {
                let pubkey = Wallet::load_pubkey(&wallet_path)?;
                let client = rpc::new_client(&cfg.rpc_url);
                let lamports = rpc::get_sol_balance(&client, &pubkey)?;
                println!(
                    "SOL balance: {} lamports  ({:.9} SOL)",
                    lamports,
                    lamports as f64 / 1e9
                );
                return Ok(());
            }
            let wallet = Wallet::load(&wallet_path)?;
            commands::balance::run(&wallet, &cfg)
        }

        Commands::Accounts => {
            let cfg = cfg?;
            commands::accounts::run(&cfg)
        }

        Commands::CreateAccount => {
            let cfg = cfg?;
            let wallet = Wallet::load(&wallet_path)?;
            commands::create_account::run(&wallet, &cfg)
        }

        Commands::Deposit { lamports } => {
            let cfg = cfg?;
            let wallet = Wallet::load(&wallet_path)?;
            commands::deposit::run(&wallet, &cfg, lamports)
        }

        Commands::Transfer { lamports, to } => {
            let cfg = cfg?;
            let wallet = Wallet::load(&wallet_path)?;
            commands::transfer::run(&wallet, &cfg, lamports, &to)
        }

        Commands::Withdraw { lamports } => {
            let cfg = cfg?;
            let wallet = Wallet::load(&wallet_path)?;
            commands::withdraw::run(&wallet, &cfg, lamports)
        }

        Commands::Send { lamports, to } => {
            let cfg = cfg?;
            let wallet = Wallet::load(&wallet_path)?;
            commands::send::run(&wallet, &cfg, lamports, &to)
        }

        Commands::TokenList => {
            let cfg = cfg?;
            let pubkey = Wallet::load_pubkey(&wallet_path)?;
            commands::token::run_list(&pubkey, &cfg)
        }

        Commands::TokenSend { mint, amount, to } => {
            let cfg = cfg?;
            let wallet = Wallet::load(&wallet_path)?;
            commands::token::run_send(&wallet, &cfg, &mint, amount, &to)
        }

        Commands::TokenClose { mint } => {
            let cfg = cfg?;
            let wallet = Wallet::load(&wallet_path)?;
            commands::token::run_close(&wallet, &cfg, &mint)
        }

        Commands::Stake(stake_cmd) => {
            let cfg = cfg?;
            match stake_cmd {
                StakeCmd::List => {
                    let pubkey = Wallet::load_pubkey(&wallet_path)?;
                    commands::stake::run_list(&pubkey, &cfg)
                }
                _ => {
                    let wallet = Wallet::load(&wallet_path)?;
                    match stake_cmd {
                        StakeCmd::Create { lamports } => {
                            commands::stake::run_create(&wallet, &cfg, lamports)
                        }
                        StakeCmd::Delegate { stake, vote } => {
                            commands::stake::run_delegate(&wallet, &cfg, &stake, &vote)
                        }
                        StakeCmd::Deactivate { stake } => {
                            commands::stake::run_deactivate(&wallet, &cfg, &stake)
                        }
                        StakeCmd::Withdraw { stake, lamports } => {
                            commands::stake::run_withdraw(&wallet, &cfg, &stake, lamports)
                        }
                        StakeCmd::List => unreachable!(),
                    }
                }
            }
        }

        Commands::History { limit } => {
            let cfg = cfg?;
            let pubkey = Wallet::load_pubkey(&wallet_path)?;
            commands::history::run(&pubkey, &cfg, limit)
        }

        Commands::Init { .. } | Commands::Config(_) => unreachable!(),
    }
}
