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
    Init,

    /// Show Solana pubkey and BN254 pubkey X coordinate
    Pubkey {
        /// Also show the Laurelin PDA
        #[arg(long)]
        verbose: bool,
    },

    /// Show SOL balance and confidential (encrypted) balance
    Balance,

    /// List all Laurelin accounts on-chain
    Accounts,

    /// Register this wallet's PDA on-chain
    CreateAccount,

    /// Deposit SOL lamports into the confidential balance
    Deposit { lamports: u64 },

    /// Confidential ring transfer to another account
    Transfer {
        lamports: u64,
        /// Recipient's BN254 pubkey X coordinate (32-byte hex)
        #[arg(long)]
        to: String,
    },

    /// Withdraw lamports from the confidential balance to SOL
    Withdraw { lamports: u64 },

    /// Manage config file settings
    #[command(subcommand)]
    Config(ConfigCmd),
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
    if let Commands::Init = cli.command {
        return commands::init::run(&wallet_path);
    }

    // All other commands need a loaded config and wallet
    let cfg_file = Config::load(&config_path)?;
    let cfg = ResolvedConfig::resolve(&cfg_file, cli.url.as_deref(), cli.program.as_deref());

    match cli.command {
        Commands::Pubkey { verbose } => {
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

        Commands::Balance => {
            let cfg = cfg?;
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

        Commands::Init | Commands::Config(_) => unreachable!(),
    }
}
