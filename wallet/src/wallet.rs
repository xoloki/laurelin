//! Wallet file: ~/.laurelin/wallet.json
//!
//! Stores the Solana keypair (64 bytes) and BN254 secret key (32-byte hex).
//! The BN254 public key is derived on load; it is never stored to disk.

use std::path::{Path, PathBuf};

use anyhow::Context;
use ark_bn254::{Fr, G1Affine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::bn254::{fr_from_bytes, g1_to_bytes, generator, scalar_mul};
use crate::config::laurelin_dir;

/// On-disk wallet file format.
#[derive(Serialize, Deserialize)]
struct WalletFile {
    version: u32,
    /// 64-byte Solana keypair (first 32 = secret, last 32 = public).
    solana_keypair: Vec<u8>,
    /// 32-byte BN254 scalar, hex-encoded.
    bn254_secret_key: String,
}

/// Loaded wallet with derived public key.
pub struct Wallet {
    pub solana_keypair: Zeroizing<[u8; 64]>,
    pub bn254_sk: Zeroizing<[u8; 32]>,
    pub bn254_pk: G1Affine,
    /// BN254 public key as 64-byte X||Y (for on-chain use).
    pub bn254_pk_bytes: [u8; 64],
}

impl Wallet {
    /// Load from a JSON file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("read wallet {}", path.display()))?;
        let wf: WalletFile = serde_json::from_str(&data)
            .with_context(|| format!("parse wallet {}", path.display()))?;

        anyhow::ensure!(wf.version == 1, "unsupported wallet version {}", wf.version);
        anyhow::ensure!(
            wf.solana_keypair.len() == 64,
            "solana_keypair must be 64 bytes"
        );

        let mut kp = Zeroizing::new([0u8; 64]);
        kp.copy_from_slice(&wf.solana_keypair);

        let sk_bytes: [u8; 32] = hex::decode(&wf.bn254_secret_key)
            .context("decode bn254_secret_key hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bn254_secret_key must be 32 bytes"))?;
        let sk_bytes = Zeroizing::new(sk_bytes);

        let sk: Fr = fr_from_bytes(&sk_bytes);
        let g = generator();
        let pk: G1Affine = scalar_mul(&g, &sk);
        let pk_bytes = g1_to_bytes(&pk);

        Ok(Wallet {
            solana_keypair: kp,
            bn254_sk: sk_bytes,
            bn254_pk: pk,
            bn254_pk_bytes: pk_bytes,
        })
    }

    /// Save a new wallet to a JSON file, creating parent directories as needed.
    pub fn save(path: &Path, solana_keypair: &[u8; 64], bn254_sk: &[u8; 32]) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
        let wf = WalletFile {
            version: 1,
            solana_keypair: solana_keypair.to_vec(),
            bn254_secret_key: hex::encode(bn254_sk),
        };
        let data = serde_json::to_string_pretty(&wf)?;
        std::fs::write(path, data).with_context(|| format!("write wallet {}", path.display()))?;
        Ok(())
    }

    /// Return the Solana keypair as a `solana_sdk::signature::Keypair`.
    pub fn solana_keypair(&self) -> anyhow::Result<solana_sdk::signature::Keypair> {
        solana_sdk::signature::Keypair::from_bytes(&*self.solana_keypair)
            .map_err(|e| anyhow::anyhow!("invalid solana keypair: {}", e))
    }

    /// Return the BN254 secret key as Fr.
    pub fn bn254_sk_fr(&self) -> Fr {
        fr_from_bytes(&*self.bn254_sk)
    }

    /// Compute the PDA for this wallet's BN254 pubkey under a given program.
    pub fn pda(&self, program_id: &solana_sdk::pubkey::Pubkey) -> solana_sdk::pubkey::Pubkey {
        let (pda, _) = solana_sdk::pubkey::Pubkey::find_program_address(
            &[&self.bn254_pk_bytes[..32]],
            program_id,
        );
        pda
    }
}

/// Return the default wallet file path: ~/.laurelin/wallet.json.
pub fn default_wallet_path() -> PathBuf {
    laurelin_dir().join("wallet.json")
}
