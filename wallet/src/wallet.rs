//! Wallet file: ~/.laurelin/wallet.json
//!
//! Two on-disk formats:
//!
//! **Version 1** (plaintext / `--insecure`): stores keys in the clear.  For
//! testing only.
//!
//! **Version 2** (encrypted, default): derives a 256-bit AES key from the
//! user's password using Argon2id (m=256 MB, t=4, p=2), then encrypts
//! `solana_sk (32B)` and `laurelin_sk (32B)` separately with AES-256-GCM.
//! The Solana pubkey is stored unencrypted so read-only operations never
//! need to prompt for a password.
//!
//! All in-memory key material lives in `Zeroizing` wrappers and is
//! overwritten with zeros on drop.

use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::Context;
use argon2::{Algorithm, Argon2, Params, Version};
use ark_bn254::{Fr, G1Affine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{SeedDerivable, Signer},
};
use zeroize::{Zeroize, Zeroizing};

use crate::bn254::{fr_from_bytes, g1_to_bytes, generator, scalar_mul};
use crate::config::laurelin_dir;

// ── Argon2id / AES-GCM constants ─────────────────────────────────────────────

/// Argon2id memory cost: 256 MB (in kibibytes).
const ARGON2_M_COST: u32 = 256 * 1024;
/// Argon2id time cost (iterations).
const ARGON2_T_COST: u32 = 4;
/// Argon2id parallelism.
const ARGON2_P_COST: u32 = 2;
const ARGON2_SALT_LEN: usize = 16;
const AES_KEY_LEN: usize = 32;
const AES_NONCE_LEN: usize = 12;

// ── On-disk file formats ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

/// Version 1: plaintext (--insecure / backward compat).
#[derive(Serialize, Deserialize)]
struct WalletV1 {
    version: u32,        // = 1
    solana_sk: String,   // 32-byte Ed25519 seed, hex-encoded
    laurelin_sk: String, // 32-byte BN254 scalar, hex-encoded
}

/// Version 2: AES-256-GCM encrypted with Argon2id key derivation.
///
/// One Argon2 derivation (single salt → single key); each 32-byte secret key
/// encrypted with its own nonce.  `solana_pubkey` is stored in plaintext so
/// read-only operations (history, token list, stake list, etc.) never need to
/// prompt for a password.
#[derive(Serialize, Deserialize)]
struct WalletV2 {
    version: u32, // = 2
    /// Solana pubkey, base58-encoded.  Public information; stored unencrypted.
    #[serde(default)]
    solana_pubkey: String,
    /// 16-byte Argon2 salt, hex-encoded.
    argon2_salt: String,
    /// 12-byte nonce for the Solana sk ciphertext, hex-encoded.
    solana_nonce: String,
    /// AES-GCM ciphertext of the 32-byte Solana seed, hex-encoded.
    solana_ciphertext: String,
    /// 12-byte nonce for the Laurelin sk ciphertext, hex-encoded.
    laurelin_nonce: String,
    /// AES-GCM ciphertext of the 32-byte Laurelin sk, hex-encoded.
    laurelin_ciphertext: String,
}

// ── Key derivation / encryption helpers ──────────────────────────────────────

fn argon2_derive(password: &[u8], salt: &[u8]) -> anyhow::Result<Zeroizing<[u8; AES_KEY_LEN]>> {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(AES_KEY_LEN),
    )
    .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; AES_KEY_LEN]);
    argon2
        .hash_password_into(password, salt, &mut key[..])
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(key)
}

fn aes_encrypt(
    solana_sk: &[u8; 32],
    laurelin_sk: &[u8; 32],
    password: &[u8],
    solana_pubkey: &Pubkey,
) -> anyhow::Result<WalletV2> {
    let mut rng = rand::thread_rng();

    let mut salt = [0u8; ARGON2_SALT_LEN];
    let mut solana_nonce_bytes = [0u8; AES_NONCE_LEN];
    let mut laurelin_nonce_bytes = [0u8; AES_NONCE_LEN];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut solana_nonce_bytes);
    rng.fill_bytes(&mut laurelin_nonce_bytes);

    let key = argon2_derive(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..])
        .map_err(|_| anyhow::anyhow!("invalid AES key length"))?;

    let solana_ct = cipher
        .encrypt(Nonce::from_slice(&solana_nonce_bytes), solana_sk.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed (solana)"))?;

    let laurelin_ct = cipher
        .encrypt(
            Nonce::from_slice(&laurelin_nonce_bytes),
            laurelin_sk.as_ref(),
        )
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed (laurelin)"))?;

    Ok(WalletV2 {
        version: 2,
        solana_pubkey: solana_pubkey.to_string(),
        argon2_salt: hex::encode(salt),
        solana_nonce: hex::encode(solana_nonce_bytes),
        solana_ciphertext: hex::encode(&solana_ct),
        laurelin_nonce: hex::encode(laurelin_nonce_bytes),
        laurelin_ciphertext: hex::encode(&laurelin_ct),
    })
}

fn aes_decrypt(
    wf: &WalletV2,
    password: &[u8],
) -> anyhow::Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
    let salt = hex::decode(&wf.argon2_salt).context("decode argon2_salt")?;
    let solana_nonce = hex::decode(&wf.solana_nonce).context("decode solana_nonce")?;
    let laurelin_nonce = hex::decode(&wf.laurelin_nonce).context("decode laurelin_nonce")?;
    let mut solana_ct = hex::decode(&wf.solana_ciphertext).context("decode solana_ciphertext")?;
    let mut laurelin_ct =
        hex::decode(&wf.laurelin_ciphertext).context("decode laurelin_ciphertext")?;

    let key = argon2_derive(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..])
        .map_err(|_| anyhow::anyhow!("invalid AES key length"))?;

    let mut solana_pt = cipher
        .decrypt(Nonce::from_slice(&solana_nonce), solana_ct.as_ref())
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong password?"))?;
    solana_ct.zeroize();

    let mut laurelin_pt = cipher
        .decrypt(Nonce::from_slice(&laurelin_nonce), laurelin_ct.as_ref())
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong password?"))?;
    laurelin_ct.zeroize();

    anyhow::ensure!(solana_pt.len() == 32, "solana_sk must decrypt to 32 bytes");
    anyhow::ensure!(
        laurelin_pt.len() == 32,
        "laurelin_sk must decrypt to 32 bytes"
    );

    let mut solana_sk = Zeroizing::new([0u8; 32]);
    let mut laurelin_sk = Zeroizing::new([0u8; 32]);
    solana_sk.copy_from_slice(&solana_pt);
    laurelin_sk.copy_from_slice(&laurelin_pt);
    solana_pt.zeroize();
    laurelin_pt.zeroize();

    Ok((solana_sk, laurelin_sk))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Loaded wallet.  All secret key material is in `Zeroizing` wrappers and is
/// overwritten with zeros when this struct is dropped.
pub struct Wallet {
    pub solana_sk: Zeroizing<[u8; 32]>,
    pub laurelin_sk: Zeroizing<[u8; 32]>,
    pub laurelin_pk: G1Affine,
    /// Laurelin public key as 64-byte X||Y (for on-chain use).
    pub laurelin_pk_bytes: [u8; 64],
}

impl Wallet {
    /// Load from a JSON file, prompting for password if encrypted.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("read wallet {}", path.display()))?;

        let probe: VersionProbe = serde_json::from_str(&data)
            .with_context(|| format!("parse wallet version {}", path.display()))?;

        let (solana_sk, laurelin_sk) = match probe.version {
            1 => {
                let wf: WalletV1 = serde_json::from_str(&data)
                    .with_context(|| format!("parse wallet v1 {}", path.display()))?;

                let solana_bytes = hex::decode(&wf.solana_sk).context("decode solana_sk")?;
                let solana_arr: [u8; 32] = solana_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("solana_sk must be 32 bytes"))?;

                let laurelin_bytes = hex::decode(&wf.laurelin_sk).context("decode laurelin_sk")?;
                let laurelin_arr: [u8; 32] = laurelin_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("laurelin_sk must be 32 bytes"))?;

                (Zeroizing::new(solana_arr), Zeroizing::new(laurelin_arr))
            }
            2 => {
                let wf: WalletV2 = serde_json::from_str(&data)
                    .with_context(|| format!("parse wallet v2 {}", path.display()))?;
                let password = Zeroizing::new(rpassword::prompt_password("Wallet password: ")?);
                aes_decrypt(&wf, password.as_bytes())?
            }
            v => anyhow::bail!("unsupported wallet version {v}"),
        };

        let laurelin_sk_fr: Fr = fr_from_bytes(&laurelin_sk);
        let laurelin_pk: G1Affine = scalar_mul(&generator(), &laurelin_sk_fr);
        let laurelin_pk_bytes = g1_to_bytes(&laurelin_pk);

        Ok(Wallet {
            solana_sk,
            laurelin_sk,
            laurelin_pk,
            laurelin_pk_bytes,
        })
    }

    /// Load only the Solana pubkey without decrypting.
    ///
    /// For v2 wallets created before this field was added (empty `solana_pubkey`),
    /// falls back to full decryption.  For v1 the seed is already plaintext.
    pub fn load_pubkey(path: &Path) -> anyhow::Result<Pubkey> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("read wallet {}", path.display()))?;

        let probe: VersionProbe = serde_json::from_str(&data)
            .with_context(|| format!("parse wallet version {}", path.display()))?;

        match probe.version {
            1 => {
                let wf: WalletV1 = serde_json::from_str(&data)
                    .with_context(|| format!("parse wallet v1 {}", path.display()))?;
                let seed = hex::decode(&wf.solana_sk).context("decode solana_sk")?;
                let keypair = solana_sdk::signature::Keypair::from_seed(&seed)
                    .map_err(|e| anyhow::anyhow!("invalid solana seed: {e}"))?;
                Ok(keypair.pubkey())
            }
            2 => {
                let wf: WalletV2 = serde_json::from_str(&data)
                    .with_context(|| format!("parse wallet v2 {}", path.display()))?;
                if !wf.solana_pubkey.is_empty() {
                    wf.solana_pubkey
                        .parse()
                        .context("parse solana_pubkey from wallet")
                } else {
                    // Old wallet file without the plaintext pubkey — decrypt to derive it.
                    let password = Zeroizing::new(rpassword::prompt_password("Wallet password: ")?);
                    let (solana_sk, _) = aes_decrypt(&wf, password.as_bytes())?;
                    let keypair = solana_sdk::signature::Keypair::from_seed(&*solana_sk)
                        .map_err(|e| anyhow::anyhow!("invalid solana seed: {e}"))?;
                    Ok(keypair.pubkey())
                }
            }
            v => anyhow::bail!("unsupported wallet version {v}"),
        }
    }

    /// Save an encrypted (version 2) wallet.  `password` must already be
    /// collected and confirmed by the caller.
    pub fn save_encrypted(
        path: &Path,
        solana_sk: &[u8; 32],
        laurelin_sk: &[u8; 32],
        password: &[u8],
    ) -> anyhow::Result<()> {
        let keypair = solana_sdk::signature::Keypair::from_seed(solana_sk)
            .map_err(|e| anyhow::anyhow!("invalid solana seed: {e}"))?;
        let wf = aes_encrypt(solana_sk, laurelin_sk, password, &keypair.pubkey())?;
        write_wallet(path, &serde_json::to_string_pretty(&wf)?)
    }

    /// Save a plaintext (version 1) wallet.  For `--insecure` / testing only.
    pub fn save_plaintext(
        path: &Path,
        solana_sk: &[u8; 32],
        laurelin_sk: &[u8; 32],
    ) -> anyhow::Result<()> {
        let wf = WalletV1 {
            version: 1,
            solana_sk: hex::encode(solana_sk),
            laurelin_sk: hex::encode(laurelin_sk),
        };
        write_wallet(path, &serde_json::to_string_pretty(&wf)?)
    }

    /// Reconstruct and return the Solana signing keypair.
    pub fn solana_keypair(&self) -> anyhow::Result<solana_sdk::signature::Keypair> {
        solana_sdk::signature::Keypair::from_seed(&*self.solana_sk)
            .map_err(|e| anyhow::anyhow!("invalid solana seed: {e}"))
    }

    /// Return the Laurelin secret key as Fr.
    pub fn laurelin_sk_fr(&self) -> Fr {
        fr_from_bytes(&*self.laurelin_sk)
    }

    /// Compute the Laurelin PDA for this wallet under the given program.
    pub fn pda(&self, program_id: &Pubkey) -> Pubkey {
        let (pda, _) = Pubkey::find_program_address(&[&self.laurelin_pk_bytes[..32]], program_id);
        pda
    }
}

fn write_wallet(path: &Path, json: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
    }
    std::fs::write(path, json).with_context(|| format!("write wallet {}", path.display()))
}

/// Return the default wallet file path: ~/.laurelin/wallet.json.
pub fn default_wallet_path() -> PathBuf {
    laurelin_dir().join("wallet.json")
}
