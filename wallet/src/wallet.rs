//! Wallet file: ~/.laurelin/wallet.json
//!
//! Two on-disk formats:
//!
//! **Version 1** (plaintext / `--insecure`): stores keys in the clear.  For
//! testing only.
//!
//! **Version 2** (encrypted, default): derives a 256-bit AES key from the
//! user's password using Argon2id (m=256 MB, t=4, p=2), then encrypts
//! `solana_keypair (64B) ‖ bn254_sk (32B)` with AES-256-GCM.
//!
//! The BN254 public key is always derived from the secret key on load and
//! never stored to disk.  All in-memory key material lives in `Zeroizing`
//! wrappers and is overwritten with zeros on drop.

use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use anyhow::Context;
use ark_bn254::{Fr, G1Affine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
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
    version: u32, // = 1
    solana_keypair: Vec<u8>,
    bn254_secret_key: String,
}

/// Version 2: AES-256-GCM encrypted with Argon2id key derivation.
///
/// One Argon2 derivation (single salt → single key); each field encrypted
/// with its own nonce so plaintexts are never concatenated.
#[derive(Serialize, Deserialize)]
struct WalletV2 {
    version: u32, // = 2
    /// 16-byte Argon2 salt, hex-encoded.
    argon2_salt: String,
    /// 12-byte nonce for the Solana keypair ciphertext, hex-encoded.
    solana_nonce: String,
    /// AES-GCM ciphertext of the 64-byte Solana keypair, hex-encoded.
    solana_ciphertext: String,
    /// 12-byte nonce for the BN254 secret key ciphertext, hex-encoded.
    bn254_nonce: String,
    /// AES-GCM ciphertext of the 32-byte BN254 secret key, hex-encoded.
    bn254_ciphertext: String,
}

// ── Key derivation / encryption helpers ──────────────────────────────────────

fn argon2_derive(password: &[u8], salt: &[u8]) -> anyhow::Result<Zeroizing<[u8; AES_KEY_LEN]>> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(AES_KEY_LEN))
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; AES_KEY_LEN]);
    argon2
        .hash_password_into(password, salt, &mut key[..])
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(key)
}

fn aes_encrypt(
    kp: &[u8; 64],
    sk: &[u8; 32],
    password: &[u8],
) -> anyhow::Result<WalletV2> {
    let mut rng = rand::thread_rng();

    let mut salt = [0u8; ARGON2_SALT_LEN];
    let mut solana_nonce_bytes = [0u8; AES_NONCE_LEN];
    let mut bn254_nonce_bytes = [0u8; AES_NONCE_LEN];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut solana_nonce_bytes);
    rng.fill_bytes(&mut bn254_nonce_bytes);

    let key = argon2_derive(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..])
        .map_err(|_| anyhow::anyhow!("invalid AES key length"))?;

    let solana_ct = cipher
        .encrypt(Nonce::from_slice(&solana_nonce_bytes), kp.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed (solana)"))?;

    let bn254_ct = cipher
        .encrypt(Nonce::from_slice(&bn254_nonce_bytes), sk.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed (bn254)"))?;

    Ok(WalletV2 {
        version: 2,
        argon2_salt: hex::encode(salt),
        solana_nonce: hex::encode(solana_nonce_bytes),
        solana_ciphertext: hex::encode(&solana_ct),
        bn254_nonce: hex::encode(bn254_nonce_bytes),
        bn254_ciphertext: hex::encode(&bn254_ct),
    })
}

fn aes_decrypt(
    wf: &WalletV2,
    password: &[u8],
) -> anyhow::Result<(Zeroizing<[u8; 64]>, Zeroizing<[u8; 32]>)> {
    let salt = hex::decode(&wf.argon2_salt).context("decode argon2_salt")?;
    let solana_nonce = hex::decode(&wf.solana_nonce).context("decode solana_nonce")?;
    let bn254_nonce = hex::decode(&wf.bn254_nonce).context("decode bn254_nonce")?;
    let mut solana_ct = hex::decode(&wf.solana_ciphertext).context("decode solana_ciphertext")?;
    let mut bn254_ct = hex::decode(&wf.bn254_ciphertext).context("decode bn254_ciphertext")?;

    let key = argon2_derive(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..])
        .map_err(|_| anyhow::anyhow!("invalid AES key length"))?;

    let mut kp_pt = cipher
        .decrypt(Nonce::from_slice(&solana_nonce), solana_ct.as_ref())
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong password?"))?;
    solana_ct.zeroize();

    let mut sk_pt = cipher
        .decrypt(Nonce::from_slice(&bn254_nonce), bn254_ct.as_ref())
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong password?"))?;
    bn254_ct.zeroize();

    anyhow::ensure!(kp_pt.len() == 64, "solana keypair must decrypt to 64 bytes");
    anyhow::ensure!(sk_pt.len() == 32, "bn254 sk must decrypt to 32 bytes");

    let mut kp = Zeroizing::new([0u8; 64]);
    let mut sk = Zeroizing::new([0u8; 32]);
    kp.copy_from_slice(&kp_pt);
    sk.copy_from_slice(&sk_pt);
    kp_pt.zeroize();
    sk_pt.zeroize();

    Ok((kp, sk))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Loaded wallet.  All secret key material is in `Zeroizing` wrappers and is
/// overwritten with zeros when this struct is dropped.
pub struct Wallet {
    pub solana_keypair: Zeroizing<[u8; 64]>,
    pub bn254_sk: Zeroizing<[u8; 32]>,
    pub bn254_pk: G1Affine,
    /// BN254 public key as 64-byte X||Y (for on-chain use).
    pub bn254_pk_bytes: [u8; 64],
}

impl Wallet {
    /// Load from a JSON file.
    ///
    /// Version 2 files prompt the user for their password on stdin.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("read wallet {}", path.display()))?;

        let probe: VersionProbe = serde_json::from_str(&data)
            .with_context(|| format!("parse wallet version {}", path.display()))?;

        let (kp, sk) = match probe.version {
            1 => {
                let wf: WalletV1 = serde_json::from_str(&data)
                    .with_context(|| format!("parse wallet v1 {}", path.display()))?;
                anyhow::ensure!(wf.solana_keypair.len() == 64, "solana_keypair must be 64 bytes");

                let mut kp = Zeroizing::new([0u8; 64]);
                kp.copy_from_slice(&wf.solana_keypair);

                let sk_vec = hex::decode(&wf.bn254_secret_key).context("decode bn254_secret_key")?;
                let sk_arr: [u8; 32] = sk_vec
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("bn254_secret_key must be 32 bytes"))?;
                (kp, Zeroizing::new(sk_arr))
            }
            2 => {
                let wf: WalletV2 = serde_json::from_str(&data)
                    .with_context(|| format!("parse wallet v2 {}", path.display()))?;
                let password =
                    Zeroizing::new(rpassword::prompt_password("Wallet password: ")?);
                aes_decrypt(&wf, password.as_bytes())?
            }
            v => anyhow::bail!("unsupported wallet version {v}"),
        };

        let sk_fr: Fr = fr_from_bytes(&sk);
        let pk: G1Affine = scalar_mul(&generator(), &sk_fr);
        let pk_bytes = g1_to_bytes(&pk);

        Ok(Wallet {
            solana_keypair: kp,
            bn254_sk: sk,
            bn254_pk: pk,
            bn254_pk_bytes: pk_bytes,
        })
    }

    /// Save an encrypted (version 2) wallet.  `password` must already be
    /// collected and confirmed by the caller.
    pub fn save_encrypted(
        path: &Path,
        solana_keypair: &[u8; 64],
        bn254_sk: &[u8; 32],
        password: &[u8],
    ) -> anyhow::Result<()> {
        let wf = aes_encrypt(solana_keypair, bn254_sk, password)?;
        write_wallet(path, &serde_json::to_string_pretty(&wf)?)
    }

    /// Save a plaintext (version 1) wallet.  For `--insecure` / testing only.
    pub fn save_plaintext(
        path: &Path,
        solana_keypair: &[u8; 64],
        bn254_sk: &[u8; 32],
    ) -> anyhow::Result<()> {
        let wf = WalletV1 {
            version: 1,
            solana_keypair: solana_keypair.to_vec(),
            bn254_secret_key: hex::encode(bn254_sk),
        };
        write_wallet(path, &serde_json::to_string_pretty(&wf)?)
    }

    /// Return the Solana keypair.
    pub fn solana_keypair(&self) -> anyhow::Result<solana_sdk::signature::Keypair> {
        solana_sdk::signature::Keypair::from_bytes(&*self.solana_keypair)
            .map_err(|e| anyhow::anyhow!("invalid solana keypair: {e}"))
    }

    /// Return the BN254 secret key as Fr.
    pub fn bn254_sk_fr(&self) -> Fr {
        fr_from_bytes(&*self.bn254_sk)
    }

    /// Compute the Laurelin PDA for this wallet under the given program.
    pub fn pda(&self, program_id: &solana_sdk::pubkey::Pubkey) -> solana_sdk::pubkey::Pubkey {
        let (pda, _) = solana_sdk::pubkey::Pubkey::find_program_address(
            &[&self.bn254_pk_bytes[..32]],
            program_id,
        );
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
