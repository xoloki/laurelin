//! Config file: ~/.laurelin/config.json
//!
//! Stores program_id, rpc_url, and pk_dir.
//! All fields are optional on disk; missing values fall back to defaults or
//! are overridden by CLI flags.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Default RPC endpoint.
pub const DEFAULT_RPC_URL: &str = "http://localhost:8899";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub program_id: Option<String>,
    pub rpc_url: Option<String>,
    pub pk_dir: Option<String>,
    /// Name or full path of the laurelin prover binary (default: "laurelin-prover").
    pub prover: Option<String>,
}

impl Config {
    /// Load from a JSON file.  Returns a default Config if the file does not exist.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let cfg: Config = serde_json::from_str(&data)
            .with_context(|| format!("parse config {}", path.display()))?;
        Ok(cfg)
    }

    /// Save to a JSON file, creating parent directories as needed.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data).with_context(|| format!("write config {}", path.display()))?;
        Ok(())
    }
}

/// Resolved runtime configuration.
///
/// Resolution order: CLI flag → config file → default/error.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub program_id: String,
    pub rpc_url: String,
    pub pk_dir: PathBuf,
    pub prover: String,
}

impl ResolvedConfig {
    /// Resolve config, applying optional CLI flag overrides.
    ///
    /// `program_id` is required either in the config or as a CLI override;
    /// an error is returned if it is absent from both.
    pub fn resolve(
        cfg: &Config,
        url_override: Option<&str>,
        program_override: Option<&str>,
    ) -> anyhow::Result<Self> {
        let rpc_url = url_override
            .map(str::to_owned)
            .or_else(|| cfg.rpc_url.clone())
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_owned());

        let program_id = program_override
            .map(str::to_owned)
            .or_else(|| cfg.program_id.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "program_id is required: pass --program <id> or set it in config with \
                     `laurelin-wallet config set-program <id>`"
                )
            })?;

        let pk_dir = cfg
            .pk_dir
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(default_pk_dir);

        let prover = cfg
            .prover
            .clone()
            .unwrap_or_else(|| "laurelin-prover".to_owned());

        Ok(ResolvedConfig {
            program_id,
            rpc_url,
            pk_dir,
            prover,
        })
    }
}

/// Default pk_dir: ~/laurelin/setup  (a reasonable guess; users set it explicitly).
fn default_pk_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("laurelin")
        .join("setup")
}

/// Return the default config file path: ~/.laurelin/config.json.
pub fn default_config_path() -> PathBuf {
    laurelin_dir().join("config.json")
}

/// Return the ~/.laurelin directory.
pub fn laurelin_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".laurelin")
}
