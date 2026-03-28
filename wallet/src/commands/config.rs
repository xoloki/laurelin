//! `config set-*` — update the laurelin config file.

use std::path::Path;

use crate::config::Config;

pub fn set_program(config_path: &Path, id: &str) -> anyhow::Result<()> {
    let mut cfg = Config::load(config_path)?;
    cfg.program_id = Some(id.to_owned());
    cfg.save(config_path)?;
    println!("program_id set to {id}");
    Ok(())
}

pub fn set_url(config_path: &Path, url: &str) -> anyhow::Result<()> {
    let mut cfg = Config::load(config_path)?;
    cfg.rpc_url = Some(url.to_owned());
    cfg.save(config_path)?;
    println!("rpc_url set to {url}");
    Ok(())
}

pub fn set_pk_dir(config_path: &Path, path: &str) -> anyhow::Result<()> {
    let mut cfg = Config::load(config_path)?;
    cfg.pk_dir = Some(path.to_owned());
    cfg.save(config_path)?;
    println!("pk_dir set to {path}");
    Ok(())
}

pub fn set_prover(config_path: &Path, name: &str) -> anyhow::Result<()> {
    let mut cfg = Config::load(config_path)?;
    cfg.prover = Some(name.to_owned());
    cfg.save(config_path)?;
    println!("prover set to {name}");
    Ok(())
}
