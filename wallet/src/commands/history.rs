//! `history [--limit N]` — recent transaction history for this wallet.

use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_sdk::pubkey::Pubkey;

use crate::{config::ResolvedConfig, rpc::new_client};

pub fn run(pubkey: &Pubkey, cfg: &ResolvedConfig, limit: usize) -> anyhow::Result<()> {
    let client = new_client(&cfg.rpc_url);

    let sigs = client
        .get_signatures_for_address_with_config(
            pubkey,
            GetConfirmedSignaturesForAddress2Config {
                limit: Some(limit),
                ..Default::default()
            },
        )
        .map_err(|e| anyhow::anyhow!("get_signatures_for_address: {e}"))?;

    if sigs.is_empty() {
        println!("No transactions found.");
        return Ok(());
    }

    println!(
        "{:<6}  {:<12}  {:<20}  {}",
        "Status", "Slot", "Time (UTC)", "Signature"
    );
    println!("{}", "-".repeat(100));

    for tx in &sigs {
        let status = if tx.err.is_some() { "FAIL" } else { "OK" };
        let time = tx
            .block_time
            .map(format_unix_ts)
            .unwrap_or_else(|| "?".to_owned());
        println!(
            "{:<6}  {:<12}  {:<20}  {}",
            status, tx.slot, time, tx.signature
        );
    }
    Ok(())
}

/// Format a Unix timestamp as `YYYY-MM-DD HH:MM:SS` without pulling in chrono.
fn format_unix_ts(ts: i64) -> String {
    // Days since Unix epoch using the proleptic Gregorian calendar
    const SECS_PER_MIN: i64 = 60;
    const SECS_PER_HOUR: i64 = 3600;
    const SECS_PER_DAY: i64 = 86400;

    let secs = ts % SECS_PER_DAY;
    let days = ts / SECS_PER_DAY;
    let h = secs / SECS_PER_HOUR;
    let m = (secs % SECS_PER_HOUR) / SECS_PER_MIN;
    let s = secs % SECS_PER_MIN;

    // Civil date from day number (algorithm by Howard Hinnant)
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };

    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}
