use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, ensure};
use log::{error, info, warn};

use crate::config::{
    CERTS_DIR, DEFAULT_PORT, DEPLOY_HOOKS, RENEW_LIFETIME_DIVISOR, RENEW_MAX_DAYS, RENEW_MIN_DAYS,
};
use crate::fetcher::{
    fetch_cert_chain, verify_cert_matches_domain, verify_cert_matches_private_key,
};
use crate::write_cert_files;

/// Returns the (not_before, not_after) timestamps of a PEM certificate.
pub(crate) fn cert_validity(path: &Path) -> Result<(i64, i64)> {
    let data = fs::read(path)?;
    let p = pem::parse(&data)?;
    let (_, cert) = x509_parser::parse_x509_certificate(p.contents())?;
    let validity = cert.validity();
    Ok((
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    ))
}

/// How long before expiry (in seconds) a certificate becomes due for renewal:
/// a fraction of its lifetime, rounded up to whole days.
fn renew_window(not_before: i64, not_after: i64) -> i64 {
    let per_day = RENEW_LIFETIME_DIVISOR * 86400;
    let days = (not_after - not_before + per_day - 1) / per_day;
    days.clamp(RENEW_MIN_DAYS, RENEW_MAX_DAYS) * 86400
}

/// Try to renew a single domain. Returns Ok(true) if renewed, Ok(false) if skipped.
pub(crate) fn try_renew(
    base_dir: &Path,
    domain: &str,
    now: i64,
    force: bool,
) -> Result<bool> {
    let cert_path = base_dir.join(domain).join("cert.pem");
    if !cert_path.exists() {
        warn!("{}: no cert.pem, skipping", domain);
        return Ok(false);
    }

    if !force {
        let (not_before, not_after) = cert_validity(&cert_path)?;
        let renew_at = not_after - renew_window(not_before, not_after);
        if now < renew_at {
            let days = (not_after - now) / 86400;
            let renew_days = (renew_at - now) / 86400;
            info!(
                "{}: {} days remaining, renewal in {} days, skipping",
                domain, days, renew_days
            );
            return Ok(false);
        }
    }

    info!("{}: fetching certificate", domain);
    let certs = fetch_cert_chain(domain, DEFAULT_PORT)?;
    verify_cert_matches_domain(&certs[0], domain)?;
    verify_cert_matches_private_key(&certs[0], &base_dir.join(domain).join("privkey.pem"))?;

    let new_pem = crate::fetcher::der_to_pem(&certs[0]);
    let existing = fs::read_to_string(&cert_path).unwrap_or_default();
    if new_pem == existing {
        info!("{}: certificate unchanged, skipping", domain);
        return Ok(false);
    }

    write_cert_files(base_dir, domain, &certs)?;
    Ok(true)
}

pub(crate) fn run_deploy_hooks(hooks_dir: &Path, base_dir: &Path, domain: &str) {
    let entries = match fs::read_dir(hooks_dir) {
        Ok(e) => e,
        Err(_) => {
            warn!(
                "no deploy hooks found in {} — web server won't be reloaded",
                hooks_dir.display()
            );
            return;
        }
    };

    let lineage = base_dir.join(domain);
    let mut ran = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        info!("running deploy hook: {}", path.display());
        let result = Command::new(&path)
            .env("RENEWED_LINEAGE", &lineage)
            .env("RENEWED_DOMAINS", domain)
            .status();
        if let Err(e) = result {
            warn!("hook {} failed: {}", path.display(), e);
        }
        ran += 1;
    }

    if ran == 0 {
        warn!(
            "no deploy hooks found in {} — web server won't be reloaded",
            hooks_dir.display()
        );
    }
}

pub fn cmd_renew(force: bool) -> Result<()> {
    let live = Path::new(CERTS_DIR);
    ensure!(live.exists(), "{CERTS_DIR} does not exist");

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let mut updated = 0u32;
    let mut skipped = 0u32;
    let mut renewed_domains = Vec::new();

    for entry in fs::read_dir(live)? {
        let entry = entry?;
        if !entry.path().is_dir() {
            continue;
        }

        let domain = entry.file_name().to_string_lossy().into_owned();
        let Ok(renewed) = try_renew(live, &domain, now, force)
            .inspect_err(|e| error!("{}: {:#}", domain, e))
        else {
            skipped += 1;
            continue;
        };
        if renewed {
            updated += 1;
            renewed_domains.push(domain);
        } else {
            skipped += 1;
        }
    }

    for domain in &renewed_domains {
        run_deploy_hooks(Path::new(DEPLOY_HOOKS), live, domain);
    }

    info!("done: {} updated, {} skipped", updated, skipped);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::renew_window;

    const DAY: i64 = 86400;

    #[test]
    fn renew_window_is_tenth_of_lifetime() {
        assert_eq!(renew_window(0, 90 * DAY), 9 * DAY);
    }

    #[test]
    fn renew_window_rounds_up_to_whole_days() {
        assert_eq!(renew_window(0, 47 * DAY), 5 * DAY);
        assert_eq!(renew_window(0, 90 * DAY - 1), 9 * DAY);
    }

    #[test]
    fn renew_window_has_two_day_minimum() {
        assert_eq!(renew_window(0, 6 * DAY), 2 * DAY);
    }

    #[test]
    fn renew_window_has_thirty_day_maximum() {
        assert_eq!(renew_window(0, 300 * DAY), 30 * DAY);
        assert_eq!(renew_window(0, 398 * DAY), 30 * DAY);
    }
}
