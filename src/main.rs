mod cmd_fetch;
mod cmd_renew;
mod config;
mod fetcher;
mod install;

use std::path::Path;
use std::process;

use anyhow::{Result, ensure};
use log::{error, info};

use fetcher::der_to_pem;

pub(crate) fn write_cert_files(base_dir: &Path, domain: &str, certs: &[Vec<u8>]) -> Result<()> {
    ensure!(!certs.is_empty(), "no certificates received");

    let dir = base_dir.join(domain);
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }

    std::fs::write(dir.join("cert.pem"), der_to_pem(&certs[0]))?;
    info!("{}/cert.pem written", dir.display());

    let chain: String = certs[1..].iter().map(|c| der_to_pem(c)).collect();
    std::fs::write(dir.join("chain.pem"), &chain)?;
    info!("{}/chain.pem written", dir.display());

    let fullchain: String = certs.iter().map(|c| der_to_pem(c)).collect();
    std::fs::write(dir.join("fullchain.pem"), &fullchain)?;
    info!("{}/fullchain.pem written", dir.display());

    Ok(())
}

fn main() {
    logsy::set_echo(true);
    let _ = logsy::set_filename(Some("/var/log/certferry/certferry.log"));

    let args: Vec<String> = std::env::args().collect();

    let has = |flag: &str| args.iter().any(|a| a == flag);
    let domain = args.iter().skip(1).find(|a| !a.starts_with("--"));

    let result = if has("--renew") {
        cmd_renew::cmd_renew(has("--force"))
    } else if let Some(arg) = domain {
        cmd_fetch::cmd_fetch(arg)
    } else {
        eprintln!("Usage:");
        eprintln!("  certferry <domain>        Fetch certificate from remote host");
        eprintln!("  certferry --renew         Renew expiring local certificates");
        eprintln!("  certferry --renew --force  Renew all certificates unconditionally");
        process::exit(1);
    };

    if let Err(e) = result {
        error!("{:#}", e);
        process::exit(1);
    }
}
