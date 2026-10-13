use std::path::Path;

use anyhow::Result;
use log::{info, warn};

use crate::cmd_renew::run_deploy_hooks;
use crate::config::{CERTS_DIR, DEFAULT_PORT, DEPLOY_HOOKS};
use crate::fetcher::{
    fetch_cert_chain, verify_cert_matches_domain, verify_cert_matches_private_key,
};
use crate::install::install_timer;
use crate::write_cert_files;

pub fn cmd_fetch(host: &str) -> Result<()> {
    info!("connecting to {}:{}", host, DEFAULT_PORT);
    let certs = fetch_cert_chain(host, DEFAULT_PORT)?;
    info!("received {} certificate(s)", certs.len());
    verify_cert_matches_domain(&certs[0], host)?;

    let base = Path::new(CERTS_DIR);
    verify_cert_matches_private_key(&certs[0], &base.join(host).join("privkey.pem"))?;

    write_cert_files(base, host, &certs)?;

    run_deploy_hooks(Path::new(DEPLOY_HOOKS), base, host);

    match install_timer() {
        Ok(()) => info!("systemd renewal timer installed"),
        Err(e) => warn!("failed to install systemd timer: {e:#}"),
    }
    Ok(())
}
