use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const LIVE_DIR: &str = "/etc/certferry";
const HOOKS_DIR: &str = "/etc/letsencrypt/renewal-hooks/deploy";

fn certferry() -> Command {
    Command::new(env!("CARGO_BIN_EXE_certferry"))
}

fn setup() {
    fs::create_dir_all(LIVE_DIR).unwrap();
}

fn cleanup(domain: &str) {
    let _ = fs::remove_dir_all(Path::new(LIVE_DIR).join(domain));
}

fn clean_all_live() {
    if let Ok(entries) = fs::read_dir(LIVE_DIR) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---- shared TLS server on 127.0.0.1:443 ----

struct SharedServer {
    leaf_key_pem: String,
}

static SERVER: OnceLock<SharedServer> = OnceLock::new();

fn shared_server() -> &'static SharedServer {
    SERVER.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Self-signed CA
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_params = rcgen::CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Leaf signed by CA, SAN "localhost"
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        let leaf_der = leaf_cert.der().to_vec();
        let ca_der = ca_cert.der().to_vec();
        let leaf_key_pem = leaf_key.serialize_pem();
        let leaf_key_der = leaf_key.serialize_der();

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![
                    rustls::pki_types::CertificateDer::from(leaf_der),
                    rustls::pki_types::CertificateDer::from(ca_der),
                ],
                rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key_der).into(),
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:443").expect(
            "failed to bind 127.0.0.1:443 — run tests as root or set \
             net.ipv4.ip_unprivileged_port_start=443",
        );
        let config = Arc::new(config);

        thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let mut conn = rustls::ServerConnection::new(config.clone()).unwrap();
                let _ = conn.complete_io(&mut stream);
            }
        });

        SharedServer { leaf_key_pem }
    })
}

fn plant_localhost_key() {
    let dir = Path::new(LIVE_DIR).join("localhost");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("privkey.pem"), &shared_server().leaf_key_pem).unwrap();
}

// ---- test cert generation for renew tests ----

fn make_cert_pem(days_until_expiry: i64) -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let ts = now_ts() + days_until_expiry * 86400;
    let dt = time::OffsetDateTime::from_unix_timestamp(ts).unwrap();
    params.not_after = rcgen::date_time_ymd(dt.year(), dt.month() as u8, dt.day());
    params.self_signed(&key).unwrap().pem()
}

// ========================================================================
// Fetch tests
// ========================================================================

#[test]
fn fetch_basic() {
    setup();
    cleanup("localhost");
    shared_server();
    plant_localhost_key();

    let out = certferry().arg("localhost").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let dir = Path::new(LIVE_DIR).join("localhost");
    assert!(dir.join("cert.pem").exists());
    assert!(dir.join("chain.pem").exists());
    assert!(dir.join("fullchain.pem").exists());

    cleanup("localhost");
}

#[test]
fn cert_pem_is_valid_pem() {
    setup();
    cleanup("localhost");
    shared_server();
    plant_localhost_key();

    let out = certferry().arg("localhost").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let data = fs::read(Path::new(LIVE_DIR).join("localhost/cert.pem")).unwrap();
    let parsed = pem::parse(&data).unwrap();
    assert_eq!(parsed.tag(), "CERTIFICATE");

    cleanup("localhost");
}

#[test]
fn chain_pem_is_non_empty() {
    setup();
    cleanup("localhost");
    shared_server();
    plant_localhost_key();

    let out = certferry().arg("localhost").output().unwrap();
    assert!(out.status.success());

    let chain = fs::read_to_string(Path::new(LIVE_DIR).join("localhost/chain.pem")).unwrap();
    assert!(!chain.is_empty());
    let certs = pem::parse_many(chain.as_bytes()).unwrap();
    assert!(!certs.is_empty());

    cleanup("localhost");
}

#[test]
fn fullchain_equals_cert_plus_chain() {
    setup();
    cleanup("localhost");
    shared_server();
    plant_localhost_key();

    certferry().arg("localhost").output().unwrap();

    let dir = Path::new(LIVE_DIR).join("localhost");
    let cert = fs::read_to_string(dir.join("cert.pem")).unwrap();
    let chain = fs::read_to_string(dir.join("chain.pem")).unwrap();
    let fullchain = fs::read_to_string(dir.join("fullchain.pem")).unwrap();

    assert_eq!(fullchain, format!("{cert}{chain}"));

    cleanup("localhost");
}

#[test]
fn fullchain_has_multiple_certs() {
    setup();
    cleanup("localhost");
    shared_server();
    plant_localhost_key();

    certferry().arg("localhost").output().unwrap();

    let data = fs::read(Path::new(LIVE_DIR).join("localhost/fullchain.pem")).unwrap();
    let certs = pem::parse_many(&data).unwrap();
    assert!(
        certs.len() >= 2,
        "fullchain should have leaf + intermediate, got {}",
        certs.len()
    );

    cleanup("localhost");
}

#[test]
fn creates_domain_directory() {
    setup();
    cleanup("localhost");
    shared_server();
    plant_localhost_key();

    // Remove cert files but keep privkey.pem
    let dir = Path::new(LIVE_DIR).join("localhost");
    for f in ["cert.pem", "chain.pem", "fullchain.pem"] {
        let _ = fs::remove_file(dir.join(f));
    }

    let out = certferry().arg("localhost").output().unwrap();
    assert!(out.status.success());
    assert!(dir.is_dir());
    assert!(dir.join("cert.pem").exists());

    cleanup("localhost");
}

#[test]
fn overwrites_existing_cert_files() {
    setup();
    cleanup("localhost");
    shared_server();
    plant_localhost_key();

    certferry().arg("localhost").output().unwrap();
    let first = fs::read_to_string(Path::new(LIVE_DIR).join("localhost/cert.pem")).unwrap();

    certferry().arg("localhost").output().unwrap();
    let second = fs::read_to_string(Path::new(LIVE_DIR).join("localhost/cert.pem")).unwrap();

    assert_eq!(first, second);

    cleanup("localhost");
}

// ========================================================================
// Domain and key verification tests
// ========================================================================

#[test]
fn mismatched_domain_fails() {
    // Shared server's cert has SAN "localhost", connecting via 127.0.0.1 mismatches.
    setup();
    cleanup("127.0.0.1");
    shared_server();

    let out = certferry().arg("127.0.0.1").output().unwrap();
    assert!(!out.status.success());

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("does not match"),
        "expected 'does not match', got: {combined}"
    );

    assert!(!Path::new(LIVE_DIR).join("127.0.0.1/cert.pem").exists());
}

#[test]
fn matching_private_key_succeeds() {
    setup();
    cleanup("localhost");
    shared_server();
    plant_localhost_key();

    let out = certferry().arg("localhost").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(Path::new(LIVE_DIR).join("localhost/cert.pem").exists());

    cleanup("localhost");
}

#[test]
fn mismatched_private_key_fails() {
    setup();
    cleanup("localhost");
    shared_server();

    // Plant a DIFFERENT key than what the server uses
    let other = rcgen::KeyPair::generate().unwrap();
    let dir = Path::new(LIVE_DIR).join("localhost");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("privkey.pem"), other.serialize_pem()).unwrap();

    let out = certferry().arg("localhost").output().unwrap();
    assert!(!out.status.success());

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("private key does not match"),
        "expected 'private key does not match', got: {combined}"
    );

    assert!(!dir.join("cert.pem").exists());

    cleanup("localhost");
}

#[test]
fn missing_private_key_fails() {
    setup();
    cleanup("localhost");
    shared_server();

    let out = certferry().arg("localhost").output().unwrap();
    assert!(!out.status.success());
    assert!(!Path::new(LIVE_DIR).join("localhost/cert.pem").exists());

    cleanup("localhost");
}

// ========================================================================
// Renew tests
// ========================================================================

#[test]
fn renew_updates_expiring_cert() {
    setup();
    clean_all_live();
    shared_server();

    // Plant expiring cert + server's key
    let dir = Path::new(LIVE_DIR).join("localhost");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("cert.pem"), make_cert_pem(5)).unwrap();
    fs::write(dir.join("privkey.pem"), &shared_server().leaf_key_pem).unwrap();

    let before = fs::read_to_string(dir.join("cert.pem")).unwrap();

    let out = certferry().arg("--renew").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = fs::read_to_string(dir.join("cert.pem")).unwrap();
    assert_ne!(before, after, "cert.pem should have been updated");

    let parsed = pem::parse(after.as_bytes()).unwrap();
    assert_eq!(parsed.tag(), "CERTIFICATE");

    clean_all_live();
}

#[test]
fn renew_skips_valid_cert() {
    setup();
    clean_all_live();

    // Valid cert (365 days), no server needed since it should skip
    let dir = Path::new(LIVE_DIR).join("localhost");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("cert.pem"), make_cert_pem(365)).unwrap();

    let before = fs::read_to_string(dir.join("cert.pem")).unwrap();

    let out = certferry().arg("--renew").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = fs::read_to_string(dir.join("cert.pem")).unwrap();
    assert_eq!(before, after, "valid cert should not be updated");

    clean_all_live();
}

#[test]
fn renew_force_updates_valid_cert() {
    setup();
    clean_all_live();
    shared_server();

    let dir = Path::new(LIVE_DIR).join("localhost");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("cert.pem"), make_cert_pem(365)).unwrap();
    fs::write(dir.join("privkey.pem"), &shared_server().leaf_key_pem).unwrap();

    let before = fs::read_to_string(dir.join("cert.pem")).unwrap();

    let out = certferry().args(["--renew", "--force"]).output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = fs::read_to_string(dir.join("cert.pem")).unwrap();
    assert_ne!(before, after, "--force should update even valid certs");

    clean_all_live();
}

#[test]
fn force_renew_order_independent() {
    setup();
    clean_all_live();
    shared_server();

    let dir = Path::new(LIVE_DIR).join("localhost");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("cert.pem"), make_cert_pem(365)).unwrap();
    fs::write(dir.join("privkey.pem"), &shared_server().leaf_key_pem).unwrap();

    let before = fs::read_to_string(dir.join("cert.pem")).unwrap();

    // --force before --renew
    let out = certferry().args(["--force", "--renew"]).output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = fs::read_to_string(dir.join("cert.pem")).unwrap();
    assert_ne!(before, after);

    clean_all_live();
}

#[test]
fn renew_empty_live_dir() {
    setup();
    clean_all_live();

    let out = certferry().arg("--renew").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let output = String::from_utf8_lossy(&out.stdout);
    assert!(
        output.contains("0 updated") && output.contains("0 skipped"),
        "expected 0 updated/skipped, got: {output}"
    );
}

#[test]
fn renew_domain_without_cert_pem_skipped() {
    setup();
    clean_all_live();

    // Create dir but no cert.pem
    fs::create_dir_all(Path::new(LIVE_DIR).join("emptyhost")).unwrap();

    let out = certferry().arg("--renew").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    clean_all_live();
}

#[test]
fn renew_with_invalid_cert_pem_skipped() {
    setup();
    clean_all_live();

    let dir = Path::new(LIVE_DIR).join("badhost");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("cert.pem"), "this is not a certificate").unwrap();

    let out = certferry().arg("--renew").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    clean_all_live();
}

#[test]
fn renew_unchanged_cert_not_counted_as_updated() {
    setup();
    clean_all_live();
    shared_server();
    plant_localhost_key();

    // Initial fetch
    let out = certferry().arg("localhost").output().unwrap();
    assert!(
        out.status.success(),
        "initial fetch failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Force renew — cert unchanged, should skip
    let out = certferry().args(["--renew", "--force"]).output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let output = String::from_utf8_lossy(&out.stdout);
    assert!(
        output.contains("0 updated"),
        "unchanged cert should not count as updated, got: {output}"
    );

    clean_all_live();
}

#[test]
fn renew_unchanged_cert_no_deploy_hooks() {
    setup();
    clean_all_live();
    shared_server();
    plant_localhost_key();

    fs::create_dir_all(HOOKS_DIR).unwrap();
    let marker = Path::new("/tmp/certferry-hook-marker");
    let _ = fs::remove_file(marker);

    let hook = Path::new(HOOKS_DIR).join("certferry-test-hook.sh");
    fs::write(&hook, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Initial fetch
    certferry().arg("localhost").output().unwrap();
    let _ = fs::remove_file(marker);

    // Force renew — cert unchanged, hooks should NOT run
    let out = certferry().args(["--renew", "--force"]).output().unwrap();
    assert!(out.status.success());
    assert!(
        !marker.exists(),
        "deploy hook should not run when cert is unchanged"
    );

    let _ = fs::remove_file(&hook);
    let _ = fs::remove_file(marker);
    clean_all_live();
}
