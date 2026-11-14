//! The certificate for the HTTPS listener.
//!
//! With no certificate given, the daemon makes a self-signed one on first
//! start and keeps it in the state directory, so the web UI is encrypted
//! from the first minute. A browser will warn about it until it is replaced
//! with a certificate the browser trusts.

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use axum_server::tls_rustls::RustlsConfig;

/// Loads the TLS config and a few words about where the certificate is from.
pub async fn config(
    state_dir: &Path,
    cert: Option<&Path>,
    key: Option<&Path>,
) -> Result<(RustlsConfig, String), String> {
    // rustls needs to be told which crypto library to use, once.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (cert, key, note) = match (cert, key) {
        (Some(c), Some(k)) => (
            c.to_path_buf(),
            k.to_path_buf(),
            "your certificate".to_string(),
        ),
        _ => {
            let dir = state_dir.join("tls");
            let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
            if !(cert.exists() && key.exists()) {
                fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                let host = fs::read_to_string("/etc/hostname")
                    .map(|h| h.trim().to_string())
                    .unwrap_or_default();
                let mut names = vec!["localhost".to_string()];
                if !host.is_empty() {
                    names.push(host);
                }
                let made = rcgen::generate_simple_self_signed(names)
                    .map_err(|e| format!("could not make a certificate: {e}"))?;
                fs::write(&cert, made.cert.pem())
                    .map_err(|e| format!("{}: {e}", cert.display()))?;
                fs::write(&key, made.signing_key.serialize_pem())
                    .map_err(|e| format!("{}: {e}", key.display()))?;
                // Only the daemon's user may read the private key.
                fs::set_permissions(&key, fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("{}: {e}", key.display()))?;
            }
            (
                cert,
                key,
                "self-signed certificate; browsers will warn".to_string(),
            )
        }
    };
    let config = RustlsConfig::from_pem_file(&cert, &key)
        .await
        .map_err(|e| format!("{} and {}: {e}", cert.display(), key.display()))?;
    Ok((config, note))
}
