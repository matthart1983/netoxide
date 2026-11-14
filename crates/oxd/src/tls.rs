//! The certificate for the HTTPS listener.
//!
//! With no certificate given, the daemon makes a self-signed one on first
//! start and keeps it in the state directory, so the web UI is encrypted
//! from the first minute. A browser will warn about it until it is replaced
//! with a certificate the browser trusts.

use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

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
                // The key is never on disk with wider permissions, and each
                // file appears whole or not at all, so a crash here cannot
                // leave half a pair that stops the next start.
                let put = |path: &Path, text: String| -> Result<(), String> {
                    let tmp = path.with_extension("tmp");
                    let _ = fs::remove_file(&tmp);
                    let write = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&tmp)
                        .and_then(|mut f| {
                            f.write_all(text.as_bytes())?;
                            f.sync_all()
                        })
                        .and_then(|()| fs::rename(&tmp, path));
                    write.map_err(|e| format!("{}: {e}", path.display()))
                };
                put(&key, made.signing_key.serialize_pem())?;
                put(&cert, made.cert.pem())?;
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
