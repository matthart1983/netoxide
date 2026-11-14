//! TLS for the client, and the two ways it knows a box is the right one.
//!
//! - **A saved fingerprint.** A box makes its own certificate on first
//!   start, which no certificate authority has signed. The client keeps the
//!   SHA-256 of that certificate and accepts only it, the way SSH keeps host
//!   keys. The certificate's dates and names are not checked: the
//!   fingerprint says more than either.
//! - **The machine's certificate authorities.** For a box that was given a
//!   certificate from a public or company authority.

use std::{
    net::TcpStream,
    path::Path,
    sync::{Arc, Mutex},
};

use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// Accept exactly the certificate with this SHA-256.
    Pin([u8; 32]),
    /// Accept what this machine's certificate authorities vouch for.
    Roots,
}

pub fn fingerprint_text(fp: &[u8; 32]) -> String {
    format!(
        "sha256:{}",
        fp.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// Reads `sha256:<64 hex digits>`. Colons between bytes and capitals are
/// accepted, since that is how other tools print fingerprints.
pub fn parse_fingerprint(text: &str) -> Result<[u8; 32], String> {
    let bad = || format!("'{text}' is not a fingerprint; it looks like sha256: and 64 hex digits");
    let hex: String = text
        .trim()
        .strip_prefix("sha256:")
        .or_else(|| text.trim().strip_prefix("SHA256:"))
        .ok_or_else(bad)?
        .chars()
        .filter(|c| *c != ':')
        .collect();
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

fn sha256(cert: &CertificateDer<'_>) -> [u8; 32] {
    Sha256::digest(cert.as_ref()).into()
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Checks the certificate against a fingerprint, or records it and accepts
/// anything when there is none. The handshake signature is always checked,
/// so the other end has to hold the certificate's private key.
#[derive(Debug)]
struct Pinned {
    want: Option<[u8; 32]>,
    seen: Mutex<Option<[u8; 32]>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = sha256(end_entity);
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(got);
        match self.want {
            Some(want) if want != got => Err(rustls::Error::General(format!(
                "{MISMATCH} {} but the box offered {}",
                fingerprint_text(&want),
                fingerprint_text(&got)
            ))),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

const MISMATCH: &str = "the saved fingerprint is";

/// The certificate authorities this machine trusts, from the usual files.
fn system_roots() -> Result<RootCertStore, String> {
    let from_env = std::env::var("SSL_CERT_FILE").ok();
    let files = from_env.iter().map(String::as_str).chain([
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ]);
    for file in files {
        let Ok(certs) = CertificateDer::pem_file_iter(Path::new(file)) else {
            continue;
        };
        let mut store = RootCertStore::empty();
        store.add_parsable_certificates(certs.filter_map(Result::ok));
        if !store.is_empty() {
            return Ok(store);
        }
    }
    Err("this machine has no list of certificate authorities where one is usually kept; set SSL_CERT_FILE to a PEM file of them, or save the box's fingerprint with `ox remote add`".into())
}

fn config(verifier: Result<Arc<Pinned>, RootCertStore>) -> Result<Arc<ClientConfig>, String> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(match verifier {
        Ok(pinned) => builder
            .dangerous()
            .with_custom_certificate_verifier(pinned)
            .with_no_client_auth(),
        Err(roots) => builder.with_root_certificates(roots).with_no_client_auth(),
    }))
}

fn pinned(want: Option<[u8; 32]>) -> Arc<Pinned> {
    Arc::new(Pinned {
        want,
        seen: Mutex::new(None),
        provider: provider(),
    })
}

fn name(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_string()).map_err(|_| format!("'{host}' is not a host name"))
}

pub(crate) fn wrap(
    tcp: TcpStream,
    host: &str,
    trust: &Trust,
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let config = match trust {
        Trust::Pin(fp) => config(Ok(pinned(Some(*fp))))?,
        Trust::Roots => config(Err(system_roots()?))?,
    };
    let conn = ClientConnection::new(config, name(host)?).map_err(|e| e.to_string())?;
    Ok(StreamOwned::new(conn, tcp))
}

/// Turns a failure on the wire into words about what to do.
pub(crate) fn explain(e: &std::io::Error, target: &str) -> String {
    let text = e.to_string();
    if text.contains(MISMATCH) {
        return format!(
            "{target} is not showing the certificate saved for it: {text}. If the box's certificate was replaced on purpose, compare the new fingerprint with `ox status` on the box and run `ox remote add` again. If not, something between you and the box may be answering in its place, and the access token was not sent"
        );
    }
    if matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) {
        return format!("{target} did not answer in time");
    }
    if text.contains("UnknownIssuer") || text.contains("invalid peer certificate") {
        return format!(
            "{target} has a certificate this machine does not trust ({text}). A box makes its own certificate unless it is given one; save its fingerprint with `ox remote add`"
        );
    }
    format!("{target}: {text}")
}

/// What a box shows before it is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub fingerprint: [u8; 32],
    /// Whether this machine's certificate authorities vouch for it.
    pub trusted: bool,
}

/// Connects without trusting anything, to see which certificate a box
/// offers. Nothing is sent but the TLS handshake.
pub fn probe(host: &str, port: u16) -> Result<Probe, String> {
    let handshake = |verifier| -> Result<(), String> {
        let mut tcp = crate::connect_tcp(host, port)?;
        let mut conn =
            ClientConnection::new(config(verifier)?, name(host)?).map_err(|e| e.to_string())?;
        while conn.is_handshaking() {
            conn.complete_io(&mut tcp)
                .map_err(|e| explain(&e, &format!("https://{}", crate::authority(host, port))))?;
        }
        Ok(())
    };
    let seen = pinned(None);
    handshake(Ok(seen.clone()))?;
    let fingerprint = seen
        .seen
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .ok_or("the box sent no certificate")?;
    let trusted = system_roots().is_ok_and(|roots| handshake(Err(roots)).is_ok());
    Ok(Probe {
        fingerprint,
        trusted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_round_trip() {
        let mut fp = [0u8; 32];
        for (i, b) in fp.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        let text = fingerprint_text(&fp);
        assert!(text.starts_with("sha256:") && text.len() == 71);
        assert_eq!(parse_fingerprint(&text), Ok(fp));
        assert_eq!(parse_fingerprint(&format!("  {text}\n")), Ok(fp));
        // The way openssl prints one.
        let colons: Vec<String> = fp.iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(
            parse_fingerprint(&format!("SHA256:{}", colons.join(":"))),
            Ok(fp)
        );
        for bad in [
            "",
            "sha256:",
            "sha256:abcd",
            &text[7..],
            &text.replace('0', "g"),
        ] {
            assert!(parse_fingerprint(bad).is_err(), "{bad}");
        }
    }
}
