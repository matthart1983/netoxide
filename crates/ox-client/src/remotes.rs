//! The boxes this user has saved, in `~/.config/netoxide/remotes.toml`.
//!
//! Each entry has the box's address, the fingerprint of its certificate if
//! it made its own, and an access token. The file holds secrets, so it is
//! readable by its owner only.

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{Remote, Trust, fingerprint_text, parse_fingerprint, parse_url};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saved {
    pub url: String,
    /// `sha256:…` of the box's certificate. Without it, the machine's
    /// certificate authorities decide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub token: String,
}

impl Saved {
    pub fn new(host: &str, port: u16, trust: &Trust, token: &str) -> Saved {
        Saved {
            url: format!("https://{}", crate::authority(host, port)),
            fingerprint: match trust {
                Trust::Pin(fp) => Some(fingerprint_text(fp)),
                Trust::Roots => None,
            },
            token: token.to_string(),
        }
    }

    pub fn remote(&self) -> Result<Remote, String> {
        remote(&self.url, self.fingerprint.as_deref(), &self.token)
    }
}

/// Builds a remote from its parts as text.
pub fn remote(url: &str, fingerprint: Option<&str>, token: &str) -> Result<Remote, String> {
    let (host, port) = parse_url(url)?;
    let token = token.trim();
    if token.is_empty() || token.chars().any(|c| c.is_control() || c == ' ') {
        return Err("the access token is empty or has spaces in it".into());
    }
    Ok(Remote {
        host,
        port,
        trust: match fingerprint {
            Some(text) => Trust::Pin(parse_fingerprint(text)?),
            None => Trust::Roots,
        },
        token: token.to_string(),
    })
}

/// Where the saved boxes are kept: `$OX_REMOTES`, or the user's config directory.
pub fn path() -> Result<PathBuf, String> {
    let var = |name: &str| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if let Some(file) = var("OX_REMOTES") {
        return Ok(file);
    }
    let dir = var("XDG_CONFIG_HOME")
        .or_else(|| var("HOME").map(|h| h.join(".config")))
        .ok_or("cannot tell where your config directory is; set HOME or OX_REMOTES")?;
    Ok(dir.join("netoxide").join("remotes.toml"))
}

pub fn load(file: &Path) -> Result<BTreeMap<String, Saved>, String> {
    match fs::read_to_string(file) {
        Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", file.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(format!("{}: {e}", file.display())),
    }
}

/// Writes the file whole, readable by its owner only from the first byte.
pub fn save(file: &Path, remotes: &BTreeMap<String, Saved>) -> Result<(), String> {
    let err = |e: std::io::Error| format!("{}: {e}", file.display());
    if let Some(dir) = file.parent()
        && !dir.exists()
    {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let text = toml::to_string(remotes).map_err(|e| e.to_string())?;
    let tmp = file.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(err)?;
    f.write_all(text.as_bytes()).map_err(err)?;
    f.sync_all().map_err(err)?;
    fs::rename(&tmp, file).map_err(err)
}

/// Finds a saved box by name.
pub fn find(file: &Path, name: &str) -> Result<Remote, String> {
    let remotes = load(file)?;
    // A token in a file others can read is no longer a secret.
    if let Ok(meta) = fs::metadata(file)
        && meta.permissions().mode() & 0o077 != 0
    {
        return Err(format!(
            "{} holds access tokens and can be read by other users; run chmod 600 on it",
            file.display()
        ));
    }
    let saved = remotes.get(name).ok_or_else(|| {
        let known: Vec<&str> = remotes.keys().map(String::as_str).collect();
        if known.is_empty() {
            format!("no box is saved as '{name}'; save one with `ox remote add {name} <url>`")
        } else {
            format!(
                "no box is saved as '{name}'; the saved ones are {}",
                known.join(", ")
            )
        }
    })?;
    saved
        .remote()
        .map_err(|e| format!("{}: remote '{name}': {e}", file.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remotes_are_saved_private_and_found_again() {
        let dir = std::env::temp_dir().join(format!("ox-remotes-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let file = dir.join("deep").join("remotes.toml");
        assert!(load(&file).unwrap().is_empty());
        assert!(find(&file, "home").unwrap_err().contains("ox remote add"));

        let fp = [7u8; 32];
        let mut all = BTreeMap::new();
        all.insert(
            "home".to_string(),
            Saved::new("2001:db8::1", 8443, &Trust::Pin(fp), "ox_abc"),
        );
        all.insert(
            "office".to_string(),
            Saved::new("fw.example.net", 443, &Trust::Roots, "ox_def"),
        );
        save(&file, &all).unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(file.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(load(&file).unwrap(), all);

        let home = find(&file, "home").unwrap();
        assert_eq!((home.host.as_str(), home.port), ("2001:db8::1", 8443));
        assert_eq!(home.trust, Trust::Pin(fp));
        assert_eq!(find(&file, "office").unwrap().trust, Trust::Roots);
        assert!(find(&file, "lab").unwrap_err().contains("home, office"));

        // A file other users can read is refused, with the fix named.
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(find(&file, "home").unwrap_err().contains("chmod 600"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_entry_is_named() {
        assert!(remote("http://fw", None, "ox_a").is_err());
        assert!(remote("https://fw", Some("sha256:12"), "ox_a").is_err());
        assert!(remote("https://fw", None, " ").is_err());
        assert!(remote("https://fw", None, "ox a").is_err());
        assert_eq!(remote("https://fw", None, " ox_a\n").unwrap().token, "ox_a");
    }
}
