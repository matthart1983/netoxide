//! Who may do what: roles, access tokens, and the four-eyes setting.

use std::{fs, io::Read, path::Path};

use serde::{Deserialize, Serialize};

use crate::audit::sha256_hex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Reads the config, candidates, plans and status.
    Viewer,
    /// A viewer who may also read the audit log.
    Auditor,
    /// Saves candidates, approves, commits, confirms and reverts.
    Operator,
    /// Everything, including rollback, tokens and settings.
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Auditor => "auditor",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        [Role::Viewer, Role::Auditor, Role::Operator, Role::Admin]
            .into_iter()
            .find(|r| r.as_str() == s)
    }

    /// Whether this role may perform an action.
    pub fn may(self, action: Action) -> bool {
        match action {
            Action::Read => true,
            Action::ReadAudit => self != Role::Viewer,
            Action::Edit | Action::Approve | Action::Commit => {
                matches!(self, Role::Operator | Role::Admin)
            }
            Action::Rollback | Action::Manage => self == Role::Admin,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Status, running config, candidates, plans, explain, leases, kernel.
    Read,
    ReadAudit,
    /// Save and delete candidates.
    Edit,
    Approve,
    /// Commit, confirm and revert.
    Commit,
    Rollback,
    /// Tokens and settings.
    Manage,
}

impl Action {
    pub fn describe(self) -> &'static str {
        match self {
            Action::Read => "read the config and status",
            Action::ReadAudit => "read the audit log",
            Action::Edit => "save or delete candidates",
            Action::Approve => "approve candidates",
            Action::Commit => "commit, confirm or revert",
            Action::Rollback => "roll back",
            Action::Manage => "manage tokens and settings",
        }
    }
}

/// A caller, after the daemon has worked out who it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub role: Role,
}

/// An access token as stored. The secret itself is never kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub name: String,
    pub role: Role,
    /// SHA-256 of the secret.
    pub sha256: String,
    pub created: u64,
    /// Unix time after which the token stops working.
    pub expires: Option<u64>,
    pub created_by: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// A commit needs approval from someone other than the candidate's author.
    #[serde(default)]
    pub four_eyes: bool,
}

/// Approval state of a candidate, stored beside it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateMeta {
    /// Who saved the candidate last.
    pub author: String,
    pub saved_at: u64,
    /// SHA-256 of the candidate text the fields below refer to.
    pub sha256: String,
    pub approved_by: Option<String>,
    pub approved_at: Option<u64>,
}

/// 32 random bytes from the kernel, as a token secret.
pub(crate) fn new_secret() -> std::io::Result<String> {
    let mut bytes = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(format!(
        "ox_{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

pub(crate) fn load<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T, String> {
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Finds the token a secret belongs to, if it is still valid.
pub(crate) fn verify(tokens: &[Token], secret: &str, now: u64) -> Option<Identity> {
    let hash = sha256_hex(secret.as_bytes());
    tokens
        .iter()
        .find(|t| t.sha256 == hash && t.expires.is_none_or(|e| now < e))
        .map(|t| Identity {
            name: format!("token:{}", t.name),
            role: t.role,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_allow_what_they_should() {
        use Action::*;
        let table = [
            (Role::Viewer, vec![Read]),
            (Role::Auditor, vec![Read, ReadAudit]),
            (Role::Operator, vec![Read, ReadAudit, Edit, Approve, Commit]),
            (
                Role::Admin,
                vec![Read, ReadAudit, Edit, Approve, Commit, Rollback, Manage],
            ),
        ];
        for (role, allowed) in table {
            for action in [Read, ReadAudit, Edit, Approve, Commit, Rollback, Manage] {
                assert_eq!(
                    role.may(action),
                    allowed.contains(&action),
                    "{role:?} {action:?}"
                );
            }
        }
        assert_eq!(Role::parse("operator"), Some(Role::Operator));
        assert_eq!(Role::parse("root"), None);
    }

    #[test]
    fn secrets_are_long_and_differ() {
        let (a, b) = (new_secret().unwrap(), new_secret().unwrap());
        assert!(a.starts_with("ox_") && a.len() == 67);
        assert_ne!(a, b);
    }
}
