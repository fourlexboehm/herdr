use std::collections::HashSet;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{ProfileId, MAX_CATALOG_BYTES, MAX_LABEL_BYTES, MAX_PROFILES};
use crate::relay::protocol::{valid_capability, ROUTE_BYTES};

pub(super) const RELAY_CATALOG_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedRelayEndpoint {
    pub(crate) id: ProfileId,
    pub(crate) label: String,
    pub(crate) relay_url: String,
    pub(crate) route_id: String,
    pub(crate) target_public_key: String,
    pub(crate) session: String,
    pub(crate) credential_id: String,
    pub(crate) enabled: bool,
    /// A completed interactive repair requests a fresh connection in open clients.
    #[serde(default)]
    pub(crate) connection_revision: u64,
}

impl SavedRelayEndpoint {
    pub(crate) fn from_invitation(
        invitation: &crate::relay::store::RelayInvitation,
        credential_id: impl Into<String>,
    ) -> Result<Self, String> {
        invitation.validate(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )?;
        let profile = Self {
            id: ProfileId::generate(),
            label: invitation.target_label.clone(),
            relay_url: invitation.relay_url.clone(),
            route_id: invitation.route_id.clone(),
            target_public_key: invitation.target_public_key.clone(),
            session: invitation.session.clone(),
            credential_id: credential_id.into(),
            enabled: true,
            connection_revision: 0,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        ProfileId::parse(self.id.to_string())?;
        let label = self.label.trim();
        if label.is_empty() || label.len() > MAX_LABEL_BYTES || label.chars().any(char::is_control)
        {
            return Err(format!(
                "relay endpoint label must be 1 to {MAX_LABEL_BYTES} bytes with no control characters"
            ));
        }
        crate::relay::store::validate_relay_url(&self.relay_url)?;
        if self.relay_url.len() > 2048 {
            return Err("relay URL exceeds the storage limit".into());
        }
        if !valid_capability(&self.route_id, ROUTE_BYTES) {
            return Err("relay endpoint route id is invalid".into());
        }
        if !valid_capability(&self.target_public_key, 32) {
            return Err("relay endpoint target public key is invalid".into());
        }
        crate::session::validate_name(&self.session)?;
        if self.credential_id.is_empty()
            || self.credential_id.len() > 64
            || self.credential_id.chars().any(char::is_control)
        {
            return Err("relay endpoint credential reference is invalid".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayEndpointCatalog {
    pub(super) version: u32,
    #[serde(default)]
    pub(crate) relay: Vec<SavedRelayEndpoint>,
}

impl Default for RelayEndpointCatalog {
    fn default() -> Self {
        Self {
            version: RELAY_CATALOG_VERSION,
            relay: Vec::new(),
        }
    }
}

impl RelayEndpointCatalog {
    pub(crate) fn load() -> Result<Self, String> {
        Self::load_from_path(&relay_catalog_path())
    }

    pub(crate) fn store(&self) -> Result<(), String> {
        self.store_to_path(&relay_catalog_path())
    }

    pub(crate) fn add(&mut self, profile: SavedRelayEndpoint) -> Result<ProfileId, String> {
        if self.relay.len() >= MAX_PROFILES {
            return Err(format!(
                "at most {MAX_PROFILES} relay endpoints can be saved"
            ));
        }
        profile.validate()?;
        if self.relay.iter().any(|existing| {
            existing.route_id == profile.route_id && existing.session == profile.session
        }) {
            return Err("this relay target and session are already saved".into());
        }
        let id = profile.id.clone();
        self.relay.push(profile);
        Ok(id)
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.version != RELAY_CATALOG_VERSION {
            return Err(format!(
                "unsupported relay endpoint catalog version {}; expected {RELAY_CATALOG_VERSION}",
                self.version
            ));
        }
        if self.relay.len() > MAX_PROFILES {
            return Err(format!(
                "relay endpoint catalog contains more than {MAX_PROFILES} profiles"
            ));
        }
        let mut ids = HashSet::new();
        for profile in &self.relay {
            profile.validate()?;
            if !ids.insert(profile.id.clone()) {
                return Err(format!(
                    "duplicate relay endpoint profile id {}",
                    profile.id
                ));
            }
        }
        Ok(())
    }

    pub(super) fn load_from_path(path: &Path) -> Result<Self, String> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => {
                return Err(format!(
                    "failed to open relay endpoint catalog {}: {error}",
                    path.display()
                ))
            }
        };
        let metadata = file
            .metadata()
            .map_err(|error| format!("failed to inspect relay endpoint catalog: {error}"))?;
        if metadata.len() > MAX_CATALOG_BYTES {
            return Err("relay endpoint catalog exceeds the storage limit".into());
        }
        let mut content = String::new();
        file.take(MAX_CATALOG_BYTES + 1)
            .read_to_string(&mut content)
            .map_err(|error| format!("failed to read relay endpoint catalog: {error}"))?;
        if content.len() as u64 > MAX_CATALOG_BYTES {
            return Err("relay endpoint catalog exceeds the storage limit".into());
        }
        let catalog: Self = serde_json::from_str(&content)
            .map_err(|error| format!("stored relay endpoint catalog is invalid: {error}"))?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub(super) fn store_to_path(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let content = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("failed to encode relay endpoint catalog: {error}"))?;
        super::store_private_json(path, &content, "relay endpoint catalog")
    }
}

pub(crate) fn relay_catalog_path() -> PathBuf {
    crate::config::state_dir()
        .join("client")
        .join("relay-endpoints-v1.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "herdr-relay-endpoint-catalog-{}-{name}",
                std::process::id()
            ))
            .join("relay-endpoints-v1.json")
    }

    #[test]
    fn relay_catalog_roundtrip_contains_no_enrollment_secret() {
        let path = path("roundtrip");
        let mut host =
            crate::relay::store::RelayHostState::create("wss://relay.example", "Studio", "default")
                .unwrap();
        let invitation = host.create_invitation().unwrap();
        let mut catalog = RelayEndpointCatalog::default();
        catalog
            .add(SavedRelayEndpoint::from_invitation(&invitation, "default").unwrap())
            .unwrap();
        catalog.store_to_path(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains(&invitation.enrollment_secret));
        assert_eq!(
            RelayEndpointCatalog::load_from_path(&path).unwrap(),
            catalog
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
