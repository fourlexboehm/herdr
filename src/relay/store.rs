use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::crypto::IdentityKeypair;
use super::protocol::{
    valid_capability, RelayRole, CAPABILITY_BYTES, INVITATION_SECRET_BYTES, RELAY_PROTOCOL_VERSION,
    ROUTE_BYTES,
};
use super::sealed::{self, SEAL_OVERHEAD};

const STORE_VERSION: u8 = 1;
const INVITATION_PREFIX: &str = "herdr-relay-v1:";
const MAX_STATE_BYTES: u64 = 256 * 1024;
const MAX_INVITATIONS: usize = 16;
const MAX_PAIRED_DEVICES: usize = 64;
const DEFAULT_INVITATION_TTL_SECONDS: u64 = 15 * 60;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(1);

/// An invitation consumed by a different public key means the code reached
/// someone else first. Callers report that separately from an ordinary retry so
/// setup can warn instead of advising a fresh exchange.
pub(crate) const INVITATION_ALREADY_USED: &str =
    "relay invitation has already been used by another device";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayInvitation {
    pub(crate) version: u8,
    pub(crate) relay_url: String,
    pub(crate) route_id: String,
    pub(crate) target_public_key: String,
    pub(crate) target_label: String,
    pub(crate) session: String,
    pub(crate) invitation_id: String,
    pub(crate) enrollment_secret: String,
    pub(crate) expires_unix_seconds: u64,
    pub(crate) role: RelayRole,
}

impl RelayInvitation {
    pub(crate) fn encode(&self) -> Result<Zeroizing<String>, String> {
        self.validate(now_unix_seconds())?;
        let json = serde_json::to_vec(self)
            .map_err(|error| format!("failed to encode relay invitation: {error}"))?;
        Ok(Zeroizing::new(format!(
            "{INVITATION_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
        )))
    }

    pub(crate) fn decode(encoded: &str) -> Result<Self, String> {
        let payload = encoded
            .trim()
            .strip_prefix(INVITATION_PREFIX)
            .ok_or("relay invitation has an unsupported format")?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "relay invitation is not valid base64url")?;
        if json.len() as u64 > MAX_STATE_BYTES {
            return Err("relay invitation exceeds the storage limit".into());
        }
        let invitation: Self = serde_json::from_slice(&json)
            .map_err(|error| format!("relay invitation is invalid: {error}"))?;
        invitation.validate(now_unix_seconds())?;
        Ok(invitation)
    }

    pub(crate) fn validate(&self, now: u64) -> Result<(), String> {
        if self.version != RELAY_PROTOCOL_VERSION {
            return Err(format!(
                "unsupported relay invitation version {}; expected {}",
                self.version, RELAY_PROTOCOL_VERSION
            ));
        }
        validate_relay_url(&self.relay_url)?;
        if !valid_capability(&self.route_id, ROUTE_BYTES) {
            return Err("relay invitation contains an invalid route id".into());
        }
        if !valid_capability(&self.target_public_key, 32) {
            return Err("relay invitation contains an invalid target identity".into());
        }
        if !valid_hex_id(&self.invitation_id) {
            return Err("relay invitation contains an invalid invitation id".into());
        }
        if !valid_capability(&self.enrollment_secret, INVITATION_SECRET_BYTES) {
            return Err("relay invitation contains an invalid enrollment secret".into());
        }
        validate_label(&self.target_label)?;
        validate_session(&self.session)?;
        if self.expires_unix_seconds <= now {
            return Err("relay invitation has expired".into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn enrollment_secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        decode_fixed(
            &self.enrollment_secret,
            INVITATION_SECRET_BYTES,
            "enrollment secret",
        )
        .map(Zeroizing::new)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingInvitation {
    pub(crate) id: String,
    pub(crate) enrollment_secret: String,
    pub(crate) expires_unix_seconds: u64,
    pub(crate) role: RelayRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) consumed_by: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairedDevice {
    pub(crate) public_key: String,
    pub(crate) label: String,
    pub(crate) role: RelayRole,
    pub(crate) paired_unix_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayHostState {
    version: u8,
    pub(crate) enabled: bool,
    pub(crate) relay_url: String,
    pub(crate) route_id: String,
    pub(crate) registration_capability: String,
    pub(crate) target_label: String,
    pub(crate) session: String,
    private_key: String,
    public_key: String,
    pub(crate) invitations: Vec<PendingInvitation>,
    pub(crate) paired_devices: Vec<PairedDevice>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientPairingSecret {
    pub(crate) invitation_id: String,
    pub(crate) enrollment_secret: String,
    pub(crate) expires_unix_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayClientCredential {
    pub(crate) id: String,
    private_key: String,
    public_key: String,
    pub(crate) pairing: Option<ClientPairingSecret>,
}

impl RelayClientCredential {
    pub(crate) fn identity(&self) -> Result<IdentityKeypair, String> {
        IdentityKeypair::from_parts(
            decode_fixed(&self.private_key, 32, "relay client private key")?,
            decode_fixed(&self.public_key, 32, "relay client public key")?,
        )
        .map_err(|error| error.to_string())
    }

    pub(crate) fn pairing_secret(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        let Some(pairing) = &self.pairing else {
            return Ok(None);
        };
        if pairing.expires_unix_seconds <= now_unix_seconds() {
            return Err("relay pairing invitation has expired".into());
        }
        decode_fixed(
            &pairing.enrollment_secret,
            INVITATION_SECRET_BYTES,
            "relay enrollment secret",
        )
        .map(Zeroizing::new)
        .map(Some)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayClientStore {
    version: u8,
    pub(crate) credentials: Vec<RelayClientCredential>,
}

impl Default for RelayClientStore {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            credentials: Vec::new(),
        }
    }
}

impl RelayClientStore {
    pub(crate) fn load() -> Result<Self, String> {
        Self::load_from_path(&client_store_path())
    }

    fn load_from_path(path: &Path) -> Result<Self, String> {
        let Some(content) = read_store_bytes(path, "relay client credentials")? else {
            return Ok(Self::default());
        };
        let store: Self = serde_json::from_slice(&content)
            .map_err(|error| format!("stored relay client credentials are invalid: {error}"))?;
        store.validate()?;
        Ok(store)
    }

    pub(crate) fn update<T>(
        mutation: impl FnOnce(&mut Self) -> Result<T, String>,
    ) -> Result<T, String> {
        let path = client_store_path();
        with_store_lock(&path, "relay client credentials", || {
            let mut store = Self::load_from_path(&path)?;
            let result = mutation(&mut store)?;
            store.store_to_path(&path)?;
            Ok(result)
        })
    }

    fn store_to_path(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let content = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("failed to encode relay client credentials: {error}"))?;
        store_private_json(path, &content, "relay client credentials")
    }

    pub(crate) fn import_invitation(
        &mut self,
        invitation: &RelayInvitation,
    ) -> Result<String, String> {
        invitation.validate(now_unix_seconds())?;
        if self.credentials.len() >= MAX_PAIRED_DEVICES {
            return Err(format!(
                "at most {MAX_PAIRED_DEVICES} relay client credentials may be stored"
            ));
        }
        let identity = IdentityKeypair::generate()
            .map_err(|error| format!("failed to generate controller identity: {error}"))?;
        let id = random_hex_id()?;
        self.credentials.push(RelayClientCredential {
            id: id.clone(),
            private_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(identity.private()),
            public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(identity.public()),
            pairing: Some(ClientPairingSecret {
                invitation_id: invitation.invitation_id.clone(),
                enrollment_secret: invitation.enrollment_secret.clone(),
                expires_unix_seconds: invitation.expires_unix_seconds,
            }),
        });
        Ok(id)
    }

    pub(crate) fn renew_invitation(
        &mut self,
        id: &str,
        invitation: &RelayInvitation,
    ) -> Result<(), String> {
        invitation.validate(now_unix_seconds())?;
        let credential = self
            .credentials
            .iter_mut()
            .find(|credential| credential.id == id)
            .ok_or("relay client credential is missing")?;
        credential.pairing = Some(ClientPairingSecret {
            invitation_id: invitation.invitation_id.clone(),
            enrollment_secret: invitation.enrollment_secret.clone(),
            expires_unix_seconds: invitation.expires_unix_seconds,
        });
        Ok(())
    }

    pub(crate) fn credential(&self, id: &str) -> Option<&RelayClientCredential> {
        self.credentials
            .iter()
            .find(|credential| credential.id == id)
    }

    pub(crate) fn complete_pairing(&mut self, id: &str) -> Result<(), String> {
        let credential = self
            .credentials
            .iter_mut()
            .find(|credential| credential.id == id)
            .ok_or("relay client credential is missing")?;
        credential.pairing = None;
        Ok(())
    }

    pub(crate) fn remove(&mut self, id: &str) -> bool {
        let previous = self.credentials.len();
        self.credentials.retain(|credential| credential.id != id);
        previous != self.credentials.len()
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != STORE_VERSION {
            return Err(format!(
                "unsupported relay client credential version {}; expected {STORE_VERSION}",
                self.version
            ));
        }
        if self.credentials.len() > MAX_PAIRED_DEVICES {
            return Err("too many relay client credentials are stored".into());
        }
        let mut ids = std::collections::HashSet::new();
        for credential in &self.credentials {
            if !valid_hex_id(&credential.id) || !ids.insert(&credential.id) {
                return Err("stored relay client credential id is invalid or duplicated".into());
            }
            decode_fixed(&credential.private_key, 32, "relay client private key")?;
            decode_fixed(&credential.public_key, 32, "relay client public key")?;
            if let Some(pairing) = &credential.pairing {
                if !valid_hex_id(&pairing.invitation_id)
                    || !valid_capability(&pairing.enrollment_secret, INVITATION_SECRET_BYTES)
                {
                    return Err("stored relay pairing credential is invalid".into());
                }
            }
        }
        Ok(())
    }
}

impl RelayHostState {
    pub(crate) fn configuration_id(&self) -> String {
        use sha2::{Digest as _, Sha256};
        let mut digest = Sha256::new();
        for field in [
            &self.route_id,
            &self.relay_url,
            &self.session,
            &self.public_key,
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.finalize())
    }

    pub(crate) fn same_host_configuration(&self, other: &Self) -> bool {
        self.route_id == other.route_id
            && self.relay_url == other.relay_url
            && self.session == other.session
            && self.private_key == other.private_key
            && self.public_key == other.public_key
            && self.registration_capability == other.registration_capability
    }

    pub(crate) fn create(
        relay_url: &str,
        target_label: &str,
        session: &str,
    ) -> Result<Self, String> {
        validate_relay_url(relay_url)?;
        validate_label(target_label)?;
        validate_session(session)?;
        let identity = IdentityKeypair::generate()
            .map_err(|error| format!("failed to generate relay identity: {error}"))?;
        Ok(Self {
            version: STORE_VERSION,
            enabled: true,
            relay_url: relay_url.trim_end_matches('/').to_owned(),
            route_id: random_capability(ROUTE_BYTES)?,
            registration_capability: random_capability(CAPABILITY_BYTES)?,
            target_label: target_label.to_owned(),
            session: session.to_owned(),
            private_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(identity.private()),
            public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(identity.public()),
            invitations: Vec::new(),
            paired_devices: Vec::new(),
        })
    }

    pub(crate) fn load() -> Result<Option<Self>, String> {
        Self::load_from_path(&host_state_path())
    }

    pub(crate) fn load_from_path(path: &Path) -> Result<Option<Self>, String> {
        let Some(content) = read_store_bytes(path, "relay host state")? else {
            return Ok(None);
        };
        let mut state: Self = serde_json::from_slice(&content)
            .map_err(|error| format!("stored relay host state is invalid: {error}"))?;
        state.validate()?;
        state.prune_expired_invitations(now_unix_seconds());
        Ok(Some(state))
    }

    pub(crate) fn update<T>(
        mutation: impl FnOnce(Option<Self>) -> Result<(Option<Self>, T), String>,
    ) -> Result<T, String> {
        Self::update_from_path(&host_state_path(), mutation)
    }

    fn update_from_path<T>(
        path: &Path,
        mutation: impl FnOnce(Option<Self>) -> Result<(Option<Self>, T), String>,
    ) -> Result<T, String> {
        with_store_lock(path, "relay host state", || {
            let current = Self::load_from_path(path)?;
            let (next, result) = mutation(current)?;
            if let Some(next) = next {
                next.store_to_path(path)?;
            }
            Ok(result)
        })
    }

    pub(crate) fn store_to_path(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let content = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("failed to encode relay host state: {error}"))?;
        store_private_json(path, &content, "relay host state")
    }

    pub(crate) fn identity(&self) -> Result<IdentityKeypair, String> {
        IdentityKeypair::from_parts(
            decode_fixed(&self.private_key, 32, "relay private key")?,
            decode_fixed(&self.public_key, 32, "relay public key")?,
        )
        .map_err(|error| error.to_string())
    }

    pub(crate) fn public_key_bytes(&self) -> Result<Vec<u8>, String> {
        decode_fixed(&self.public_key, 32, "relay public key")
    }

    pub(crate) fn create_invitation(&mut self) -> Result<RelayInvitation, String> {
        let now = now_unix_seconds();
        self.prune_expired_invitations(now);
        if self.invitations.len() >= MAX_INVITATIONS {
            return Err(format!(
                "at most {MAX_INVITATIONS} unexpired relay invitations may exist"
            ));
        }
        let secret = random_capability(INVITATION_SECRET_BYTES)?;
        let id = random_hex_id()?;
        let expires = now.saturating_add(DEFAULT_INVITATION_TTL_SECONDS);
        self.invitations.push(PendingInvitation {
            id: id.clone(),
            enrollment_secret: secret.clone(),
            expires_unix_seconds: expires,
            role: RelayRole::Controller,
            consumed_by: None,
        });
        Ok(RelayInvitation {
            version: RELAY_PROTOCOL_VERSION,
            relay_url: self.relay_url.clone(),
            route_id: self.route_id.clone(),
            target_public_key: self.public_key.clone(),
            target_label: self.target_label.clone(),
            session: self.session.clone(),
            invitation_id: id,
            enrollment_secret: secret,
            expires_unix_seconds: expires,
            role: RelayRole::Controller,
        })
    }

    pub(crate) fn invitation_secret(&self, id: &str) -> Option<Zeroizing<Vec<u8>>> {
        let now = now_unix_seconds();
        self.invitations
            .iter()
            .find(|invitation| invitation.id == id && invitation.expires_unix_seconds > now)
            .and_then(|invitation| {
                decode_fixed(
                    &invitation.enrollment_secret,
                    INVITATION_SECRET_BYTES,
                    "enrollment secret",
                )
                .ok()
            })
            .map(Zeroizing::new)
    }

    /// Returns whether this confirmation added a new paired device. A repaired
    /// controller whose earlier confirmation was lost returns `false`.
    pub(crate) fn complete_pairing(
        &mut self,
        invitation_id: &str,
        public_key: &[u8],
        label: &str,
    ) -> Result<bool, String> {
        validate_label(label)?;
        let invitation_index = self
            .invitations
            .iter()
            .position(|invitation| {
                invitation.id == invitation_id
                    && invitation.expires_unix_seconds > now_unix_seconds()
            })
            .ok_or("relay invitation is missing, expired, or already used")?;
        let invitation = self.invitations[invitation_index].clone();
        let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key);
        if let Some(consumed_by) = &invitation.consumed_by {
            if consumed_by != &public_key {
                return Err(INVITATION_ALREADY_USED.into());
            }
            if self
                .paired_devices
                .iter()
                .any(|device| device.public_key == public_key)
            {
                return Ok(false);
            }
            // The same device consumed this invitation and was revoked since.
            // Revocation stays sticky; only a new invitation can re-pair it.
            return Err(
                "relay invitation was already used by this device, which has since been revoked"
                    .into(),
            );
        }
        if self
            .paired_devices
            .iter()
            .any(|device| device.public_key == public_key)
        {
            // A fresh invitation can repair a controller whose confirmation was lost.
            self.invitations[invitation_index].consumed_by = Some(public_key);
            return Ok(false);
        }
        if self.paired_devices.len() >= MAX_PAIRED_DEVICES {
            return Err(format!(
                "at most {MAX_PAIRED_DEVICES} controller devices may be paired"
            ));
        }
        self.paired_devices.push(PairedDevice {
            public_key: public_key.clone(),
            label: label.to_owned(),
            role: invitation.role,
            paired_unix_seconds: now_unix_seconds(),
        });
        self.invitations[invitation_index].consumed_by = Some(public_key);
        Ok(true)
    }

    pub(crate) fn paired_device(&self, public_key: &[u8]) -> Option<&PairedDevice> {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key);
        self.paired_devices
            .iter()
            .find(|device| device.public_key == encoded)
    }

    pub(crate) fn revoke(&mut self, public_key: &str) -> bool {
        let previous = self.paired_devices.len();
        self.paired_devices
            .retain(|device| device.public_key != public_key);
        self.paired_devices.len() != previous
    }

    fn prune_expired_invitations(&mut self, now: u64) {
        self.invitations
            .retain(|invitation| invitation.expires_unix_seconds > now);
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != STORE_VERSION {
            return Err(format!(
                "unsupported relay host state version {}; expected {STORE_VERSION}",
                self.version
            ));
        }
        validate_relay_url(&self.relay_url)?;
        validate_label(&self.target_label)?;
        validate_session(&self.session)?;
        if !valid_capability(&self.route_id, ROUTE_BYTES) {
            return Err("stored relay route id is invalid".into());
        }
        if !valid_capability(&self.registration_capability, CAPABILITY_BYTES) {
            return Err("stored relay registration capability is invalid".into());
        }
        decode_fixed(&self.private_key, 32, "relay private key")?;
        decode_fixed(&self.public_key, 32, "relay public key")?;
        if self.invitations.len() > MAX_INVITATIONS
            || self.paired_devices.len() > MAX_PAIRED_DEVICES
        {
            return Err("stored relay authorization list exceeds its limit".into());
        }
        let mut invitation_ids = HashSet::new();
        for invitation in &self.invitations {
            if !invitation_ids.insert(&invitation.id) || !valid_hex_id(&invitation.id) {
                return Err("stored relay invitation id is invalid or duplicated".into());
            }
            if !valid_capability(&invitation.enrollment_secret, INVITATION_SECRET_BYTES) {
                return Err("stored relay invitation secret is invalid".into());
            }
            if invitation
                .consumed_by
                .as_ref()
                .is_some_and(|public_key| !valid_capability(public_key, 32))
            {
                return Err("stored relay invitation consumer is invalid".into());
            }
        }
        let mut device_keys = HashSet::new();
        for device in &self.paired_devices {
            if !device_keys.insert(&device.public_key) || !valid_capability(&device.public_key, 32)
            {
                return Err("stored relay device identity is invalid or duplicated".into());
            }
            validate_label(&device.label)?;
        }
        Ok(())
    }
}

pub(crate) fn host_state_path() -> PathBuf {
    crate::config::state_dir()
        .join("relay")
        .join("host-v1.json")
}

pub(crate) fn client_store_path() -> PathBuf {
    crate::config::state_dir()
        .join("relay")
        .join("client-credentials-v1.json")
}

fn with_store_lock<T>(
    path: &Path,
    description: &str,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid {description} path: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {description} directory: {error}"))?;
    let lock_path = path.with_extension("lock");
    if let Ok(metadata) = std::fs::symlink_metadata(&lock_path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "refusing to lock {description} through a non-file path"
            ));
        }
    }
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| format!("failed to open {description} lock: {error}"))?;
    lock.lock()
        .map_err(|error| format!("failed to lock {description}: {error}"))?;
    operation()
}

/// Resolved once per process: `update()` reads and writes in one lock, and a
/// keychain fetch can prompt, so it must not happen twice per operation.
static AT_REST_KEY: OnceLock<Option<Zeroizing<Vec<u8>>>> = OnceLock::new();

/// Master key protecting relay state at rest, or `None` where the platform has
/// no system keystore and state stays plaintext JSON.
fn at_rest_key() -> Result<Option<&'static Zeroizing<Vec<u8>>>, String> {
    if let Some(cached) = AT_REST_KEY.get() {
        return Ok(cached.as_ref());
    }
    // Unit tests must exercise the sealed path without touching the real
    // login keychain, which would prompt and persist an item on developer Macs.
    #[cfg(test)]
    let key = Some(Zeroizing::new(vec![0x5a_u8; 32]));
    #[cfg(not(test))]
    let key = crate::platform::relay_state_key()
        .map_err(|error| format!("failed to open the relay key in the keychain: {error}"))?;
    Ok(AT_REST_KEY.get_or_init(|| key).as_ref())
}

/// Reads a relay state file, unsealing it when it is sealed.
///
/// Plaintext files are still accepted so an install that predates at-rest
/// protection keeps working; the next write reseals them.
fn read_store_bytes(path: &Path, description: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("failed to read {description}: {error}")),
    };
    if raw.len() as u64 > MAX_STATE_BYTES.saturating_add(SEAL_OVERHEAD as u64) {
        return Err(format!("{description} exceeds the storage limit"));
    }
    let content = if sealed::is_sealed(&raw) {
        let key = at_rest_key()?.ok_or_else(|| {
            format!("{description} is encrypted but this platform has no keychain to unlock it")
        })?;
        sealed::open(key, &raw)?
    } else {
        Zeroizing::new(raw)
    };
    if content.len() as u64 > MAX_STATE_BYTES {
        return Err(format!("{description} exceeds the storage limit"));
    }
    Ok(Some(content))
}

fn store_private_json(path: &Path, content: &[u8], description: &str) -> Result<(), String> {
    if content.len() as u64 > MAX_STATE_BYTES {
        return Err(format!("{description} exceeds the storage limit"));
    }
    // A plaintext file from an older install is resealed by this write.
    let sealed = match at_rest_key()? {
        Some(key) => Some(sealed::seal(key, content)?),
        None => None,
    };
    let content = sealed.as_deref().unwrap_or(content);
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid {description} path: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {description} directory: {error}"))?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "refusing to replace {description} through a non-file path"
            ));
        }
    }
    let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let temp_path = parent.join(format!(".relay-{}-{sequence}.tmp", std::process::id()));
    let mut temp = crate::platform::create_private_state_file(&temp_path)
        .map_err(|error| format!("failed to create {description}: {error}"))?;
    if let Err(error) = temp.write_all(content).and_then(|()| temp.sync_all()) {
        drop(temp);
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("failed to write {description}: {error}"));
    }
    drop(temp);
    if let Err(error) = crate::platform::replace_file(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("failed to activate {description}: {error}"));
    }
    crate::platform::sync_parent_directory(parent)
        .map_err(|error| format!("failed to persist {description} directory: {error}"))
}

fn random_capability(bytes: usize) -> Result<String, String> {
    let mut value = Zeroizing::new(vec![0_u8; bytes]);
    getrandom::fill(&mut value)
        .map_err(|error| format!("failed to obtain operating-system randomness: {error}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*value))
}

fn random_hex_id() -> Result<String, String> {
    let mut value = [0_u8; 16];
    getrandom::fill(&mut value)
        .map_err(|error| format!("failed to obtain operating-system randomness: {error}"))?;
    Ok(value.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn decode_fixed(value: &str, bytes: usize, description: &str) -> Result<Vec<u8>, String> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("{description} is not valid base64url"))?;
    if decoded.len() != bytes {
        return Err(format!("{description} has an invalid length"));
    }
    Ok(decoded)
}

pub(crate) fn validate_relay_url(value: &str) -> Result<(), String> {
    let value = value.trim();
    let secure = value
        .strip_prefix("wss://")
        .is_some_and(|authority| !authority.is_empty() && !authority.starts_with('/'));
    let debug_loopback = cfg!(debug_assertions) && is_loopback_ws_url(value);
    if (!secure && !debug_loopback) || value.contains(['?', '#', '\0']) {
        return Err("relay URL must be an absolute wss:// URL without query or fragment".into());
    }
    Ok(())
}

fn is_loopback_ws_url(value: &str) -> bool {
    let Some(remainder) = value.strip_prefix("ws://") else {
        return false;
    };
    let authority = remainder.split('/').next().unwrap_or_default();
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    matches!(host, "127.0.0.1" | "localhost")
        && port.is_none_or(|port| !port.is_empty() && port.parse::<u16>().is_ok())
}

fn validate_label(value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 96 || value.contains(['\n', '\r', '\0']) {
        Err("relay device label must contain 1 to 96 single-line bytes".into())
    } else {
        Ok(())
    }
}

fn validate_session(value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 128 || value.contains(['/', '\\', '\0']) {
        Err("relay session name is invalid".into())
    } else {
        Ok(())
    }
}

fn valid_hex_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("herdr-relay-store-{}-{name}", std::process::id()))
            .join("host-v1.json")
    }

    #[test]
    fn invitation_roundtrip_is_versioned_and_secret_bearing() {
        let mut state = RelayHostState::create("wss://relay.example", "studio", "default").unwrap();
        let invitation = state.create_invitation().unwrap();
        let encoded = invitation.encode().unwrap();
        assert_eq!(RelayInvitation::decode(&encoded).unwrap(), invitation);
        assert!(!encoded.contains(&state.registration_capability));
        assert!(invitation.enrollment_secret_bytes().is_ok());
    }

    #[test]
    fn host_state_roundtrip_uses_separate_private_file() {
        let path = path("roundtrip");
        let mut state = RelayHostState::create("wss://relay.example", "studio", "default").unwrap();
        state.create_invitation().unwrap();
        state.store_to_path(&path).unwrap();
        assert_eq!(RelayHostState::load_from_path(&path).unwrap(), Some(state));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn concurrent_host_updates_preserve_both_mutations() {
        let path = path("concurrent-update");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        RelayHostState::create("wss://relay.example", "studio", "default")
            .unwrap()
            .store_to_path(&path)
            .unwrap();
        let start = std::sync::Arc::new(std::sync::Barrier::new(3));

        std::thread::scope(|scope| {
            for _ in 0..2 {
                let start = start.clone();
                let path = path.clone();
                scope.spawn(move || {
                    start.wait();
                    RelayHostState::update_from_path(&path, |current| {
                        let mut current = current.ok_or("missing relay host state")?;
                        current.create_invitation()?;
                        Ok((Some(current), ()))
                    })
                    .unwrap();
                });
            }
            start.wait();
        });

        let state = RelayHostState::load_from_path(&path).unwrap().unwrap();
        assert_eq!(state.invitations.len(), 2);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn pairing_consumes_invitation_and_revocation_is_independent() {
        let mut state = RelayHostState::create("wss://relay.example", "studio", "default").unwrap();
        let invitation = state.create_invitation().unwrap();
        let device = IdentityKeypair::generate().unwrap();
        assert!(state
            .complete_pairing(&invitation.invitation_id, device.public(), "laptop")
            .unwrap());
        assert!(state.invitation_secret(&invitation.invitation_id).is_some());
        let other = IdentityKeypair::generate().unwrap();
        assert_eq!(
            state
                .complete_pairing(&invitation.invitation_id, other.public(), "other")
                .unwrap_err(),
            INVITATION_ALREADY_USED
        );
        let public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(device.public());
        assert!(state.revoke(&public));
        assert!(state.paired_devices.is_empty());
        // A revoked device retrying its own consumed code is not a stolen code.
        assert_ne!(
            state
                .complete_pairing(&invitation.invitation_id, device.public(), "laptop")
                .unwrap_err(),
            INVITATION_ALREADY_USED
        );
    }

    #[test]
    fn consumed_invitation_retry_is_idempotent_at_device_capacity() {
        let mut state = RelayHostState::create("wss://relay.example", "studio", "default").unwrap();
        let invitation = state.create_invitation().unwrap();
        let device = IdentityKeypair::generate().unwrap();
        state
            .complete_pairing(&invitation.invitation_id, device.public(), "laptop")
            .unwrap();
        while state.paired_devices.len() < MAX_PAIRED_DEVICES {
            let other = IdentityKeypair::generate().unwrap();
            state.paired_devices.push(PairedDevice {
                public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(other.public()),
                label: format!("device-{}", state.paired_devices.len()),
                role: RelayRole::Controller,
                paired_unix_seconds: now_unix_seconds(),
            });
        }
        state
            .complete_pairing(&invitation.invitation_id, device.public(), "laptop")
            .unwrap();
    }

    #[test]
    fn stored_invitation_consumer_must_be_a_public_key() {
        let path = path("invalid-consumer");
        let mut state = RelayHostState::create("wss://relay.example", "studio", "default").unwrap();
        state.create_invitation().unwrap();
        state.invitations[0].consumed_by = Some("invalid".into());
        assert!(state.store_to_path(&path).is_err());
    }

    #[test]
    fn completing_client_pairing_erases_the_enrollment_secret() {
        let path = path("client");
        let mut host = RelayHostState::create("wss://relay.example", "studio", "default").unwrap();
        let invitation = host.create_invitation().unwrap();
        let mut clients = RelayClientStore::default();
        let id = clients.import_invitation(&invitation).unwrap();
        clients.store_to_path(&path).unwrap();
        let reloaded = RelayClientStore::load_from_path(&path).unwrap();
        assert_eq!(
            reloaded
                .credential(&id)
                .and_then(|credential| credential.pairing.as_ref())
                .map(|pairing| pairing.enrollment_secret.as_str()),
            Some(invitation.enrollment_secret.as_str())
        );
        clients.complete_pairing(&id).unwrap();
        clients.store_to_path(&path).unwrap();
        assert!(RelayClientStore::load_from_path(&path)
            .unwrap()
            .credential(&id)
            .is_some_and(|credential| credential.pairing.is_none()));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn stored_state_is_sealed_and_leaks_no_secret_bytes() {
        let path = path("sealed");
        let mut state = RelayHostState::create("wss://relay.example", "studio", "default").unwrap();
        let invitation = state.create_invitation().unwrap();
        state.store_to_path(&path).unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(sealed::is_sealed(&raw));
        // Every secret the host state carries must be absent from the file.
        for secret in [
            &state.private_key,
            &state.registration_capability,
            &invitation.enrollment_secret,
        ] {
            assert!(
                !raw.windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "a secret survived in the sealed file"
            );
        }
        assert_eq!(RelayHostState::load_from_path(&path).unwrap(), Some(state));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn plaintext_state_from_an_older_install_still_loads_and_is_resealed() {
        let path = path("migrate");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let state = RelayHostState::create("wss://relay.example", "studio", "default").unwrap();

        // Exactly what a pre-encryption install left on disk.
        std::fs::write(&path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
        assert!(!sealed::is_sealed(&std::fs::read(&path).unwrap()));
        assert_eq!(
            RelayHostState::load_from_path(&path).unwrap(),
            Some(state.clone())
        );

        RelayHostState::update_from_path(&path, |current| Ok((current, ()))).unwrap();
        assert!(sealed::is_sealed(&std::fs::read(&path).unwrap()));
        assert_eq!(RelayHostState::load_from_path(&path).unwrap(), Some(state));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn corrupted_sealed_state_is_an_error_rather_than_a_silent_reset() {
        let path = path("corrupt");
        RelayHostState::create("wss://relay.example", "studio", "default")
            .unwrap()
            .store_to_path(&path)
            .unwrap();
        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        std::fs::write(&path, &raw).unwrap();
        // A load that silently returned None here would re-enroll the host and
        // orphan every paired controller.
        assert!(RelayHostState::load_from_path(&path).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn relay_urls_require_tls_except_for_debug_loopback() {
        assert!(validate_relay_url("wss://relay.example").is_ok());
        assert!(validate_relay_url("https://relay.example").is_err());
        assert!(validate_relay_url("ws://relay.example").is_err());
        assert!(validate_relay_url("wss://relay.example?secret=value").is_err());
        if cfg!(debug_assertions) {
            assert!(validate_relay_url("ws://127.0.0.1:8787").is_ok());
            assert!(validate_relay_url("ws://localhost:8787").is_ok());
            assert!(validate_relay_url("ws://localhost.evil:8787").is_err());
        }
    }
}
