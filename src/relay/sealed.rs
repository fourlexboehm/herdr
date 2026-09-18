//! At-rest protection for the relay state files.
//!
//! The relay stores long-lived X25519 identity private keys, the registration
//! capability, and live enrollment secrets. On platforms with a system
//! keystore the master key lives there (see `platform::relay_state_key`) and
//! these files hold only ciphertext, so copying the state directory off the
//! machine does not yield a usable controller identity.
//!
//! Layout:
//!
//! ```text
//! MAGIC (16) | VERSION (1) | SALT (32) | ChaCha20-Poly1305(plaintext) || TAG (16)
//! ```
//!
//! Each write draws a fresh salt and derives a single-use key from it, so the
//! nonce is always zero and no counter has to be tracked across writes. The
//! header is the AEAD associated data, which binds the version and salt to the
//! ciphertext.

use snow::params::CipherChoice;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::Cipher;
use zeroize::Zeroizing;

const MAGIC: &[u8; 16] = b"herdr-relay-seal";
const SEAL_VERSION: u8 = 1;
const SALT_BYTES: usize = 32;
const KEY_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = MAGIC.len() + 1 + SALT_BYTES;
/// Bytes a seal adds on top of the plaintext it protects.
pub(crate) const SEAL_OVERHEAD: usize = HEADER_BYTES + TAG_BYTES;
/// Domain separator, so this key derivation cannot collide with another use of
/// the same Keychain secret.
const DERIVATION_LABEL: &[u8] = b"herdr relay state seal v1";

/// Whether stored bytes are sealed rather than plaintext JSON.
///
/// Existing installs have plaintext state files; callers use this to accept
/// both and reseal on the next write.
pub(crate) fn is_sealed(stored: &[u8]) -> bool {
    stored.starts_with(MAGIC)
}

/// Derives the single-use content key for one salt.
fn derive_key(master: &[u8], salt: &[u8]) -> Zeroizing<[u8; KEY_BYTES]> {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    for input in [DERIVATION_LABEL, master, salt] {
        digest.update((input.len() as u64).to_be_bytes());
        digest.update(input);
    }
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    key.copy_from_slice(&digest.finalize());
    key
}

fn cipher(key: &[u8; KEY_BYTES]) -> Result<Box<dyn Cipher>, String> {
    let mut cipher = DefaultResolver
        .resolve_cipher(&CipherChoice::ChaChaPoly)
        .ok_or("the built-in ChaCha20-Poly1305 cipher is unavailable")?;
    cipher.set(key);
    Ok(cipher)
}

/// Seals `plaintext` under `master`, producing bytes safe to leave on disk.
pub(crate) fn seal(master: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if master.len() != KEY_BYTES {
        return Err("relay at-rest key has an invalid length".into());
    }
    let mut salt = [0_u8; SALT_BYTES];
    getrandom::fill(&mut salt)
        .map_err(|error| format!("failed to obtain operating-system randomness: {error}"))?;

    let mut sealed = Vec::with_capacity(HEADER_BYTES + plaintext.len() + TAG_BYTES);
    sealed.extend_from_slice(MAGIC);
    sealed.push(SEAL_VERSION);
    sealed.extend_from_slice(&salt);
    let header_end = sealed.len();
    sealed.resize(header_end + plaintext.len() + TAG_BYTES, 0);

    let key = derive_key(master, &salt);
    let (header, body) = sealed.split_at_mut(header_end);
    let written = cipher(&key)?.encrypt(0, header, plaintext, body);
    if written != plaintext.len() + TAG_BYTES {
        return Err("relay state encryption produced an unexpected length".into());
    }
    Ok(sealed)
}

/// Opens bytes produced by [`seal`].
///
/// A wrong key, a truncated file, or a modified header all surface as the same
/// authentication failure; the AEAD cannot distinguish them and neither should
/// the caller.
pub(crate) fn open(master: &[u8], stored: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if master.len() != KEY_BYTES {
        return Err("relay at-rest key has an invalid length".into());
    }
    if !is_sealed(stored) {
        return Err("relay state is not sealed".into());
    }
    // Guard before slicing: the cipher subtracts the tag length unchecked.
    if stored.len() < HEADER_BYTES + TAG_BYTES {
        return Err("sealed relay state is truncated".into());
    }
    let version = stored[MAGIC.len()];
    if version != SEAL_VERSION {
        return Err(format!(
            "unsupported sealed relay state version {version}; expected {SEAL_VERSION}"
        ));
    }
    let (header, body) = stored.split_at(HEADER_BYTES);
    let salt = &header[MAGIC.len() + 1..];

    let key = derive_key(master, salt);
    let mut plaintext = Zeroizing::new(vec![0_u8; body.len() - TAG_BYTES]);
    let written = cipher(&key)?
        .decrypt(0, header, body, &mut plaintext)
        .map_err(|_| {
            "relay state could not be decrypted; the keychain key may have been replaced".to_owned()
        })?;
    if written != plaintext.len() {
        return Err("relay state decryption produced an unexpected length".into());
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; KEY_BYTES] = [0x11; KEY_BYTES];

    #[test]
    fn sealed_state_round_trips_and_hides_the_plaintext() {
        let plaintext = br#"{"private_key":"AAAA-secret-material"}"#;
        let sealed = seal(&MASTER, plaintext).unwrap();
        assert!(is_sealed(&sealed));
        // The point of the exercise: no secret survives in the stored bytes.
        assert!(!sealed
            .windows(b"secret-material".len())
            .any(|window| window == b"secret-material"));
        assert_eq!(&*open(&MASTER, &sealed).unwrap(), plaintext);
    }

    #[test]
    fn each_seal_uses_a_fresh_salt_so_writes_never_repeat() {
        let plaintext = b"identical";
        let first = seal(&MASTER, plaintext).unwrap();
        let second = seal(&MASTER, plaintext).unwrap();
        assert_ne!(first, second);
        assert_eq!(first.len(), second.len());
        assert_eq!(first.len(), plaintext.len() + SEAL_OVERHEAD);
    }

    #[test]
    fn a_different_key_cannot_open_the_seal() {
        let sealed = seal(&MASTER, b"payload").unwrap();
        assert!(open(&[0x22; KEY_BYTES], &sealed).is_err());
    }

    #[test]
    fn tampering_with_any_region_fails_authentication() {
        let sealed = seal(&MASTER, b"payload").unwrap();
        // Version byte, salt, and ciphertext are all covered.
        for index in [MAGIC.len(), MAGIC.len() + 4, sealed.len() - 1] {
            let mut damaged = sealed.clone();
            damaged[index] ^= 0x01;
            assert!(
                open(&MASTER, &damaged).is_err(),
                "tampering at byte {index} was not detected"
            );
        }
    }

    #[test]
    fn truncated_input_is_rejected_without_panicking() {
        let sealed = seal(&MASTER, b"payload").unwrap();
        for length in [0, MAGIC.len(), HEADER_BYTES, HEADER_BYTES + TAG_BYTES - 1] {
            assert!(open(&MASTER, &sealed[..length]).is_err());
        }
    }

    #[test]
    fn plaintext_json_is_not_mistaken_for_sealed_state() {
        assert!(!is_sealed(br#"{"version":1}"#));
        assert!(!is_sealed(b""));
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let sealed = seal(&MASTER, b"").unwrap();
        assert_eq!(sealed.len(), SEAL_OVERHEAD);
        assert!(open(&MASTER, &sealed).unwrap().is_empty());
    }
}
