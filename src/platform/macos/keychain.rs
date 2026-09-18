//! Keychain-backed storage for the relay at-rest master key.
//!
//! The relay state files hold long-lived X25519 identity private keys, the
//! registration capability, and live enrollment secrets. Keeping them as
//! readable JSON means any process running as the user — or anything that can
//! copy the state directory off the machine — walks away with a working
//! controller identity. The master key lives here instead, so the on-disk
//! files are ciphertext and exfiltrating them is not enough.
//!
//! This uses the legacy file-based login keychain rather than the data
//! protection keychain. Data protection items key their access control to the
//! caller's code signature, which an unsigned or ad-hoc signed `herdr` cannot
//! satisfy; it would fail with `errSecMissingEntitlement` for exactly the
//! installs most likely to need this.

// The relay store substitutes a fixed key under `#[cfg(test)]` so unit tests
// never prompt for or mutate the developer's real login keychain, which leaves
// the production path genuinely unreferenced in test builds only.
#![cfg_attr(test, allow(dead_code))]

use std::ffi::c_void;
use std::io;
use std::ptr::NonNull;

use zeroize::Zeroizing;

/// Service name for every Keychain item herdr owns.
const SERVICE: &str = "dev.herdr.relay";
/// Account name for the relay at-rest master key.
const RELAY_STATE_ACCOUNT: &str = "relay-state-key-v1";
/// Human-readable label, so the item is identifiable in Keychain Access.
const RELAY_STATE_LABEL: &str = "herdr relay state key";
const KEY_BYTES: usize = 32;

type CFTypeRef = *const c_void;
type CFAllocatorRef = CFTypeRef;
type CFStringRef = CFTypeRef;
type CFDictionaryRef = CFTypeRef;
type CFDataRef = CFTypeRef;
type CFIndex = isize;
type CFStringEncoding = u32;
type OSStatus = i32;
type Boolean = u8;

const KCF_STRING_ENCODING_UTF8: CFStringEncoding = 0x0800_0100;

const ERR_SEC_SUCCESS: OSStatus = 0;
const ERR_SEC_DUPLICATE_ITEM: OSStatus = -25299;
const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;
const ERR_SEC_AUTH_FAILED: OSStatus = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: OSStatus = -25308;
const ERR_SEC_USER_CANCELED: OSStatus = -128;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
    static kCFBooleanTrue: CFTypeRef;

    fn CFRelease(cf: CFTypeRef);
    fn CFStringCreateWithBytes(
        allocator: CFAllocatorRef,
        bytes: *const u8,
        num_bytes: CFIndex,
        encoding: CFStringEncoding,
        is_external_representation: Boolean,
    ) -> CFStringRef;
    fn CFDataCreate(allocator: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
    fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
    fn CFDataGetLength(data: CFDataRef) -> CFIndex;
    fn CFDictionaryCreate(
        allocator: CFAllocatorRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        num_values: CFIndex,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFDictionaryRef;
    fn CFGetTypeID(cf: CFTypeRef) -> usize;
    fn CFDataGetTypeID() -> usize;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecClass: CFStringRef;
    static kSecClassGenericPassword: CFStringRef;
    static kSecAttrService: CFStringRef;
    static kSecAttrAccount: CFStringRef;
    static kSecAttrLabel: CFStringRef;
    static kSecAttrAccessible: CFStringRef;
    static kSecAttrAccessibleWhenUnlocked: CFStringRef;
    static kSecValueData: CFStringRef;
    static kSecReturnData: CFStringRef;
    static kSecMatchLimit: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;

    fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    #[cfg(test)]
    fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
}

/// Owns one +1 Core Foundation reference and releases it on drop.
struct CfObject(NonNull<c_void>);

impl CfObject {
    /// Takes ownership of a Create/Copy-rule reference.
    fn from_create(value: CFTypeRef, description: &str) -> io::Result<Self> {
        NonNull::new(value.cast_mut())
            .map(Self)
            .ok_or_else(|| io::Error::other(format!("failed to allocate {description}")))
    }

    fn as_ref(&self) -> CFTypeRef {
        self.0.as_ptr()
    }
}

impl Drop for CfObject {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0.as_ptr()) };
    }
}

fn cf_string(value: &str) -> io::Result<CfObject> {
    let string = unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            value.as_ptr(),
            value.len() as CFIndex,
            KCF_STRING_ENCODING_UTF8,
            false as Boolean,
        )
    };
    CfObject::from_create(string, "Keychain query string")
}

fn cf_data(value: &[u8]) -> io::Result<CfObject> {
    let data = unsafe { CFDataCreate(std::ptr::null(), value.as_ptr(), value.len() as CFIndex) };
    CfObject::from_create(data, "Keychain item payload")
}

fn cf_dictionary(entries: &[(CFTypeRef, CFTypeRef)]) -> io::Result<CfObject> {
    let keys: Vec<CFTypeRef> = entries.iter().map(|(key, _)| *key).collect();
    let values: Vec<CFTypeRef> = entries.iter().map(|(_, value)| *value).collect();
    let dictionary = unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            entries.len() as CFIndex,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        )
    };
    CfObject::from_create(dictionary, "Keychain query")
}

/// Maps the statuses a caller can act on; everything else keeps its raw code
/// so an unexpected failure stays diagnosable instead of collapsing to "failed".
fn keychain_error(status: OSStatus, action: &str) -> io::Error {
    let detail = match status {
        ERR_SEC_AUTH_FAILED => "keychain authorization was refused".to_owned(),
        ERR_SEC_INTERACTION_NOT_ALLOWED => {
            "the keychain is locked and cannot prompt in this context".to_owned()
        }
        ERR_SEC_USER_CANCELED => "the keychain prompt was dismissed".to_owned(),
        other => format!("keychain error {other}"),
    };
    io::Error::other(format!("failed to {action}: {detail}"))
}

fn copy_secret(service: &str, account: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let service = cf_string(service)?;
    let account = cf_string(account)?;
    let query = cf_dictionary(&[
        (unsafe { kSecClass }, unsafe { kSecClassGenericPassword }),
        (unsafe { kSecAttrService }, service.as_ref()),
        (unsafe { kSecAttrAccount }, account.as_ref()),
        (unsafe { kSecReturnData }, unsafe { kCFBooleanTrue }),
        (unsafe { kSecMatchLimit }, unsafe { kSecMatchLimitOne }),
    ])?;

    let mut result: CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_ref(), &mut result) };
    match status {
        ERR_SEC_SUCCESS => {}
        ERR_SEC_ITEM_NOT_FOUND => return Ok(None),
        other => return Err(keychain_error(other, "read the herdr relay key")),
    }

    // SecItemCopyMatching follows the Create rule on success, so the result is
    // released even when it turns out to be an unexpected type.
    let data = CfObject::from_create(result, "Keychain result")?;
    if unsafe { CFGetTypeID(data.as_ref()) != CFDataGetTypeID() } {
        return Err(io::Error::other(
            "the herdr relay keychain item is not binary data",
        ));
    }
    let length = unsafe { CFDataGetLength(data.as_ref()) };
    let bytes = unsafe { CFDataGetBytePtr(data.as_ref()) };
    if length <= 0 || bytes.is_null() {
        return Err(io::Error::other("the herdr relay keychain item is empty"));
    }
    let mut secret = Zeroizing::new(vec![0_u8; length as usize]);
    unsafe { std::ptr::copy_nonoverlapping(bytes, secret.as_mut_ptr(), length as usize) };
    Ok(Some(secret))
}

/// Returns `false` when the item already exists, so a racing first run can
/// fall back to reading the winner's key instead of failing.
fn add_secret(service: &str, account: &str, label: &str, secret: &[u8]) -> io::Result<bool> {
    let service = cf_string(service)?;
    let account = cf_string(account)?;
    let label = cf_string(label)?;
    let value = cf_data(secret)?;
    let attributes = cf_dictionary(&[
        (unsafe { kSecClass }, unsafe { kSecClassGenericPassword }),
        (unsafe { kSecAttrService }, service.as_ref()),
        (unsafe { kSecAttrAccount }, account.as_ref()),
        (unsafe { kSecAttrLabel }, label.as_ref()),
        (unsafe { kSecAttrAccessible }, unsafe {
            kSecAttrAccessibleWhenUnlocked
        }),
        (unsafe { kSecValueData }, value.as_ref()),
    ])?;

    let status = unsafe { SecItemAdd(attributes.as_ref(), std::ptr::null_mut()) };
    match status {
        ERR_SEC_SUCCESS => Ok(true),
        ERR_SEC_DUPLICATE_ITEM => Ok(false),
        other => Err(keychain_error(other, "store the herdr relay key")),
    }
}

/// Removes an item, reporting whether one was present.
///
/// Test-only: discarding the master key makes every sealed state file
/// unreadable, and the supported recovery is to delete the relay state
/// directory so the host re-enrolls. This exists so the round-trip test does
/// not leave items in the developer's login keychain.
#[cfg(test)]
fn delete_secret(service: &str, account: &str) -> io::Result<bool> {
    let service = cf_string(service)?;
    let account = cf_string(account)?;
    let query = cf_dictionary(&[
        (unsafe { kSecClass }, unsafe { kSecClassGenericPassword }),
        (unsafe { kSecAttrService }, service.as_ref()),
        (unsafe { kSecAttrAccount }, account.as_ref()),
    ])?;

    let status = unsafe { SecItemDelete(query.as_ref()) };
    match status {
        ERR_SEC_SUCCESS => Ok(true),
        ERR_SEC_ITEM_NOT_FOUND => Ok(false),
        other => Err(keychain_error(other, "remove the herdr relay key")),
    }
}

/// Returns the relay at-rest master key, creating it on first use.
///
/// `Ok(None)` is never returned on macOS; the signature matches the
/// cross-platform contract where platforms without a system keystore keep
/// plaintext state.
pub(crate) fn relay_state_key() -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    if let Some(existing) = copy_secret(SERVICE, RELAY_STATE_ACCOUNT)? {
        if existing.len() != KEY_BYTES {
            return Err(io::Error::other(
                "the herdr relay keychain item has an invalid length",
            ));
        }
        return Ok(Some(existing));
    }

    let mut created = Zeroizing::new(vec![0_u8; KEY_BYTES]);
    getrandom::fill(&mut created)
        .map_err(|error| io::Error::other(format!("failed to obtain randomness: {error}")))?;
    if add_secret(SERVICE, RELAY_STATE_ACCOUNT, RELAY_STATE_LABEL, &created)? {
        return Ok(Some(created));
    }

    // Another herdr process created the item between our read and write.
    let existing = copy_secret(SERVICE, RELAY_STATE_ACCOUNT)?.ok_or_else(|| {
        io::Error::other("the herdr relay keychain item disappeared during creation")
    })?;
    if existing.len() != KEY_BYTES {
        return Err(io::Error::other(
            "the herdr relay keychain item has an invalid length",
        ));
    }
    Ok(Some(existing))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises the real Keychain round trip through a throwaway account so it
    /// cannot disturb the account the runtime uses.
    #[test]
    fn generic_password_round_trip_returns_the_stored_bytes() {
        let account = format!("herdr-test-{}-{}", std::process::id(), line!());
        let secret = [0x5a_u8; KEY_BYTES];
        // A locked or non-interactive keychain (CI, SSH session) cannot serve
        // this; skip rather than fail the suite for an environment reason.
        match add_secret(SERVICE, &account, "herdr test key", &secret) {
            Ok(true) => {}
            Ok(false) => panic!("test account {account} unexpectedly already exists"),
            Err(_) => return,
        }
        let fetched = copy_secret(SERVICE, &account)
            .expect("reading a just-created item should succeed")
            .expect("a just-created item should be present");
        assert_eq!(&*fetched, &secret);

        assert!(delete_secret(SERVICE, &account).expect("removing the test item should succeed"));
        assert!(copy_secret(SERVICE, &account)
            .expect("reading a removed item should succeed")
            .is_none());
        assert!(!delete_secret(SERVICE, &account).expect("a second removal is not an error"));
    }

    #[test]
    fn missing_items_are_absent_rather_than_an_error() {
        let account = format!("herdr-missing-{}-{}", std::process::id(), line!());
        // A locked or non-interactive keychain cannot serve this; an error is an
        // environment limit rather than a failure of the absent-item contract.
        if let Ok(result) = copy_secret(SERVICE, &account) {
            assert!(result.is_none());
        }
    }
}
