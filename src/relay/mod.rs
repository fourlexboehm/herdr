//! Experimental end-to-end encrypted relay transport.
//!
//! The public relay sees only opaque route identifiers, connection metadata,
//! and Noise ciphertext. Herdr's stable endpoint protocol remains unchanged
//! inside the encrypted byte stream.

pub(crate) mod crypto;
pub(crate) mod protocol;
pub(crate) mod store;
pub(crate) mod transport;

pub(crate) const FEATURE_WARNING: &str =
    "relay access is experimental and has not received an independent security audit";
