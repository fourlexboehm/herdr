use std::io;

use serde::{Deserialize, Serialize};

use crate::protocol::endpoint::ENDPOINT_PROTOCOL_GENERATION;

pub(crate) const RELAY_PROTOCOL_VERSION: u8 = 1;
/// Version of the Noise-protected controller/target protocol. This is separate
/// from the relay framing version because the Worker does not inspect it, so
/// the two move independently. Both are 1: nothing has shipped with either.
pub(crate) const ENCRYPTED_HANDSHAKE_VERSION: u8 = 1;
pub(crate) const MAX_RELAY_PAYLOAD: usize = 1024 * 1024;
pub(crate) const MAX_NOISE_PLAINTEXT: usize = 60 * 1024;
pub(crate) const MAX_NOISE_MESSAGE: usize = u16::MAX as usize;
pub(crate) const MAX_HANDSHAKE_MESSAGE: usize = 4096;
pub(crate) const ROUTE_BYTES: usize = 32;
pub(crate) const CAPABILITY_BYTES: usize = 32;
pub(crate) const INVITATION_SECRET_BYTES: usize = 32;
pub(crate) const MAX_CONTROL_PAYLOAD: usize = 512;

const ENVELOPE_HEADER_BYTES: usize = 10;
pub(crate) const MAX_RELAY_ENVELOPE: usize = ENVELOPE_HEADER_BYTES + MAX_RELAY_PAYLOAD;
const BATCH_LENGTH_BYTES: usize = 4;
const HANDSHAKE_HEADER_BYTES: usize = 4;
const SECURE_FRAME_HEADER_BYTES: usize = 5;
const MAX_SECURE_CONTROL_PAYLOAD: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RelayEnvelopeKind {
    Open = 1,
    Data = 2,
    Close = 3,
    Notice = 4,
}

impl TryFrom<u8> for RelayEnvelopeKind {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::Data),
            3 => Ok(Self::Close),
            4 => Ok(Self::Notice),
            _ => Err(invalid_data("unknown relay envelope kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayEnvelope {
    pub(crate) kind: RelayEnvelopeKind,
    pub(crate) connection_id: u32,
    pub(crate) payload: Vec<u8>,
}

impl RelayEnvelope {
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        if self.payload.len() > MAX_RELAY_PAYLOAD {
            return Err(invalid_data("relay payload exceeds the protocol limit"));
        }
        if self.kind == RelayEnvelopeKind::Open && !self.payload.is_empty() {
            return Err(invalid_data("relay open envelope must be empty"));
        }
        if matches!(
            self.kind,
            RelayEnvelopeKind::Close | RelayEnvelopeKind::Notice
        ) {
            if self.payload.len() > MAX_CONTROL_PAYLOAD {
                return Err(invalid_data("relay control payload exceeds the limit"));
            }
            std::str::from_utf8(&self.payload)
                .map_err(|_| invalid_data("relay control payload must be UTF-8"))?;
        }
        let payload_len = u32::try_from(self.payload.len())
            .map_err(|_| invalid_data("relay payload length does not fit the wire format"))?;
        let mut encoded = Vec::with_capacity(ENVELOPE_HEADER_BYTES + self.payload.len());
        encoded.push(RELAY_PROTOCOL_VERSION);
        encoded.push(self.kind as u8);
        encoded.extend_from_slice(&self.connection_id.to_be_bytes());
        encoded.extend_from_slice(&payload_len.to_be_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> io::Result<Self> {
        if encoded.len() < ENVELOPE_HEADER_BYTES {
            return Err(invalid_data("truncated relay envelope"));
        }
        if encoded[0] != RELAY_PROTOCOL_VERSION {
            return Err(invalid_data("unsupported relay envelope version"));
        }
        let kind = RelayEnvelopeKind::try_from(encoded[1])?;
        let connection_id = u32::from_be_bytes(
            encoded[2..6]
                .try_into()
                .map_err(|_| invalid_data("invalid relay connection id"))?,
        );
        let payload_len = u32::from_be_bytes(
            encoded[6..10]
                .try_into()
                .map_err(|_| invalid_data("invalid relay payload length"))?,
        ) as usize;
        if payload_len > MAX_RELAY_PAYLOAD {
            return Err(invalid_data("relay payload exceeds the protocol limit"));
        }
        if encoded.len() != ENVELOPE_HEADER_BYTES + payload_len {
            return Err(invalid_data("relay envelope length mismatch"));
        }
        let envelope = Self {
            kind,
            connection_id,
            payload: encoded[ENVELOPE_HEADER_BYTES..].to_vec(),
        };
        envelope.encode()?;
        Ok(envelope)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum HandshakeMode {
    Pair = 1,
    Reconnect = 2,
}

impl TryFrom<u8> for HandshakeMode {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Pair),
            2 => Ok(Self::Reconnect),
            _ => Err(invalid_data("unknown relay handshake mode")),
        }
    }
}

pub(crate) fn encode_handshake_message(mode: HandshakeMode, noise: &[u8]) -> io::Result<Vec<u8>> {
    if noise.len() > MAX_HANDSHAKE_MESSAGE {
        return Err(invalid_data("Noise handshake message exceeds the limit"));
    }
    let len = u16::try_from(noise.len())
        .map_err(|_| invalid_data("Noise handshake length does not fit the wire format"))?;
    let mut encoded = Vec::with_capacity(HANDSHAKE_HEADER_BYTES + noise.len());
    encoded.push(RELAY_PROTOCOL_VERSION);
    encoded.push(mode as u8);
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(noise);
    Ok(encoded)
}

pub(crate) fn decode_handshake_message(encoded: &[u8]) -> io::Result<(HandshakeMode, &[u8])> {
    if encoded.len() < HANDSHAKE_HEADER_BYTES {
        return Err(invalid_data("truncated relay handshake message"));
    }
    if encoded[0] != RELAY_PROTOCOL_VERSION {
        return Err(invalid_data("unsupported relay handshake version"));
    }
    let mode = HandshakeMode::try_from(encoded[1])?;
    let len = u16::from_be_bytes(
        encoded[2..4]
            .try_into()
            .map_err(|_| invalid_data("invalid relay handshake length"))?,
    ) as usize;
    if len > MAX_HANDSHAKE_MESSAGE || encoded.len() != HANDSHAKE_HEADER_BYTES + len {
        return Err(invalid_data("relay handshake length mismatch"));
    }
    Ok((mode, &encoded[HANDSHAKE_HEADER_BYTES..]))
}

pub(crate) fn encode_record_batch(records: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    let mut encoded = Vec::new();
    for record in records {
        if record.is_empty() || record.len() > MAX_NOISE_MESSAGE {
            return Err(invalid_data("invalid Noise transport record length"));
        }
        let len = u32::try_from(record.len())
            .map_err(|_| invalid_data("Noise record length does not fit the wire format"))?;
        if encoded
            .len()
            .saturating_add(BATCH_LENGTH_BYTES)
            .saturating_add(record.len())
            > MAX_RELAY_PAYLOAD
        {
            return Err(invalid_data("encrypted record batch exceeds the limit"));
        }
        encoded.extend_from_slice(&len.to_be_bytes());
        encoded.extend_from_slice(record);
    }
    if encoded.is_empty() {
        return Err(invalid_data("encrypted record batch must not be empty"));
    }
    Ok(encoded)
}

pub(crate) fn decode_record_batch(encoded: &[u8]) -> io::Result<Vec<&[u8]>> {
    if encoded.is_empty() || encoded.len() > MAX_RELAY_PAYLOAD {
        return Err(invalid_data("invalid encrypted record batch length"));
    }
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < encoded.len() {
        let length_end = offset + BATCH_LENGTH_BYTES;
        let length_bytes = encoded
            .get(offset..length_end)
            .ok_or_else(|| invalid_data("truncated encrypted record length"))?;
        let record_len = u32::from_be_bytes(
            length_bytes
                .try_into()
                .map_err(|_| invalid_data("invalid encrypted record length"))?,
        ) as usize;
        if record_len == 0 || record_len > MAX_NOISE_MESSAGE {
            return Err(invalid_data("invalid Noise transport record length"));
        }
        let record_end = length_end
            .checked_add(record_len)
            .ok_or_else(|| invalid_data("encrypted record length overflow"))?;
        let record = encoded
            .get(length_end..record_end)
            .ok_or_else(|| invalid_data("truncated encrypted record"))?;
        records.push(record);
        offset = record_end;
    }
    Ok(records)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum SecureFrameKind {
    Data = 1,
    ClientConfirm = 2,
    ServerConfirm = 3,
    P2pRequest = 4,
    P2pConfig = 5,
    P2pOffer = 6,
    P2pAnswer = 7,
}

impl TryFrom<u8> for SecureFrameKind {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Data),
            2 => Ok(Self::ClientConfirm),
            3 => Ok(Self::ServerConfirm),
            4 => Ok(Self::P2pRequest),
            5 => Ok(Self::P2pConfig),
            6 => Ok(Self::P2pOffer),
            7 => Ok(Self::P2pAnswer),
            _ => Err(invalid_data("unknown secure relay frame kind")),
        }
    }
}

pub(crate) fn encode_secure_frame(kind: SecureFrameKind, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_RELAY_PAYLOAD {
        return Err(invalid_data("secure relay frame exceeds the limit"));
    }
    validate_secure_frame_payload(kind, payload)?;
    let len = u32::try_from(payload.len())
        .map_err(|_| invalid_data("secure frame length does not fit the wire format"))?;
    let mut frame = Vec::with_capacity(SECURE_FRAME_HEADER_BYTES + payload.len());
    frame.push(kind as u8);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub(crate) fn decode_secure_frame(encoded: &[u8]) -> io::Result<(SecureFrameKind, &[u8])> {
    if encoded.len() < SECURE_FRAME_HEADER_BYTES {
        return Err(invalid_data("truncated secure relay frame"));
    }
    let kind = SecureFrameKind::try_from(encoded[0])?;
    let len = u32::from_be_bytes(
        encoded[1..5]
            .try_into()
            .map_err(|_| invalid_data("invalid secure relay frame length"))?,
    ) as usize;
    if len > MAX_RELAY_PAYLOAD || encoded.len() != SECURE_FRAME_HEADER_BYTES + len {
        return Err(invalid_data("secure relay frame length mismatch"));
    }
    validate_secure_frame_payload(kind, &encoded[SECURE_FRAME_HEADER_BYTES..])?;
    Ok((kind, &encoded[SECURE_FRAME_HEADER_BYTES..]))
}

fn validate_secure_frame_payload(kind: SecureFrameKind, payload: &[u8]) -> io::Result<()> {
    match kind {
        SecureFrameKind::Data => Ok(()),
        SecureFrameKind::P2pConfig | SecureFrameKind::P2pOffer | SecureFrameKind::P2pAnswer
            if !payload.is_empty() && payload.len() <= MAX_SECURE_CONTROL_PAYLOAD =>
        {
            Ok(())
        }
        SecureFrameKind::ClientConfirm
        | SecureFrameKind::ServerConfirm
        | SecureFrameKind::P2pRequest
            if payload.is_empty() =>
        {
            Ok(())
        }
        SecureFrameKind::P2pConfig | SecureFrameKind::P2pOffer | SecureFrameKind::P2pAnswer => {
            Err(invalid_data("invalid secure peer signaling payload"))
        }
        SecureFrameKind::ClientConfirm
        | SecureFrameKind::ServerConfirm
        | SecureFrameKind::P2pRequest => {
            Err(invalid_data("secure relay control frame must be empty"))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RelayRole {
    Controller,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HandshakePayload {
    pub(crate) version: u8,
    pub(crate) invitation_id: Option<String>,
    pub(crate) controller_label: String,
    pub(crate) role: RelayRole,
    pub(crate) session: String,
    pub(crate) endpoint_generation: u32,
}

impl HandshakePayload {
    pub(crate) fn validate(&self, mode: HandshakeMode, expected_session: &str) -> io::Result<()> {
        if self.version != ENCRYPTED_HANDSHAKE_VERSION {
            return Err(invalid_data("unsupported encrypted handshake version"));
        }
        if self.endpoint_generation != ENDPOINT_PROTOCOL_GENERATION {
            return Err(invalid_data("unsupported endpoint protocol generation"));
        }
        if self.session != expected_session {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "requested Herdr session is not authorized by this route",
            ));
        }
        if self.controller_label.trim().is_empty() || self.controller_label.len() > 96 {
            return Err(invalid_data("invalid controller label"));
        }
        match (mode, self.invitation_id.as_deref()) {
            (HandshakeMode::Pair, Some(id)) if valid_hex_id(id) => Ok(()),
            (HandshakeMode::Reconnect, None) => Ok(()),
            _ => Err(invalid_data(
                "invitation id does not match relay handshake mode",
            )),
        }
    }
}

pub(crate) fn handshake_prologue(
    route_id: &str,
    target_public_key: &[u8],
    session: &str,
) -> Vec<u8> {
    format!(
        "herdr-relay-v1\nroute={route_id}\ntarget={}\nsession={session}\nendpoint-generation={ENDPOINT_PROTOCOL_GENERATION}",
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            target_public_key
        )
    )
    .into_bytes()
}

pub(crate) fn valid_capability(value: &str, bytes: usize) -> bool {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == bytes)
}

fn valid_hex_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_envelopes_roundtrip_and_reject_trailing_data() {
        let envelope = RelayEnvelope {
            kind: RelayEnvelopeKind::Data,
            connection_id: 42,
            payload: vec![0, 1, 2, 255],
        };
        let encoded = envelope.encode().unwrap();
        assert_eq!(RelayEnvelope::decode(&encoded).unwrap(), envelope);

        let mut trailing = encoded;
        trailing.push(0);
        assert!(RelayEnvelope::decode(&trailing).is_err());
    }

    #[test]
    fn record_batches_preserve_boundaries_and_reject_truncation() {
        let batch = encode_record_batch(&[vec![1, 2], vec![3, 4, 5]]).unwrap();
        assert_eq!(
            decode_record_batch(&batch).unwrap(),
            vec![&[1, 2][..], &[3, 4, 5][..]]
        );
        assert!(decode_record_batch(&batch[..batch.len() - 1]).is_err());
    }

    #[test]
    fn handshake_payload_rejects_generation_and_mode_mismatch() {
        let payload = HandshakePayload {
            version: ENCRYPTED_HANDSHAKE_VERSION,
            invitation_id: Some("0123456789abcdef0123456789abcdef".into()),
            controller_label: "laptop".into(),
            role: RelayRole::Controller,
            session: "default".into(),
            endpoint_generation: ENDPOINT_PROTOCOL_GENERATION,
        };
        payload.validate(HandshakeMode::Pair, "default").unwrap();
        assert!(payload
            .validate(HandshakeMode::Reconnect, "default")
            .is_err());
    }

    #[test]
    fn secure_control_frame_payload_rules_are_enforced() {
        let frame = encode_secure_frame(SecureFrameKind::ClientConfirm, &[]).unwrap();
        assert_eq!(
            decode_secure_frame(&frame).unwrap(),
            (SecureFrameKind::ClientConfirm, &[][..])
        );
        for kind in [
            SecureFrameKind::ClientConfirm,
            SecureFrameKind::ServerConfirm,
            SecureFrameKind::P2pRequest,
        ] {
            assert!(encode_secure_frame(kind, &[]).is_ok());
            assert!(encode_secure_frame(kind, b"data").is_err());
        }
        for kind in [
            SecureFrameKind::P2pConfig,
            SecureFrameKind::P2pOffer,
            SecureFrameKind::P2pAnswer,
        ] {
            assert!(encode_secure_frame(kind, b"{}").is_ok());
            assert!(encode_secure_frame(kind, &[]).is_err());
            assert!(encode_secure_frame(kind, &vec![0; MAX_SECURE_CONTROL_PAYLOAD + 1]).is_err());
        }
        assert!(decode_secure_frame(&[8, 0, 0, 0, 0]).is_err());
    }
}
