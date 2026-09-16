use std::io;

use snow::{Builder, HandshakeState, TransportState};
use zeroize::Zeroizing;

use super::protocol::{
    decode_record_batch, encode_record_batch, invalid_data, MAX_NOISE_PLAINTEXT,
};

const IK_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PAIR_PATTERN: &str = "Noise_IKpsk0_25519_ChaChaPoly_BLAKE2s";
const NOISE_TAG_BYTES: usize = 16;
const REKEY_INTERVAL_RECORDS: u64 = 1 << 20;

#[derive(Clone)]
pub(crate) struct IdentityKeypair {
    private: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
}

impl IdentityKeypair {
    pub(crate) fn generate() -> io::Result<Self> {
        let builder = Builder::new(
            IK_PATTERN
                .parse()
                .map_err(|_| invalid_data("invalid built-in Noise pattern"))?,
        );
        let keypair = builder.generate_keypair().map_err(noise_error)?;
        Ok(Self {
            private: Zeroizing::new(keypair.private),
            public: keypair.public,
        })
    }

    pub(crate) fn from_parts(private: Vec<u8>, public: Vec<u8>) -> io::Result<Self> {
        if private.len() != 32 || public.len() != 32 {
            return Err(invalid_data("invalid X25519 identity key length"));
        }
        Ok(Self {
            private: Zeroizing::new(private),
            public,
        })
    }

    pub(crate) fn private(&self) -> &[u8] {
        &self.private
    }

    pub(crate) fn public(&self) -> &[u8] {
        &self.public
    }
}

pub(crate) struct InitiatorHandshake {
    state: HandshakeState,
}

pub(crate) struct ResponderHandshake {
    state: HandshakeState,
}

pub(crate) struct SecureTransport {
    state: TransportState,
    sent_records: u64,
    received_records: u64,
}

pub(crate) fn start_pairing_initiator(
    identity: &IdentityKeypair,
    target_public_key: &[u8],
    enrollment_secret: &[u8],
    prologue: &[u8],
    payload: &[u8],
) -> io::Result<(InitiatorHandshake, Vec<u8>)> {
    let psk: &[u8; 32] = enrollment_secret
        .try_into()
        .map_err(|_| invalid_data("Noise enrollment secret must be 32 bytes"))?;
    let builder = pairing_builder(prologue)?
        .local_private_key(identity.private())
        .map_err(noise_error)?
        .remote_public_key(target_public_key)
        .map_err(noise_error)?
        .psk(0, psk)
        .map_err(noise_error)?;
    let mut state = builder.build_initiator().map_err(noise_error)?;
    let first = write_handshake(&mut state, payload)?;
    Ok((InitiatorHandshake { state }, first))
}

pub(crate) fn start_reconnect_initiator(
    identity: &IdentityKeypair,
    target_public_key: &[u8],
    prologue: &[u8],
    payload: &[u8],
) -> io::Result<(InitiatorHandshake, Vec<u8>)> {
    let builder = reconnect_builder(prologue)?
        .local_private_key(identity.private())
        .map_err(noise_error)?
        .remote_public_key(target_public_key)
        .map_err(noise_error)?;
    let mut state = builder.build_initiator().map_err(noise_error)?;
    let first = write_handshake(&mut state, payload)?;
    Ok((InitiatorHandshake { state }, first))
}

pub(crate) fn receive_pairing(
    identity: &IdentityKeypair,
    enrollment_secret: &[u8],
    prologue: &[u8],
    first: &[u8],
) -> io::Result<(ResponderHandshake, Vec<u8>)> {
    let psk: &[u8; 32] = enrollment_secret
        .try_into()
        .map_err(|_| invalid_data("Noise enrollment secret must be 32 bytes"))?;
    let builder = pairing_builder(prologue)?
        .local_private_key(identity.private())
        .map_err(noise_error)?
        .psk(0, psk)
        .map_err(noise_error)?;
    let mut state = builder.build_responder().map_err(noise_error)?;
    let payload = read_handshake(&mut state, first)?;
    Ok((ResponderHandshake { state }, payload))
}

pub(crate) fn receive_reconnect(
    identity: &IdentityKeypair,
    prologue: &[u8],
    first: &[u8],
) -> io::Result<(ResponderHandshake, Vec<u8>)> {
    let builder = reconnect_builder(prologue)?
        .local_private_key(identity.private())
        .map_err(noise_error)?;
    let mut state = builder.build_responder().map_err(noise_error)?;
    let payload = read_handshake(&mut state, first)?;
    Ok((ResponderHandshake { state }, payload))
}

impl InitiatorHandshake {
    pub(crate) fn finish(mut self, response: &[u8]) -> io::Result<SecureTransport> {
        let payload = read_handshake(&mut self.state, response)?;
        if !payload.is_empty() {
            return Err(invalid_data("unexpected Noise handshake response payload"));
        }
        Ok(SecureTransport {
            state: self.state.into_transport_mode().map_err(noise_error)?,
            sent_records: 0,
            received_records: 0,
        })
    }
}

impl ResponderHandshake {
    pub(crate) fn remote_static(&self) -> io::Result<&[u8]> {
        self.state
            .get_remote_static()
            .ok_or_else(|| invalid_data("Noise initiator did not provide a static identity"))
    }

    pub(crate) fn finish(mut self) -> io::Result<(SecureTransport, Vec<u8>)> {
        let response = write_handshake(&mut self.state, &[])?;
        Ok((
            SecureTransport {
                state: self.state.into_transport_mode().map_err(noise_error)?,
                sent_records: 0,
                received_records: 0,
            },
            response,
        ))
    }
}

impl SecureTransport {
    pub(crate) fn encrypt(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        if plaintext.is_empty() {
            return Err(invalid_data("secure transport plaintext must not be empty"));
        }
        let mut records = Vec::new();
        for chunk in plaintext.chunks(MAX_NOISE_PLAINTEXT) {
            let mut ciphertext = vec![0; chunk.len() + NOISE_TAG_BYTES];
            let written = self
                .state
                .write_message(chunk, &mut ciphertext)
                .map_err(noise_error)?;
            ciphertext.truncate(written);
            records.push(ciphertext);
            self.sent_records = self.sent_records.saturating_add(1);
            if self.sent_records.is_multiple_of(REKEY_INTERVAL_RECORDS) {
                self.state.rekey_outgoing();
            }
        }
        encode_record_batch(&records)
    }

    pub(crate) fn decrypt(&mut self, batch: &[u8]) -> io::Result<Vec<u8>> {
        let records = decode_record_batch(batch)?;
        let mut plaintext = Vec::new();
        for record in records {
            if record.len() < NOISE_TAG_BYTES {
                return Err(invalid_data("truncated Noise transport record"));
            }
            let mut chunk = vec![0; record.len() - NOISE_TAG_BYTES];
            let written = self
                .state
                .read_message(record, &mut chunk)
                .map_err(noise_error)?;
            chunk.truncate(written);
            plaintext.extend_from_slice(&chunk);
            self.received_records = self.received_records.saturating_add(1);
            if self.received_records.is_multiple_of(REKEY_INTERVAL_RECORDS) {
                self.state.rekey_incoming();
            }
        }
        Ok(plaintext)
    }
}

fn reconnect_builder(prologue: &[u8]) -> io::Result<Builder<'_>> {
    Builder::with_resolver(
        IK_PATTERN
            .parse()
            .map_err(|_| invalid_data("invalid built-in Noise pattern"))?,
        Box::new(snow::resolvers::DefaultResolver),
    )
    .prologue(prologue)
    .map_err(noise_error)
}

fn pairing_builder(prologue: &[u8]) -> io::Result<Builder<'_>> {
    Builder::with_resolver(
        PAIR_PATTERN
            .parse()
            .map_err(|_| invalid_data("invalid built-in Noise pairing pattern"))?,
        Box::new(snow::resolvers::DefaultResolver),
    )
    .prologue(prologue)
    .map_err(noise_error)
}

fn write_handshake(state: &mut HandshakeState, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut message = vec![0; super::protocol::MAX_HANDSHAKE_MESSAGE];
    let written = state
        .write_message(payload, &mut message)
        .map_err(noise_error)?;
    message.truncate(written);
    Ok(message)
}

fn read_handshake(state: &mut HandshakeState, message: &[u8]) -> io::Result<Vec<u8>> {
    let mut payload = vec![0; super::protocol::MAX_HANDSHAKE_MESSAGE];
    let written = state
        .read_message(message, &mut payload)
        .map_err(noise_error)?;
    payload.truncate(written);
    Ok(payload)
}

fn noise_error(error: snow::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("Noise authentication failed: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::protocol::handshake_prologue;

    #[test]
    fn pairing_authenticates_and_encrypts_multiple_records() {
        let target = IdentityKeypair::generate().unwrap();
        let controller = IdentityKeypair::generate().unwrap();
        let psk = [7_u8; 32];
        let prologue = handshake_prologue("route", target.public(), "default");
        let payload = br#"{"pair":true}"#;

        let (initiator, first) =
            start_pairing_initiator(&controller, target.public(), &psk, &prologue, payload)
                .unwrap();
        let (responder, received) = receive_pairing(&target, &psk, &prologue, &first).unwrap();
        assert_eq!(received, payload);
        assert_eq!(responder.remote_static().unwrap(), controller.public());
        let (mut target_transport, second) = responder.finish().unwrap();
        let mut controller_transport = initiator.finish(&second).unwrap();

        let plaintext = vec![5; MAX_NOISE_PLAINTEXT + 10];
        let encrypted = controller_transport.encrypt(&plaintext).unwrap();
        assert_eq!(target_transport.decrypt(&encrypted).unwrap(), plaintext);
    }

    #[test]
    fn wrong_pairing_secret_fails_closed() {
        let target = IdentityKeypair::generate().unwrap();
        let controller = IdentityKeypair::generate().unwrap();
        let prologue = handshake_prologue("route", target.public(), "default");
        let (_, first) = start_pairing_initiator(
            &controller,
            target.public(),
            &[1; 32],
            &prologue,
            b"payload",
        )
        .unwrap();
        assert!(receive_pairing(&target, &[2; 32], &prologue, &first).is_err());
    }

    #[test]
    fn reconnect_rejects_wrong_target_key() {
        let target = IdentityKeypair::generate().unwrap();
        let wrong_target = IdentityKeypair::generate().unwrap();
        let controller = IdentityKeypair::generate().unwrap();
        let prologue = handshake_prologue("route", target.public(), "default");
        let (_, first) =
            start_reconnect_initiator(&controller, wrong_target.public(), &prologue, b"payload")
                .unwrap();
        assert!(receive_reconnect(&target, &prologue, &first).is_err());
    }
}
