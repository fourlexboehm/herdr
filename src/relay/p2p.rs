use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

const P2P_SIGNAL_VERSION: u8 = 1;
const DATA_CHANNEL_LABEL: &str = "herdr-endpoint-v1";
const HTTP_USER_AGENT: &str = concat!("herdr/", env!("CARGO_PKG_VERSION"));
const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(4);
const DATA_CHANNEL_TIMEOUT: Duration = Duration::from_secs(4);
const TURN_CREDENTIAL_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_ICE_SERVERS: usize = 8;
const MAX_ICE_URLS: usize = 16;
const MAX_ICE_VALUE_BYTES: usize = 2048;
const MAX_SDP_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IceServer {
    pub(crate) urls: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) credential: String,
}

impl IceServer {
    fn validate(&self) -> io::Result<()> {
        if self.urls.is_empty() || self.urls.len() > MAX_ICE_URLS {
            return Err(invalid_data("invalid ICE server URL count"));
        }
        if self.username.len() > MAX_ICE_VALUE_BYTES
            || self.credential.len() > MAX_ICE_VALUE_BYTES
            || self.urls.iter().any(|url| {
                url.is_empty()
                    || url.len() > MAX_ICE_VALUE_BYTES
                    || !matches!(url.split(':').next(), Some("stun" | "turn" | "turns"))
            })
        {
            return Err(invalid_data("invalid ICE server configuration"));
        }
        let has_turn = self
            .urls
            .iter()
            .any(|url| url.starts_with("turn:") || url.starts_with("turns:"));
        if has_turn && (self.username.is_empty() || self.credential.is_empty()) {
            return Err(invalid_data("TURN server credentials are missing"));
        }
        Ok(())
    }
}

impl From<IceServer> for RTCIceServer {
    fn from(server: IceServer) -> Self {
        Self {
            urls: server.urls,
            username: server.username,
            credential: server.credential,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct P2pConfig {
    pub(crate) version: u8,
    pub(crate) ice_servers: Vec<IceServer>,
}

impl P2pConfig {
    pub(crate) fn stun_only() -> Self {
        Self {
            version: P2P_SIGNAL_VERSION,
            ice_servers: vec![IceServer {
                urls: vec!["stun:stun.cloudflare.com:3478".into()],
                username: String::new(),
                credential: String::new(),
            }],
        }
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.version != P2P_SIGNAL_VERSION || self.ice_servers.len() > MAX_ICE_SERVERS {
            return Err(invalid_data("invalid peer transport configuration"));
        }
        for server in &self.ice_servers {
            server.validate()?;
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|error| {
            invalid_data_owned(format!(
                "failed to encode peer transport configuration: {error}"
            ))
        })?;
        if encoded.len() > MAX_SDP_BYTES {
            return Err(invalid_data(
                "peer transport configuration exceeds the signaling limit",
            ));
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> io::Result<Self> {
        if encoded.is_empty() || encoded.len() > MAX_SDP_BYTES {
            return Err(invalid_data("invalid peer transport configuration size"));
        }
        let config: Self = serde_json::from_slice(encoded).map_err(|error| {
            invalid_data_owned(format!("invalid peer transport configuration: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    fn rtc_configuration(&self) -> io::Result<RTCConfiguration> {
        self.validate()?;
        Ok(RTCConfiguration {
            ice_servers: self
                .ice_servers
                .clone()
                .into_iter()
                .map(RTCIceServer::from)
                .collect(),
            ..Default::default()
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TurnCredentialsResponse {
    allocations: Vec<TurnIceServers>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TurnIceServers {
    ice_servers: Vec<IceServer>,
}

pub(crate) async fn load_peer_configs(
    relay_url: &str,
    route_id: &str,
    registration_capability: &str,
) -> (P2pConfig, P2pConfig) {
    match fetch_turn_configs(relay_url, route_id, registration_capability).await {
        Ok(configs) => configs,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), %error, "TURN credentials unavailable; using STUN-only peer transport");
            (P2pConfig::stun_only(), P2pConfig::stun_only())
        }
    }
}

async fn fetch_turn_configs(
    relay_url: &str,
    route_id: &str,
    registration_capability: &str,
) -> io::Result<(P2pConfig, P2pConfig)> {
    let url = turn_credentials_url(relay_url, route_id)?;
    let client = reqwest::Client::new();
    let response = tokio::time::timeout(
        TURN_CREDENTIAL_TIMEOUT,
        turn_credentials_request(&client, url, registration_capability).send(),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TURN credential request timed out"))?
    .map_err(|error| io::Error::other(format!("TURN credential request failed: {error}")))?;
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "TURN credential request returned HTTP {}",
            response.status()
        )));
    }
    let response: TurnCredentialsResponse = response.json().await.map_err(|error| {
        invalid_data_owned(format!("invalid TURN credential response: {error}"))
    })?;
    let [first, second] = response.allocations.as_slice() else {
        return Err(invalid_data(
            "TURN credential response did not contain two allocations",
        ));
    };
    let first = P2pConfig {
        version: P2P_SIGNAL_VERSION,
        ice_servers: first.ice_servers.clone(),
    };
    let second = P2pConfig {
        version: P2P_SIGNAL_VERSION,
        ice_servers: second.ice_servers.clone(),
    };
    first.validate()?;
    second.validate()?;
    Ok((first, second))
}

fn turn_credentials_request(
    client: &reqwest::Client,
    url: String,
    registration_capability: &str,
) -> reqwest::RequestBuilder {
    client
        .post(url)
        .header(reqwest::header::USER_AGENT, HTTP_USER_AGENT)
        .bearer_auth(registration_capability)
}

fn turn_credentials_url(relay_url: &str, route_id: &str) -> io::Result<String> {
    let base = if let Some(rest) = relay_url.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if cfg!(debug_assertions) {
        relay_url
            .strip_prefix("ws://")
            .map(|rest| format!("http://{rest}"))
            .ok_or_else(|| invalid_data("relay URL cannot issue TURN credentials"))?
    } else {
        return Err(invalid_data("relay URL cannot issue TURN credentials"));
    };
    Ok(format!(
        "{}/v1/turn-credentials/{route_id}",
        base.trim_end_matches('/')
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct P2pDescription {
    pub(crate) version: u8,
    pub(crate) description: RTCSessionDescription,
}

impl P2pDescription {
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        if self.version != P2P_SIGNAL_VERSION {
            return Err(invalid_data("unsupported peer transport description"));
        }
        let encoded = serde_json::to_vec(self).map_err(|error| {
            invalid_data_owned(format!("failed to encode peer description: {error}"))
        })?;
        if encoded.len() > MAX_SDP_BYTES {
            return Err(invalid_data("peer transport description is too large"));
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> io::Result<Self> {
        if encoded.is_empty() || encoded.len() > MAX_SDP_BYTES {
            return Err(invalid_data("invalid peer transport description size"));
        }
        let description: Self = serde_json::from_slice(encoded)
            .map_err(|error| invalid_data_owned(format!("invalid peer description: {error}")))?;
        if description.version != P2P_SIGNAL_VERSION {
            return Err(invalid_data("unsupported peer transport description"));
        }
        Ok(description)
    }
}

pub(crate) enum P2pEvent {
    Data {
        connection_id: u32,
        payload: Vec<u8>,
    },
    Closed {
        connection_id: u32,
    },
}

impl P2pEvent {
    pub(crate) fn connection_id(&self) -> u32 {
        match self {
            Self::Data { connection_id, .. } | Self::Closed { connection_id } => *connection_id,
        }
    }
}

pub(crate) struct P2pTransport {
    peer: Arc<RTCPeerConnection>,
    channel: Arc<RTCDataChannel>,
}

impl P2pTransport {
    pub(crate) async fn wait_open(&self) -> io::Result<()> {
        let deadline = tokio::time::Instant::now() + DATA_CHANNEL_TIMEOUT;
        loop {
            match self.channel.ready_state() {
                RTCDataChannelState::Open => return Ok(()),
                RTCDataChannelState::Closing | RTCDataChannelState::Closed => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "peer transport data channel closed before opening",
                    ))
                }
                RTCDataChannelState::Unspecified | RTCDataChannelState::Connecting => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "peer transport data channel timed out",
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub(crate) async fn send(&self, payload: Vec<u8>) -> io::Result<()> {
        self.channel
            .send(&Bytes::from(payload))
            .await
            .map(|_| ())
            .map_err(|error| io::Error::other(format!("peer transport send failed: {error}")))
    }
}

impl Drop for P2pTransport {
    fn drop(&mut self) {
        let peer = self.peer.clone();
        tokio::spawn(async move {
            let _ = peer.close().await;
        });
    }
}

pub(crate) struct P2pOffer {
    transport: P2pTransport,
}

impl P2pOffer {
    pub(crate) async fn create(
        config: P2pConfig,
        connection_id: u32,
        events: mpsc::Sender<P2pEvent>,
    ) -> io::Result<(Self, Vec<u8>)> {
        let peer = new_peer(config).await?;
        attach_peer_failure_handler(&peer, connection_id, events.clone());
        let channel = peer
            .create_data_channel(
                DATA_CHANNEL_LABEL,
                Some(RTCDataChannelInit {
                    ordered: Some(true),
                    ..Default::default()
                }),
            )
            .await
            .map_err(peer_error)?;
        attach_channel_handlers(&channel, connection_id, events);
        let offer = peer.create_offer(None).await.map_err(peer_error)?;
        let description = gather_local_description(&peer, offer).await?;
        Ok((
            Self {
                transport: P2pTransport { peer, channel },
            },
            P2pDescription {
                version: P2P_SIGNAL_VERSION,
                description,
            }
            .encode()?,
        ))
    }

    pub(crate) async fn finish(self, answer: &[u8]) -> io::Result<P2pTransport> {
        let answer = P2pDescription::decode(answer)?;
        self.transport
            .peer
            .set_remote_description(answer.description)
            .await
            .map_err(peer_error)?;
        self.transport.wait_open().await?;
        Ok(self.transport)
    }
}

pub(crate) struct P2pAnswer {
    peer: Arc<RTCPeerConnection>,
    channel: oneshot::Receiver<Arc<RTCDataChannel>>,
}

impl P2pAnswer {
    pub(crate) async fn finish(self) -> io::Result<P2pTransport> {
        let channel = tokio::time::timeout(DATA_CHANNEL_TIMEOUT, self.channel)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "peer data channel was not announced",
                )
            })?
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "peer data channel announcement closed",
                )
            })?;
        let transport = P2pTransport {
            peer: self.peer,
            channel,
        };
        transport.wait_open().await?;
        Ok(transport)
    }
}

pub(crate) async fn answer(
    config: P2pConfig,
    offer: &[u8],
    connection_id: u32,
    events: mpsc::Sender<P2pEvent>,
) -> io::Result<(P2pAnswer, Vec<u8>)> {
    let offer = P2pDescription::decode(offer)?;
    let peer = new_peer(config).await?;
    attach_peer_failure_handler(&peer, connection_id, events.clone());
    let (channel_tx, channel_rx) = oneshot::channel();
    let channel_tx = Arc::new(Mutex::new(Some(channel_tx)));
    peer.on_data_channel(Box::new(move |channel| {
        attach_channel_handlers(&channel, connection_id, events.clone());
        let sender = channel_tx.lock().ok().and_then(|mut sender| sender.take());
        Box::pin(async move {
            if let Some(sender) = sender {
                let _ = sender.send(channel);
            }
        })
    }));
    peer.set_remote_description(offer.description)
        .await
        .map_err(peer_error)?;
    let answer = peer.create_answer(None).await.map_err(peer_error)?;
    let description = gather_local_description(&peer, answer).await?;
    let encoded = P2pDescription {
        version: P2P_SIGNAL_VERSION,
        description,
    }
    .encode()?;
    Ok((
        P2pAnswer {
            peer,
            channel: channel_rx,
        },
        encoded,
    ))
}

async fn new_peer(config: P2pConfig) -> io::Result<Arc<RTCPeerConnection>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs().map_err(peer_error)?;
    let registry =
        register_default_interceptors(Registry::new(), &mut media_engine).map_err(peer_error)?;
    let mut settings = SettingEngine::default();
    settings.set_ice_multicast_dns_mode(webrtc::ice::mdns::MulticastDnsMode::Disabled);
    #[cfg(test)]
    settings.set_include_loopback_candidate(true);
    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .with_setting_engine(settings)
        .build();
    api.new_peer_connection(config.rtc_configuration()?)
        .await
        .map(Arc::new)
        .map_err(peer_error)
}

async fn gather_local_description(
    peer: &RTCPeerConnection,
    description: RTCSessionDescription,
) -> io::Result<RTCSessionDescription> {
    let mut complete = peer.gathering_complete_promise().await;
    peer.set_local_description(description)
        .await
        .map_err(peer_error)?;
    if tokio::time::timeout(ICE_GATHER_TIMEOUT, complete.recv())
        .await
        .is_err()
    {
        tracing::debug!("ICE gathering deadline reached; continuing with gathered candidates");
    }
    peer.local_description()
        .await
        .ok_or_else(|| invalid_data("ICE gathering produced no local description"))
}

fn attach_channel_handlers(
    channel: &Arc<RTCDataChannel>,
    connection_id: u32,
    events: mpsc::Sender<P2pEvent>,
) {
    let data_events = events.clone();
    channel.on_message(Box::new(move |message: DataChannelMessage| {
        let events = data_events.clone();
        Box::pin(async move {
            let _ = events
                .send(P2pEvent::Data {
                    connection_id,
                    payload: message.data.to_vec(),
                })
                .await;
        })
    }));
    channel.on_close(Box::new(move || {
        let events = events.clone();
        Box::pin(async move {
            let _ = events.send(P2pEvent::Closed { connection_id }).await;
        })
    }));
}

fn attach_peer_failure_handler(
    peer: &RTCPeerConnection,
    connection_id: u32,
    events: mpsc::Sender<P2pEvent>,
) {
    peer.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
        let events = events.clone();
        Box::pin(async move {
            if matches!(
                state,
                RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
            ) {
                let _ = events.send(P2pEvent::Closed { connection_id }).await;
            }
        })
    }));
}

fn peer_error(error: webrtc::Error) -> io::Error {
    io::Error::other(format!("peer transport failed: {error}"))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_data_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_credential_url_follows_the_relay_origin() {
        assert_eq!(
            turn_credentials_url("wss://relay.example", "route").unwrap(),
            "https://relay.example/v1/turn-credentials/route"
        );
        if cfg!(debug_assertions) {
            assert_eq!(
                turn_credentials_url("ws://127.0.0.1:8787", "route").unwrap(),
                "http://127.0.0.1:8787/v1/turn-credentials/route"
            );
        }
    }

    #[test]
    fn turn_credential_request_identifies_herdr() {
        let request = turn_credentials_request(
            &reqwest::Client::new(),
            "https://relay.example/v1/turn-credentials/route".into(),
            "registration-capability",
        )
        .build()
        .unwrap();
        assert_eq!(
            request.headers().get(reqwest::header::USER_AGENT).unwrap(),
            HTTP_USER_AGENT
        );
    }

    #[test]
    fn turn_servers_require_credentials() {
        let config = P2pConfig {
            version: P2P_SIGNAL_VERSION,
            ice_servers: vec![IceServer {
                urls: vec!["turn:turn.cloudflare.com:3478?transport=udp".into()],
                username: String::new(),
                credential: String::new(),
            }],
        };
        assert!(config.validate().is_err());
        assert!(P2pConfig::stun_only().validate().is_ok());
    }

    #[tokio::test]
    async fn ordered_data_channel_roundtrips_bytes() {
        let (offer_events_tx, mut offer_events_rx) = mpsc::channel(8);
        let (answer_events_tx, mut answer_events_rx) = mpsc::channel(8);
        let config = P2pConfig {
            version: P2P_SIGNAL_VERSION,
            ice_servers: Vec::new(),
        };
        let (offer, description) = P2pOffer::create(config.clone(), 1, offer_events_tx)
            .await
            .unwrap();
        let (answer, response) = answer(config, &description, 2, answer_events_tx)
            .await
            .unwrap();
        let offer = offer.finish(&response);
        let (offer, answer) = tokio::join!(offer, answer.finish());
        let offer = offer.unwrap();
        let answer = answer.unwrap();

        offer.send(vec![1, 2, 3]).await.unwrap();
        answer.send(vec![4, 5, 6]).await.unwrap();
        assert!(matches!(
            answer_events_rx.recv().await,
            Some(P2pEvent::Data {
                connection_id: 2,
                payload
            }) if payload == [1, 2, 3]
        ));
        assert!(matches!(
            offer_events_rx.recv().await,
            Some(P2pEvent::Data {
                connection_id: 1,
                payload
            }) if payload == [4, 5, 6]
        ));
    }
}
