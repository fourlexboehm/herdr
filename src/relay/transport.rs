use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use futures_util::{SinkExt as _, StreamExt as _};
use interprocess::local_socket::traits::Listener as _;
use interprocess::TryClone as _;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{info, warn};

use crate::client::endpoint::SavedRelayEndpoint;

use super::crypto::{
    receive_pairing, receive_reconnect, start_pairing_initiator, start_reconnect_initiator,
    IdentityKeypair, SecureTransport,
};
use super::p2p::{answer as answer_p2p, P2pAnswer, P2pConfig, P2pEvent, P2pOffer, P2pTransport};
use super::protocol::{
    decode_handshake_message, decode_secure_frame, encode_handshake_message, encode_secure_frame,
    handshake_prologue, HandshakeMode, HandshakePayload, RelayEnvelope, RelayEnvelopeKind,
    SecureFrameKind, MAX_RELAY_ENVELOPE, MAX_RELAY_PAYLOAD, RELAY_PROTOCOL_VERSION,
};
use super::store::{RelayClientStore, RelayHostState};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const P2P_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(60);
const LOCAL_QUEUE_DEPTH: usize = 64;
const MAX_HOST_CONNECTIONS: usize = 16;
const MAX_HANDSHAKES_PER_MINUTE: u32 = 64;
const AUTHORIZATION_REFRESH: Duration = Duration::from_secs(2);
const LOCAL_READ_BYTES: usize = 48 * 1024;
const LOCAL_POLL_INTERVAL: Duration = Duration::from_millis(2);
static NEXT_BRIDGE_ID: AtomicU64 = AtomicU64::new(1);
static HOST_CONFIGURATION: Mutex<Option<String>> = Mutex::new(None);
static HOST_STATUS: AtomicU8 = AtomicU8::new(0);
static HOST_CONTROLLER_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

type RelayWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

const HOST_DISABLED: u8 = 0;
const HOST_CONNECTING: u8 = 1;
const HOST_ONLINE: u8 = 2;
const HOST_ATTENTION: u8 = 3;

pub(crate) struct ConnectedRelay {
    pub(crate) stream: crate::ipc::LocalStream,
    pub(crate) bridge: RelayClientBridge,
}

pub(crate) struct RelayClientBridge {
    cancelled: Arc<AtomicBool>,
    failure: Arc<(Mutex<Option<io::Error>>, Condvar)>,
    socket_path: PathBuf,
    socket_identity: Option<crate::ipc::SocketFileIdentity>,
}

impl RelayClientBridge {
    pub(crate) fn reported_failure(&self) -> Option<io::Error> {
        let (failure, ready) = &*self.failure;
        let guard = failure.lock().ok()?;
        let (guard, _) = ready
            .wait_timeout_while(guard, Duration::from_millis(100), |failure| {
                failure.is_none()
            })
            .ok()?;
        let failure = guard.as_ref()?;
        Some(io::Error::new(failure.kind(), failure.to_string()))
    }
}

impl Drop for RelayClientBridge {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(identity) = self.socket_identity.take() {
            let _ = crate::ipc::remove_socket_file_if_owned(&self.socket_path, &identity);
        }
    }
}

pub(crate) fn connect_controller(profile: &SavedRelayEndpoint) -> io::Result<ConnectedRelay> {
    let store = RelayClientStore::load().map_err(permanent_config)?;
    let credential = store
        .credential(&profile.credential_id)
        .cloned()
        .ok_or_else(|| permanent_config("relay client credential is missing"))?;
    let socket_path = controller_bridge_path();
    crate::ipc::prepare_socket_path(&socket_path, |_| {
        "relay client bridge is already active".into()
    })?;
    let listener = crate::ipc::bind_private_local_listener(&socket_path)?;
    crate::ipc::restrict_socket_permissions(&socket_path, 0o600)?;
    let socket_identity = crate::ipc::socket_file_identity(&socket_path).ok();
    let stream = crate::ipc::connect_local_stream(&socket_path)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let failure = Arc::new((Mutex::new(None), Condvar::new()));
    let worker_cancelled = cancelled.clone();
    let worker_failure = failure.clone();
    let worker_profile = profile.clone();
    std::thread::Builder::new()
        .name("relay-controller".into())
        .spawn(move || {
            let result = (|| {
                let local = listener.accept()?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(io::Error::other)?;
                runtime.block_on(run_controller(
                    worker_profile,
                    credential,
                    local,
                    worker_cancelled.clone(),
                ))
            })();
            if let Err(error) = result {
                let (failure, ready) = &*worker_failure;
                if let Ok(mut slot) = failure.lock() {
                    *slot = Some(error);
                    ready.notify_all();
                }
            }
            worker_cancelled.store(true, Ordering::Release);
        })?;
    Ok(ConnectedRelay {
        stream,
        bridge: RelayClientBridge {
            cancelled,
            failure,
            socket_path,
            socket_identity,
        },
    })
}

pub(crate) struct HostRelayHandle {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for HostRelayHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn spawn_host_supervisor(client_socket_path: PathBuf) -> HostRelayHandle {
    let server_session = crate::session::active_name()
        .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
    HostRelayHandle {
        task: tokio::spawn(run_host_reconnect_loop(server_session, client_socket_path)),
    }
}

async fn run_controller(
    profile: SavedRelayEndpoint,
    credential: super::store::RelayClientCredential,
    local: crate::ipc::LocalStream,
    cancelled: Arc<AtomicBool>,
) -> io::Result<()> {
    let session = open_controller_session(&profile, &credential).await?;
    run_controller_session(session, local, cancelled).await
}

struct ControllerSession {
    websocket: RelayWebSocket,
    secure: SecureTransport,
    p2p: P2pTransport,
    p2p_events: tokio::sync::mpsc::Receiver<P2pEvent>,
}

async fn open_controller_session(
    profile: &SavedRelayEndpoint,
    credential: &super::store::RelayClientCredential,
) -> io::Result<ControllerSession> {
    let url = controller_url(&profile.relay_url, &profile.route_id);
    let request = url
        .into_client_request()
        .map_err(|_| permanent_config("relay URL is invalid"))?;
    let websocket_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_RELAY_PAYLOAD))
        .max_frame_size(Some(MAX_RELAY_PAYLOAD));
    let (mut websocket, _) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::connect_async_with_config(request, Some(websocket_config), true),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay connection timed out"))?
    .map_err(websocket_error)?;

    let identity = credential.identity().map_err(permanent_config)?;
    let target_public_key = decode_key(&profile.target_public_key, "target public key")?;
    let prologue = handshake_prologue(&profile.route_id, &target_public_key, &profile.session);
    let pairing = credential.pairing.as_ref();
    let mode = if pairing.is_some() {
        HandshakeMode::Pair
    } else {
        HandshakeMode::Reconnect
    };
    let payload = HandshakePayload {
        version: RELAY_PROTOCOL_VERSION,
        invitation_id: pairing.map(|pairing| pairing.invitation_id.clone()),
        controller_label: local_device_label(),
        role: super::protocol::RelayRole::Controller,
        session: profile.session.clone(),
        endpoint_generation: crate::protocol::endpoint::ENDPOINT_PROTOCOL_GENERATION,
    };
    let payload = serde_json::to_vec(&payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let (handshake, first) = match credential.pairing_secret().map_err(permanent_config)? {
        Some(secret) => {
            start_pairing_initiator(&identity, &target_public_key, &secret, &prologue, &payload)?
        }
        None => start_reconnect_initiator(&identity, &target_public_key, &prologue, &payload)?,
    };
    websocket
        .send(Message::Binary(
            encode_handshake_message(mode, &first)?.into(),
        ))
        .await
        .map_err(websocket_error)?;
    let response = next_binary(&mut websocket, HANDSHAKE_TIMEOUT).await?;
    let (response_mode, response) = decode_handshake_message(&response)?;
    if response_mode != mode {
        return Err(super::protocol::invalid_data(
            "relay target changed handshake mode",
        ));
    }
    let mut secure = handshake.finish(response)?;

    let (p2p, p2p_events) = negotiate_controller_p2p(&mut websocket, &mut secure).await?;
    if mode == HandshakeMode::Pair {
        RelayClientStore::update(|store| store.complete_pairing(&profile.credential_id))
            .map_err(permanent_config)?;
    }
    Ok(ControllerSession {
        websocket,
        secure,
        p2p,
        p2p_events,
    })
}

async fn negotiate_controller_p2p(
    websocket: &mut RelayWebSocket,
    secure: &mut SecureTransport,
) -> io::Result<(P2pTransport, tokio::sync::mpsc::Receiver<P2pEvent>)> {
    send_controller_secure(websocket, secure, SecureFrameKind::P2pRequest, &[]).await?;
    let config = receive_controller_secure(websocket, secure).await?;
    let config = match config {
        (SecureFrameKind::P2pConfig, payload) => P2pConfig::decode(&payload)?,
        _ => {
            return Err(super::protocol::invalid_data(
                "relay target sent an unexpected peer transport response",
            ))
        }
    };

    let (events_tx, events_rx) = tokio::sync::mpsc::channel(LOCAL_QUEUE_DEPTH);
    let (offer, description) = P2pOffer::create(config, 0, events_tx).await?;
    send_controller_secure(websocket, secure, SecureFrameKind::P2pOffer, &description).await?;
    let answer = receive_controller_secure(websocket, secure).await?;
    let answer = match answer {
        (SecureFrameKind::P2pAnswer, payload) => payload,
        _ => {
            return Err(super::protocol::invalid_data(
                "relay target sent an unexpected peer transport answer",
            ))
        }
    };
    let transport = offer.finish(&answer).await?;

    let confirmation = encode_secure_frame(SecureFrameKind::ClientConfirm, &[])?;
    transport.send(secure.encrypt(&confirmation)?).await?;
    let confirmation = next_p2p_binary(events_rx, HANDSHAKE_TIMEOUT).await?;
    let events_rx = confirmation.0;
    let confirmation = secure.decrypt(&confirmation.1)?;
    if decode_secure_frame(&confirmation)? != (SecureFrameKind::ServerConfirm, &[][..]) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "relay target did not confirm peer transport authorization",
        ));
    }
    Ok((transport, events_rx))
}

async fn send_controller_secure(
    websocket: &mut RelayWebSocket,
    secure: &mut SecureTransport,
    kind: SecureFrameKind,
    payload: &[u8],
) -> io::Result<()> {
    let frame = encode_secure_frame(kind, payload)?;
    websocket
        .send(Message::Binary(secure.encrypt(&frame)?.into()))
        .await
        .map_err(websocket_error)
}

async fn receive_controller_secure(
    websocket: &mut RelayWebSocket,
    secure: &mut SecureTransport,
) -> io::Result<(SecureFrameKind, Vec<u8>)> {
    let ciphertext = next_binary(websocket, HANDSHAKE_TIMEOUT).await?;
    let plaintext = secure.decrypt(&ciphertext)?;
    let (kind, payload) = decode_secure_frame(&plaintext)?;
    Ok((kind, payload.to_vec()))
}

async fn next_p2p_binary(
    mut events: tokio::sync::mpsc::Receiver<P2pEvent>,
    timeout: Duration,
) -> io::Result<(tokio::sync::mpsc::Receiver<P2pEvent>, Vec<u8>)> {
    let event = tokio::time::timeout(timeout, events.recv())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "peer confirmation timed out"))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionReset,
                "peer transport event channel closed",
            )
        })?;
    match event {
        P2pEvent::Data { payload, .. } => Ok((events, payload)),
        P2pEvent::Closed { .. } => Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "peer transport closed",
        )),
    }
}

async fn run_controller_session(
    session: ControllerSession,
    local: crate::ipc::LocalStream,
    cancelled: Arc<AtomicBool>,
) -> io::Result<()> {
    let ControllerSession {
        websocket,
        mut secure,
        p2p,
        mut p2p_events,
    } = session;

    let (mut sink, mut source) = websocket.split();
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel(LOCAL_QUEUE_DEPTH);
    let (inbound_tx, inbound_rx) = mpsc::sync_channel(LOCAL_QUEUE_DEPTH);
    let local_cancelled = cancelled.clone();
    spawn_local_reader(local.try_clone()?, outbound_tx, local_cancelled.clone())?;
    spawn_local_writer(local, inbound_rx, local_cancelled)?;

    loop {
        tokio::select! {
            outbound = outbound_rx.recv() => {
                match outbound {
                    Some(LocalEvent::Data(data)) => {
                        let frame = encode_secure_frame(SecureFrameKind::Data, &data)?;
                        let ciphertext = secure.encrypt(&frame)?;
                        p2p.send(ciphertext).await?;
                    }
                    Some(LocalEvent::Closed) | None => {
                        let _ = sink.send(Message::Close(None)).await;
                        return Ok(());
                    }
                    Some(LocalEvent::Failed(error)) => return Err(error),
                }
            }
            incoming = source.next() => {
                let message = incoming
                    .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionReset, "relay connection closed"))?
                    .map_err(websocket_error)?;
                match message {
                    Message::Binary(_) => return Err(super::protocol::invalid_data(
                        "relay sent data after peer transport activation",
                    )),
                    Message::Ping(payload) => sink.send(Message::Pong(payload)).await.map_err(websocket_error)?,
                    Message::Pong(_) => {}
                    Message::Close(frame) => return Err(websocket_close_error(frame)),
                    Message::Text(_) | Message::Frame(_) => return Err(super::protocol::invalid_data("relay sent a non-binary application message")),
                }
            }
            peer = p2p_events.recv() => {
                match peer {
                    Some(P2pEvent::Data { payload: ciphertext, .. }) => {
                        let plaintext = secure.decrypt(&ciphertext)?;
                        let (kind, payload) = decode_secure_frame(&plaintext)?;
                        if kind != SecureFrameKind::Data {
                            return Err(super::protocol::invalid_data("unexpected secure peer transport control frame"));
                        }
                        inbound_tx.try_send(payload.to_vec()).map_err(|error| match error {
                            mpsc::TrySendError::Full(_) => io::Error::new(io::ErrorKind::ConnectionAborted, "relay input queue is full"),
                            mpsc::TrySendError::Disconnected(_) => io::Error::new(io::ErrorKind::BrokenPipe, "relay local bridge closed"),
                        })?;
                    }
                    Some(P2pEvent::Closed { .. }) | None => {
                        return Err(io::Error::new(io::ErrorKind::ConnectionReset, "peer transport closed"));
                    }
                }
            }
        }
        if cancelled.load(Ordering::Acquire) {
            return Ok(());
        }
    }
}

async fn run_host_reconnect_loop(server_session: String, client_socket_path: PathBuf) {
    let mut delay = RETRY_MIN;
    let mut rejected_state = None;
    let mut handshake_budget = HandshakeBudget::new();
    loop {
        let state = match RelayHostState::load() {
            Ok(Some(current)) if current.enabled && current.session == server_session => current,
            Ok(_) => {
                set_host_runtime_status(HOST_DISABLED, 0);
                rejected_state = None;
                delay = RETRY_MIN;
                tokio::time::sleep(AUTHORIZATION_REFRESH).await;
                continue;
            }
            Err(error) => {
                set_host_runtime_status(HOST_ATTENTION, 0);
                warn!(%error, "relay host state reload failed");
                tokio::time::sleep(RETRY_MAX).await;
                continue;
            }
        };
        if rejected_state.as_ref() == Some(&state) {
            tokio::time::sleep(AUTHORIZATION_REFRESH).await;
            continue;
        }
        rejected_state = None;
        set_host_runtime_status(HOST_CONNECTING, 0);
        if let Ok(mut configuration) = HOST_CONFIGURATION.lock() {
            *configuration = Some(state.configuration_id());
        }
        match run_host_connection(&state, &client_socket_path, &mut handshake_budget).await {
            Ok(()) => delay = RETRY_MIN,
            Err(error) => {
                if failure_needs_attention(&error) {
                    set_host_runtime_status(HOST_ATTENTION, 0);
                    warn!(kind = ?error.kind(), %error, "relay host requires attention");
                    rejected_state = Some(state);
                } else {
                    set_host_runtime_status(HOST_CONNECTING, 0);
                    warn!(kind = ?error.kind(), %error, "relay host connection failed");
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2).min(RETRY_MAX);
                }
            }
        }
    }
}

struct HandshakeBudget {
    started: Instant,
    attempts: u32,
}

impl HandshakeBudget {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            attempts: 0,
        }
    }

    fn admit(&mut self, now: Instant) -> bool {
        if now.duration_since(self.started) >= Duration::from_secs(60) {
            self.started = now;
            self.attempts = 0;
        }
        if self.attempts >= MAX_HANDSHAKES_PER_MINUTE {
            return false;
        }
        self.attempts += 1;
        true
    }
}

enum TargetConnection {
    AwaitingHandshake {
        deadline: Instant,
    },
    AwaitingConfirmation(PendingAuthorization),
    AwaitingP2pConfig(PendingAuthorization),
    AwaitingP2pOffer {
        pending: PendingAuthorization,
        host_config: P2pConfig,
    },
    AwaitingP2pAnswer(PendingAuthorization),
    AwaitingP2pOpen(PendingAuthorization),
    AwaitingP2pConfirmation {
        pending: PendingAuthorization,
        p2p: P2pTransport,
    },
    Connected {
        secure: SecureTransport,
        local: LocalPeer,
        device_public_key: Vec<u8>,
        p2p: P2pTransport,
    },
}

impl TargetConnection {
    fn handshake_expired(&self, now: Instant) -> bool {
        match self {
            Self::AwaitingHandshake { deadline } => *deadline <= now,
            Self::AwaitingConfirmation(pending)
            | Self::AwaitingP2pConfig(pending)
            | Self::AwaitingP2pAnswer(pending)
            | Self::AwaitingP2pOpen(pending)
            | Self::AwaitingP2pOffer { pending, .. }
            | Self::AwaitingP2pConfirmation { pending, .. } => pending.deadline <= now,
            Self::Connected { .. } => false,
        }
    }

    fn pending_device(&self) -> Option<(&[u8], bool)> {
        let pending = match self {
            Self::AwaitingConfirmation(pending)
            | Self::AwaitingP2pConfig(pending)
            | Self::AwaitingP2pAnswer(pending)
            | Self::AwaitingP2pOpen(pending)
            | Self::AwaitingP2pOffer { pending, .. }
            | Self::AwaitingP2pConfirmation { pending, .. } => pending,
            Self::AwaitingHandshake { .. } | Self::Connected { .. } => return None,
        };
        Some((&pending.device_public_key, pending.pairing.is_none()))
    }
}

struct PendingAuthorization {
    deadline: Instant,
    secure: SecureTransport,
    pairing: Option<PairingCompletion>,
    device_public_key: Vec<u8>,
}

struct PairingCompletion {
    invitation_id: String,
    public_key: Vec<u8>,
    label: String,
}

enum HostP2pSetupEvent {
    Config {
        connection_id: u32,
        host: P2pConfig,
        controller: P2pConfig,
    },
    Answer {
        connection_id: u32,
        result: io::Result<(P2pAnswer, Vec<u8>)>,
    },
    Open {
        connection_id: u32,
        result: io::Result<P2pTransport>,
    },
}

impl HostP2pSetupEvent {
    fn connection_id(&self) -> u32 {
        match self {
            Self::Config { connection_id, .. }
            | Self::Answer { connection_id, .. }
            | Self::Open { connection_id, .. } => *connection_id,
        }
    }
}

struct LocalPeer {
    inbound: mpsc::SyncSender<Vec<u8>>,
    cancelled: Arc<AtomicBool>,
}

impl Drop for LocalPeer {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

async fn run_host_connection(
    state: &RelayHostState,
    client_socket_path: &std::path::Path,
    handshake_budget: &mut HandshakeBudget,
) -> io::Result<()> {
    let url = target_url(&state.relay_url, &state.route_id);
    let mut request = url
        .into_client_request()
        .map_err(|_| permanent_config("relay URL is invalid"))?;
    let authorization = HeaderValue::from_str(&format!("Bearer {}", state.registration_capability))
        .map_err(|_| permanent_config("relay registration capability is invalid"))?;
    request.headers_mut().insert("authorization", authorization);
    let websocket_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_RELAY_ENVELOPE))
        .max_frame_size(Some(MAX_RELAY_ENVELOPE));
    let (websocket, _) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::connect_async_with_config(request, Some(websocket_config), true),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay registration timed out"))?
    .map_err(websocket_error)?;
    set_host_runtime_status(HOST_ONLINE, 0);
    info!("relay host connected");
    let identity = state.identity().map_err(permanent_config)?;
    let target_public_key = state.public_key_bytes().map_err(permanent_config)?;
    let prologue = handshake_prologue(&state.route_id, &target_public_key, &state.session);
    let (mut sink, mut source) = websocket.split();
    let (local_tx, mut local_rx) = tokio::sync::mpsc::channel(LOCAL_QUEUE_DEPTH);
    let (p2p_setup_tx, mut p2p_setup_rx) = tokio::sync::mpsc::channel(LOCAL_QUEUE_DEPTH);
    let (p2p_event_tx, mut p2p_event_rx) = tokio::sync::mpsc::channel(LOCAL_QUEUE_DEPTH);
    let mut connections = HashMap::<u32, TargetConnection>::new();
    let mut early_p2p_events = HashMap::<u32, P2pEvent>::new();
    let mut authorization_refresh = tokio::time::interval(AUTHORIZATION_REFRESH);

    loop {
        tokio::select! {
            _ = authorization_refresh.tick() => {
                let current = RelayHostState::load()
                    .map_err(permanent_config)?
                    .ok_or_else(|| permanent_config("relay host state is missing"))?;
                if !current.enabled || !current.same_host_configuration(state) {
                    return Ok(());
                }
                let now = Instant::now();
                let expired = connections
                    .iter()
                    .filter_map(|(connection_id, connection)| {
                        connection
                            .handshake_expired(now)
                            .then_some(*connection_id)
                    })
                    .collect::<Vec<_>>();
                for connection_id in expired {
                    connections.remove(&connection_id);
                    let close = RelayEnvelope {
                        kind: RelayEnvelopeKind::Close,
                        connection_id,
                        payload: b"handshake_timeout".to_vec(),
                    };
                    sink.send(Message::Binary(close.encode()?.into()))
                        .await
                        .map_err(websocket_error)?;
                }
                let revoked = connections
                    .iter()
                    .filter_map(|(connection_id, connection)| match connection {
                        TargetConnection::Connected { device_public_key, .. }
                            if current.paired_device(device_public_key).is_none() =>
                        {
                            Some(*connection_id)
                        }
                        connection
                            if connection
                                .pending_device()
                                .is_some_and(|(device, paired)| {
                                    paired && current.paired_device(device).is_none()
                                }) =>
                        {
                            Some(*connection_id)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                for connection_id in revoked {
                    connections.remove(&connection_id);
                    let close = RelayEnvelope {
                        kind: RelayEnvelopeKind::Close,
                        connection_id,
                        payload: b"controller_revoked".to_vec(),
                    };
                    sink.send(Message::Binary(close.encode()?.into()))
                        .await
                        .map_err(websocket_error)?;
                }
            }
            local = local_rx.recv() => {
                let Some((connection_id, event)) = local else {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "relay host local queue closed"));
                };
                match event {
                    LocalEvent::Data(data) => {
                        let Some(TargetConnection::Connected { secure, p2p, .. }) = connections.get_mut(&connection_id) else {
                            continue;
                        };
                        let frame = encode_secure_frame(SecureFrameKind::Data, &data)?;
                        let ciphertext = secure.encrypt(&frame)?;
                        if let Err(error) = p2p.send(ciphertext).await {
                            warn!(connection_id, kind = ?error.kind(), "peer transport delivery failed");
                            connections.remove(&connection_id);
                            let close = RelayEnvelope {
                                kind: RelayEnvelopeKind::Close,
                                connection_id,
                                payload: peer_close_reason(&error).as_bytes().to_vec(),
                            };
                            sink.send(Message::Binary(close.encode()?.into())).await.map_err(websocket_error)?;
                        }
                    }
                    LocalEvent::Closed | LocalEvent::Failed(_) => {
                        connections.remove(&connection_id);
                        let envelope = RelayEnvelope {
                            kind: RelayEnvelopeKind::Close,
                            connection_id,
                            payload: Vec::new(),
                        };
                        sink.send(Message::Binary(envelope.encode()?.into())).await.map_err(websocket_error)?;
                    }
                }
            }
            incoming = source.next() => {
                let message = incoming
                    .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionReset, "relay registration closed"))?
                    .map_err(websocket_error)?;
                match message {
                    Message::Binary(message) => {
                        let envelope = RelayEnvelope::decode(&message)?;
                        let connection_id = envelope.connection_id;
                        let needs_handshake = envelope.kind == RelayEnvelopeKind::Data
                            && matches!(connections.get(&connection_id), Some(TargetConnection::AwaitingHandshake { .. }));
                        let result = if needs_handshake && !handshake_budget.admit(Instant::now()) {
                            Err(io::Error::new(io::ErrorKind::PermissionDenied, "relay handshake budget exhausted"))
                        } else { handle_target_envelope(
                            state,
                            &identity,
                            &prologue,
                            &mut connections,
                            Some(&p2p_setup_tx),
                            Some(&p2p_event_tx),
                            &mut sink,
                            envelope,
                        ).await };
                        if let Err(error) = result {
                            warn!(
                                connection_id,
                                kind = ?error.kind(),
                                "closing failed relay controller session"
                            );
                            connections.remove(&connection_id);
                            let close = RelayEnvelope {
                                kind: RelayEnvelopeKind::Close,
                                connection_id,
                                payload: target_close_reason(&error).as_bytes().to_vec(),
                            };
                            sink.send(Message::Binary(close.encode()?.into()))
                                .await
                                .map_err(websocket_error)?;
                        }
                    }
                    Message::Ping(payload) => sink.send(Message::Pong(payload)).await.map_err(websocket_error)?,
                    Message::Pong(_) => {}
                    Message::Close(_) => return Err(io::Error::new(io::ErrorKind::ConnectionReset, "relay registration closed")),
                    Message::Text(_) | Message::Frame(_) => return Err(super::protocol::invalid_data("relay sent a non-binary application message")),
                }
            }
            setup = p2p_setup_rx.recv() => {
                let Some(setup) = setup else {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "peer setup queue closed"));
                };
                let connection_id = setup.connection_id();
                if let Err(error) = handle_host_p2p_setup(
                    setup,
                    &mut connections,
                    &mut early_p2p_events,
                    &p2p_setup_tx,
                    &p2p_event_tx,
                    &mut sink,
                ).await {
                    warn!(
                        connection_id,
                        kind = ?error.kind(),
                        "closing failed peer transport setup"
                    );
                    connections.remove(&connection_id);
                    early_p2p_events.remove(&connection_id);
                    let close = RelayEnvelope {
                        kind: RelayEnvelopeKind::Close,
                        connection_id,
                        payload: peer_close_reason(&error).as_bytes().to_vec(),
                    };
                    sink.send(Message::Binary(close.encode()?.into()))
                        .await
                        .map_err(websocket_error)?;
                }
            }
            peer = p2p_event_rx.recv() => {
                let Some(peer) = peer else {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "peer event queue closed"));
                };
                let connection_id = peer.connection_id();
                if let Err(error) = handle_host_p2p_event(
                    state,
                    &mut connections,
                    &mut early_p2p_events,
                    &local_tx,
                    client_socket_path,
                    &mut sink,
                    peer,
                ).await {
                    warn!(connection_id, kind = ?error.kind(), "closing failed peer relay session");
                    connections.remove(&connection_id);
                    early_p2p_events.remove(&connection_id);
                    let close = RelayEnvelope {
                        kind: RelayEnvelopeKind::Close,
                        connection_id,
                        payload: peer_close_reason(&error).as_bytes().to_vec(),
                    };
                    sink.send(Message::Binary(close.encode()?.into()))
                        .await
                        .map_err(websocket_error)?;
                }
            }
        }
        HOST_CONTROLLER_CONNECTIONS.store(
            connections
                .values()
                .filter(|connection| matches!(connection, TargetConnection::Connected { .. }))
                .count(),
            Ordering::Release,
        );
    }
}

async fn handle_target_envelope<S>(
    state: &RelayHostState,
    identity: &IdentityKeypair,
    prologue: &[u8],
    connections: &mut HashMap<u32, TargetConnection>,
    p2p_setup_tx: Option<&tokio::sync::mpsc::Sender<HostP2pSetupEvent>>,
    p2p_event_tx: Option<&tokio::sync::mpsc::Sender<P2pEvent>>,
    sink: &mut S,
    envelope: RelayEnvelope,
) -> io::Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    match envelope.kind {
        RelayEnvelopeKind::Open => {
            if envelope.connection_id == 0
                || connections.contains_key(&envelope.connection_id)
                || connections.len() >= MAX_HOST_CONNECTIONS
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "relay connection limit or invalid connection id",
                ));
            }
            connections.insert(
                envelope.connection_id,
                TargetConnection::AwaitingHandshake {
                    deadline: Instant::now() + HANDSHAKE_TIMEOUT,
                },
            );
        }
        RelayEnvelopeKind::Close => {
            connections.remove(&envelope.connection_id);
        }
        RelayEnvelopeKind::Notice => {
            let notice = std::str::from_utf8(&envelope.payload)
                .map_err(|_| super::protocol::invalid_data("relay notice is not UTF-8"))?;
            warn!(
                connection_id = envelope.connection_id,
                notice, "relay notice"
            );
        }
        RelayEnvelopeKind::Data => {
            let Some(connection) = connections.remove(&envelope.connection_id) else {
                return Ok(());
            };
            if connection.handshake_expired(Instant::now()) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "relay handshake expired",
                ));
            }
            let next = match connection {
                TargetConnection::AwaitingHandshake { .. } => {
                    let (mode, first) = decode_handshake_message(&envelope.payload)?;
                    let (responder, payload, matched_invitation) = match mode {
                        HandshakeMode::Pair => {
                            try_pairing_handshake(state, identity, prologue, first)?
                        }
                        HandshakeMode::Reconnect => {
                            let (responder, payload) =
                                receive_reconnect(identity, prologue, first)?;
                            (responder, payload, None)
                        }
                    };
                    let payload: HandshakePayload =
                        serde_json::from_slice(&payload).map_err(|_| {
                            super::protocol::invalid_data("encrypted handshake payload is invalid")
                        })?;
                    payload.validate(mode, &state.session)?;
                    let remote_static = responder.remote_static()?.to_vec();
                    let pairing = match mode {
                        HandshakeMode::Pair => {
                            let invitation_id = payload.invitation_id.clone().ok_or_else(|| {
                                super::protocol::invalid_data("pairing invitation id is missing")
                            })?;
                            if matched_invitation.as_deref() != Some(invitation_id.as_str()) {
                                return Err(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "relay invitation id does not match its enrollment secret",
                                ));
                            }
                            Some(PairingCompletion {
                                invitation_id,
                                public_key: remote_static.clone(),
                                label: payload.controller_label,
                            })
                        }
                        HandshakeMode::Reconnect => {
                            let current = RelayHostState::load()
                                .map_err(permanent_config)?
                                .ok_or_else(|| permanent_config("relay host state is missing"))?;
                            if !current.enabled
                                || !current.same_host_configuration(state)
                                || current.paired_device(&remote_static).is_none()
                            {
                                return Err(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "relay controller is not authorized",
                                ));
                            }
                            None
                        }
                    };
                    let (secure, response) = responder.finish()?;
                    send_target_data(
                        sink,
                        envelope.connection_id,
                        encode_handshake_message(mode, &response)?,
                    )
                    .await?;
                    TargetConnection::AwaitingConfirmation(PendingAuthorization {
                        deadline: Instant::now() + HANDSHAKE_TIMEOUT,
                        secure,
                        pairing,
                        device_public_key: remote_static,
                    })
                }
                TargetConnection::AwaitingConfirmation(mut pending) => {
                    let (kind, payload) = decrypt_pending_frame(&mut pending, &envelope.payload)?;
                    match kind {
                        SecureFrameKind::P2pRequest if payload.is_empty() => {
                            let setup = p2p_setup_tx.ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::Unsupported,
                                    "peer transport is unavailable",
                                )
                            })?;
                            let setup = setup.clone();
                            pending.deadline = Instant::now() + P2P_HANDSHAKE_TIMEOUT;
                            let relay_url = state.relay_url.clone();
                            let route_id = state.route_id.clone();
                            let capability = state.registration_capability.clone();
                            let connection_id = envelope.connection_id;
                            tokio::spawn(async move {
                                let (host, controller) = super::p2p::load_peer_configs(
                                    &relay_url,
                                    &route_id,
                                    &capability,
                                )
                                .await;
                                let _ = setup
                                    .send(HostP2pSetupEvent::Config {
                                        connection_id,
                                        host,
                                        controller,
                                    })
                                    .await;
                            });
                            TargetConnection::AwaitingP2pConfig(pending)
                        }
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "relay controller did not negotiate peer transport",
                            ))
                        }
                    }
                }
                TargetConnection::AwaitingP2pOffer {
                    mut pending,
                    host_config,
                } => {
                    let (kind, payload) = decrypt_pending_frame(&mut pending, &envelope.payload)?;
                    match kind {
                        SecureFrameKind::P2pOffer => {
                            let setup = p2p_setup_tx.ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::Unsupported,
                                    "peer transport is unavailable",
                                )
                            })?;
                            let events = p2p_event_tx.ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::Unsupported,
                                    "peer transport is unavailable",
                                )
                            })?;
                            let setup = setup.clone();
                            let events = events.clone();
                            let connection_id = envelope.connection_id;
                            tokio::spawn(async move {
                                let result =
                                    answer_p2p(host_config, &payload, connection_id, events).await;
                                let _ = setup
                                    .send(HostP2pSetupEvent::Answer {
                                        connection_id,
                                        result,
                                    })
                                    .await;
                            });
                            TargetConnection::AwaitingP2pAnswer(pending)
                        }
                        _ => {
                            return Err(super::protocol::invalid_data(
                                "unexpected peer transport offer frame",
                            ))
                        }
                    }
                }
                TargetConnection::AwaitingP2pConfig(_)
                | TargetConnection::AwaitingP2pAnswer(_)
                | TargetConnection::AwaitingP2pOpen(_)
                | TargetConnection::AwaitingP2pConfirmation { .. } => {
                    return Err(super::protocol::invalid_data(
                        "unexpected WebSocket data during peer transport setup",
                    ))
                }
                TargetConnection::Connected { .. } => {
                    return Err(super::protocol::invalid_data(
                        "WebSocket endpoint data is not supported",
                    ))
                }
            };
            connections.insert(envelope.connection_id, next);
        }
    }
    Ok(())
}

fn decrypt_pending_frame(
    pending: &mut PendingAuthorization,
    ciphertext: &[u8],
) -> io::Result<(SecureFrameKind, Vec<u8>)> {
    let plaintext = pending.secure.decrypt(ciphertext)?;
    let (kind, payload) = decode_secure_frame(&plaintext)?;
    Ok((kind, payload.to_vec()))
}

fn authorize_target_connection(
    state: &RelayHostState,
    pending: PendingAuthorization,
    connection_id: u32,
    local_tx: &tokio::sync::mpsc::Sender<(u32, LocalEvent)>,
    client_socket_path: &std::path::Path,
) -> io::Result<(SecureTransport, LocalPeer, Vec<u8>)> {
    if let Some(pairing) = pending.pairing {
        let newly_paired = RelayHostState::update(|current| {
            let mut current = current.ok_or("relay host state is missing")?;
            if !current.enabled || !current.same_host_configuration(state) {
                return Err("relay host configuration changed during pairing".into());
            }
            let newly_paired = current.complete_pairing(
                &pairing.invitation_id,
                &pairing.public_key,
                &pairing.label,
            )?;
            Ok((Some(current), newly_paired))
        })
        .map_err(pairing_error)?;
        info!(
            connection_id,
            device = %base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&pairing.public_key),
            label = ?pairing.label,
            invitation = %pairing.invitation_id,
            newly_paired,
            "relay controller pairing confirmed"
        );
    }
    let current = RelayHostState::load()
        .map_err(permanent_config)?
        .ok_or_else(|| permanent_config("relay host state is missing"))?;
    if !current.enabled
        || !current.same_host_configuration(state)
        || current.paired_device(&pending.device_public_key).is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "relay controller is no longer authorized",
        ));
    }
    let local = connect_target_local(client_socket_path, connection_id, local_tx.clone())?;
    Ok((pending.secure, local, pending.device_public_key))
}

async fn handle_host_p2p_setup<S>(
    event: HostP2pSetupEvent,
    connections: &mut HashMap<u32, TargetConnection>,
    early_events: &mut HashMap<u32, P2pEvent>,
    setup_tx: &tokio::sync::mpsc::Sender<HostP2pSetupEvent>,
    p2p_event_tx: &tokio::sync::mpsc::Sender<P2pEvent>,
    sink: &mut S,
) -> io::Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    match event {
        HostP2pSetupEvent::Config {
            connection_id,
            host,
            controller,
        } => {
            let Some(TargetConnection::AwaitingP2pConfig(mut pending)) =
                connections.remove(&connection_id)
            else {
                return Ok(());
            };
            let payload = controller.encode()?;
            send_target_secure(
                sink,
                connection_id,
                &mut pending.secure,
                SecureFrameKind::P2pConfig,
                &payload,
            )
            .await?;
            connections.insert(
                connection_id,
                TargetConnection::AwaitingP2pOffer {
                    pending,
                    host_config: host,
                },
            );
        }
        HostP2pSetupEvent::Answer {
            connection_id,
            result,
        } => {
            let Some(TargetConnection::AwaitingP2pAnswer(mut pending)) =
                connections.remove(&connection_id)
            else {
                return Ok(());
            };
            match result {
                Ok((answer, description)) => {
                    send_target_secure(
                        sink,
                        connection_id,
                        &mut pending.secure,
                        SecureFrameKind::P2pAnswer,
                        &description,
                    )
                    .await?;
                    let setup = setup_tx.clone();
                    tokio::spawn(async move {
                        let result = answer.finish().await;
                        let _ = setup
                            .send(HostP2pSetupEvent::Open {
                                connection_id,
                                result,
                            })
                            .await;
                    });
                    connections.insert(connection_id, TargetConnection::AwaitingP2pOpen(pending));
                }
                Err(error) => return Err(error),
            }
        }
        HostP2pSetupEvent::Open {
            connection_id,
            result,
        } => {
            let Some(TargetConnection::AwaitingP2pOpen(pending)) =
                connections.remove(&connection_id)
            else {
                return Ok(());
            };
            match result {
                Ok(p2p) => {
                    connections.insert(
                        connection_id,
                        TargetConnection::AwaitingP2pConfirmation { pending, p2p },
                    );
                    if let Some(event) = early_events.remove(&connection_id) {
                        p2p_event_tx.send(event).await.map_err(|_| {
                            io::Error::new(io::ErrorKind::BrokenPipe, "peer event queue closed")
                        })?;
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

async fn handle_host_p2p_event<S>(
    state: &RelayHostState,
    connections: &mut HashMap<u32, TargetConnection>,
    early_events: &mut HashMap<u32, P2pEvent>,
    local_tx: &tokio::sync::mpsc::Sender<(u32, LocalEvent)>,
    client_socket_path: &std::path::Path,
    _sink: &mut S,
    event: P2pEvent,
) -> io::Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let connection_id = event.connection_id();
    if matches!(
        connections.get(&connection_id),
        Some(TargetConnection::AwaitingP2pOpen(_))
    ) {
        if early_events.insert(connection_id, event).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "peer transport sent data before setup completed",
            ));
        }
        return Ok(());
    }

    let Some(connection) = connections.remove(&connection_id) else {
        return Ok(());
    };
    let next = match connection {
        TargetConnection::AwaitingP2pConfirmation { mut pending, p2p } => {
            let P2pEvent::Data {
                payload: ciphertext,
                ..
            } = event
            else {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "peer transport closed during confirmation",
                ));
            };
            let (kind, payload) = decrypt_pending_frame(&mut pending, &ciphertext)?;
            if kind != SecureFrameKind::ClientConfirm || !payload.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "peer transport controller confirmation is invalid",
                ));
            }
            let (mut secure, local, device_public_key) = authorize_target_connection(
                state,
                pending,
                connection_id,
                local_tx,
                client_socket_path,
            )?;
            let confirmation = encode_secure_frame(SecureFrameKind::ServerConfirm, &[])?;
            p2p.send(secure.encrypt(&confirmation)?).await?;
            TargetConnection::Connected {
                secure,
                local,
                device_public_key,
                p2p,
            }
        }
        TargetConnection::Connected {
            mut secure,
            local,
            device_public_key,
            p2p,
        } => {
            let P2pEvent::Data {
                payload: ciphertext,
                ..
            } = event
            else {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "peer transport closed",
                ));
            };
            let plaintext = secure.decrypt(&ciphertext)?;
            let (kind, payload) = decode_secure_frame(&plaintext)?;
            if kind != SecureFrameKind::Data {
                return Err(super::protocol::invalid_data(
                    "unexpected secure peer transport control frame",
                ));
            }
            local
                .inbound
                .try_send(payload.to_vec())
                .map_err(|error| match error {
                    mpsc::TrySendError::Full(_) => io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "relay target input queue is full",
                    ),
                    mpsc::TrySendError::Disconnected(_) => io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "relay target local bridge closed",
                    ),
                })?;
            TargetConnection::Connected {
                secure,
                local,
                device_public_key,
                p2p,
            }
        }
        other => {
            connections.insert(connection_id, other);
            return Err(super::protocol::invalid_data(
                "peer transport data arrived in an invalid state",
            ));
        }
    };
    connections.insert(connection_id, next);
    Ok(())
}

async fn send_target_secure<S>(
    sink: &mut S,
    connection_id: u32,
    secure: &mut SecureTransport,
    kind: SecureFrameKind,
    payload: &[u8],
) -> io::Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let frame = encode_secure_frame(kind, payload)?;
    send_target_data(sink, connection_id, secure.encrypt(&frame)?).await
}

fn try_pairing_handshake(
    _state: &RelayHostState,
    identity: &IdentityKeypair,
    prologue: &[u8],
    first: &[u8],
) -> io::Result<(super::crypto::ResponderHandshake, Vec<u8>, Option<String>)> {
    let current = RelayHostState::load()
        .map_err(permanent_config)?
        .ok_or_else(|| permanent_config("relay host state is missing"))?;
    for invitation in &current.invitations {
        let Some(secret) = current.invitation_secret(&invitation.id) else {
            continue;
        };
        if let Ok(result) = receive_pairing(identity, &secret, prologue, first) {
            return Ok((result.0, result.1, Some(invitation.id.clone())));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "relay pairing invitation is invalid or expired",
    ))
}

async fn send_target_data<S>(sink: &mut S, connection_id: u32, payload: Vec<u8>) -> io::Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let envelope = RelayEnvelope {
        kind: RelayEnvelopeKind::Data,
        connection_id,
        payload,
    };
    sink.send(Message::Binary(envelope.encode()?.into()))
        .await
        .map_err(websocket_error)
}

fn connect_target_local(
    client_socket_path: &std::path::Path,
    connection_id: u32,
    outbound: tokio::sync::mpsc::Sender<(u32, LocalEvent)>,
) -> io::Result<LocalPeer> {
    let local = crate::ipc::connect_local_stream(client_socket_path)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let (inbound, inbound_rx) = mpsc::sync_channel(LOCAL_QUEUE_DEPTH);
    let (reader_tx, mut reader_rx) = tokio::sync::mpsc::channel(LOCAL_QUEUE_DEPTH);
    spawn_local_reader(local.try_clone()?, reader_tx, cancelled.clone())?;
    spawn_local_writer(local, inbound_rx, cancelled.clone())?;
    tokio::spawn(async move {
        while let Some(event) = reader_rx.recv().await {
            let closed = !matches!(event, LocalEvent::Data(_));
            if outbound.send((connection_id, event)).await.is_err() || closed {
                return;
            }
        }
        let _ = outbound.send((connection_id, LocalEvent::Closed)).await;
    });
    Ok(LocalPeer { inbound, cancelled })
}

enum LocalEvent {
    Data(Vec<u8>),
    Closed,
    Failed(io::Error),
}

fn spawn_local_reader(
    mut local: crate::ipc::LocalStream,
    outbound: tokio::sync::mpsc::Sender<LocalEvent>,
    cancelled: Arc<AtomicBool>,
) -> io::Result<()> {
    crate::ipc::set_local_stream_polling(&mut local, true)?;
    std::thread::Builder::new()
        .name("relay-local-reader".into())
        .spawn(move || {
            let mut buffer = vec![0_u8; LOCAL_READ_BYTES];
            loop {
                if cancelled.load(Ordering::Acquire) {
                    break;
                }
                match crate::ipc::poll_local_stream_read_count(&mut local, &mut buffer) {
                    Ok(crate::ipc::LocalStreamReadCount::Data(read)) => {
                        if outbound
                            .blocking_send(LocalEvent::Data(buffer[..read].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(crate::ipc::LocalStreamReadCount::Pending) => {
                        std::thread::sleep(LOCAL_POLL_INTERVAL);
                    }
                    Ok(crate::ipc::LocalStreamReadCount::Closed) => {
                        let _ = outbound.blocking_send(LocalEvent::Closed);
                        break;
                    }
                    Err(error) => {
                        let _ = outbound.blocking_send(LocalEvent::Failed(error));
                        break;
                    }
                }
            }
        })?;
    Ok(())
}

fn spawn_local_writer(
    mut local: crate::ipc::LocalStream,
    inbound: mpsc::Receiver<Vec<u8>>,
    cancelled: Arc<AtomicBool>,
) -> io::Result<()> {
    std::thread::Builder::new()
        .name("relay-local-writer".into())
        .spawn(move || {
            while !cancelled.load(Ordering::Acquire) {
                let data = match inbound.recv_timeout(Duration::from_millis(100)) {
                    Ok(data) => data,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                if write_local_with_backpressure(&mut local, &data, &cancelled).is_err() {
                    break;
                }
            }
            cancelled.store(true, Ordering::Release);
        })?;
    Ok(())
}

fn write_local_with_backpressure(
    local: &mut impl io::Write,
    mut data: &[u8],
    cancelled: &AtomicBool,
) -> io::Result<()> {
    while !data.is_empty() {
        if cancelled.load(Ordering::Acquire) {
            return Ok(());
        }
        match local.write(data) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "relay local socket closed",
                ))
            }
            Ok(written) => data = &data[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(LOCAL_POLL_INTERVAL)
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn next_binary<S>(websocket: &mut S, timeout: Duration) -> io::Result<Vec<u8>>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let message = tokio::time::timeout(timeout, websocket.next())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay handshake timed out"))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionReset, "relay connection closed"))?
        .map_err(websocket_error)?;
    match message {
        Message::Binary(data) if data.len() <= MAX_RELAY_PAYLOAD => Ok(data.to_vec()),
        Message::Binary(_) => Err(super::protocol::invalid_data(
            "relay handshake message exceeds the limit",
        )),
        Message::Close(frame) => Err(websocket_close_error(frame)),
        _ => Err(super::protocol::invalid_data(
            "relay handshake requires a binary message",
        )),
    }
}

fn target_close_reason(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::PermissionDenied => "authentication_failed",
        io::ErrorKind::InvalidData => "protocol_error",
        io::ErrorKind::AlreadyExists => "invitation_already_used",
        _ => "target_session_failed",
    }
}

fn peer_close_reason(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::PermissionDenied
        | io::ErrorKind::InvalidData
        | io::ErrorKind::AlreadyExists => target_close_reason(error),
        _ => "peer_transport_failed",
    }
}

/// A pairing code consumed by a different device is a distinct, permanent
/// outcome: the controller must warn rather than exchange a fresh code.
fn pairing_error(error: String) -> io::Error {
    if error == super::store::INVITATION_ALREADY_USED {
        return io::Error::new(io::ErrorKind::AlreadyExists, error);
    }
    permanent_config(error)
}

fn websocket_close_error(frame: Option<CloseFrame>) -> io::Error {
    let reason = frame
        .as_ref()
        .map(|frame| frame.reason.as_str())
        .unwrap_or_default();
    match reason {
        "authentication_failed" | "controller_revoked" => io::Error::new(
            io::ErrorKind::PermissionDenied,
            "relay authorization was rejected",
        ),
        "invitation_already_used" => io::Error::new(
            io::ErrorKind::AlreadyExists,
            "this pairing code was already used by another device",
        ),
        "protocol_error" => super::protocol::invalid_data("relay protocol was rejected"),
        "peer_transport_failed" => io::Error::new(
            io::ErrorKind::ConnectionReset,
            "peer transport setup or delivery failed",
        ),
        "target_unavailable" => {
            io::Error::new(io::ErrorKind::NotConnected, "relay target is unavailable")
        }
        _ => io::Error::new(io::ErrorKind::ConnectionReset, "relay connection closed"),
    }
}

fn controller_url(base: &str, route: &str) -> String {
    format!("{}/v1/controllers/{route}", base.trim_end_matches('/'))
}

fn target_url(base: &str, route: &str) -> String {
    format!("{}/v1/targets/{route}", base.trim_end_matches('/'))
}

fn controller_bridge_path() -> PathBuf {
    let sequence = NEXT_BRIDGE_ID.fetch_add(1, Ordering::Relaxed);
    crate::config::state_dir()
        .join("relay")
        .join(format!("controller-{}-{sequence}.sock", std::process::id()))
}

fn decode_key(value: &str, description: &str) -> io::Result<Vec<u8>> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| permanent_config(format!("{description} is not valid base64url")))?;
    if decoded.len() != 32 {
        return Err(permanent_config(format!(
            "{description} has an invalid length"
        )));
    }
    Ok(decoded)
}

fn local_device_label() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.chars().take(96).collect())
        .unwrap_or_else(|| "Herdr controller".into())
}

fn websocket_error(error: tokio_tungstenite::tungstenite::Error) -> io::Error {
    let kind = match &error {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            websocket_http_error_kind(response.status())
        }
        tokio_tungstenite::tungstenite::Error::Url(_) => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::ConnectionReset,
    };
    io::Error::new(kind, format!("relay WebSocket error: {error}"))
}

fn websocket_http_error_kind(status: StatusCode) -> io::ErrorKind {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => io::ErrorKind::PermissionDenied,
        StatusCode::BAD_REQUEST
        | StatusCode::NOT_FOUND
        | StatusCode::METHOD_NOT_ALLOWED
        | StatusCode::NOT_ACCEPTABLE
        | StatusCode::GONE => io::ErrorKind::InvalidInput,
        StatusCode::UPGRADE_REQUIRED => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::ConnectionReset,
    }
}

fn permanent_config(error: impl ToString) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("relay configuration error: {}", error.to_string()),
    )
}

pub(crate) fn failure_needs_attention(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AlreadyExists
            | io::ErrorKind::InvalidData
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::Unsupported
    )
}

pub(crate) fn host_runtime_status() -> crate::api::schema::RelayServerStatus {
    let status = match HOST_STATUS.load(Ordering::Acquire) {
        HOST_CONNECTING => crate::api::schema::RelayConnectionStatus::Connecting,
        HOST_ONLINE => crate::api::schema::RelayConnectionStatus::Online,
        HOST_ATTENTION => crate::api::schema::RelayConnectionStatus::Attention,
        _ => crate::api::schema::RelayConnectionStatus::Disabled,
    };
    crate::api::schema::RelayServerStatus {
        configuration_id: HOST_CONFIGURATION.lock().ok().and_then(|id| id.clone()),
        status,
        controller_connections: HOST_CONTROLLER_CONNECTIONS.load(Ordering::Acquire),
    }
}

fn set_host_runtime_status(status: u8, controller_connections: usize) {
    HOST_CONTROLLER_CONNECTIONS.store(controller_connections, Ordering::Release);
    HOST_STATUS.store(status, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    fn close(reason: &str) -> Option<CloseFrame> {
        Some(CloseFrame {
            code: CloseCode::Normal,
            reason: reason.into(),
        })
    }

    #[test]
    fn authorization_close_reasons_need_attention() {
        for reason in ["authentication_failed", "controller_revoked"] {
            let error = websocket_close_error(close(reason));
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(failure_needs_attention(&error));
        }
    }

    #[test]
    fn consumed_invitation_is_reported_separately_and_needs_attention() {
        let error = pairing_error(super::super::store::INVITATION_ALREADY_USED.to_owned());
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(target_close_reason(&error), "invitation_already_used");
        let reported = websocket_close_error(close(target_close_reason(&error)));
        assert_eq!(reported.kind(), io::ErrorKind::AlreadyExists);
        assert!(failure_needs_attention(&reported));
        // Any other pairing failure keeps the generic retryable configuration path.
        let other = pairing_error("relay host state is missing".to_owned());
        assert_eq!(other.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(target_close_reason(&other), "target_session_failed");
    }

    #[test]
    fn target_absence_remains_reconnectable() {
        let error = websocket_close_error(close("target_unavailable"));
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(!failure_needs_attention(&error));
    }

    #[test]
    fn deterministic_http_configuration_failures_need_attention() {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::METHOD_NOT_ALLOWED,
        ] {
            let kind = websocket_http_error_kind(status);
            assert!(matches!(
                kind,
                io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
            ));
        }
        assert_eq!(
            websocket_http_error_kind(StatusCode::UPGRADE_REQUIRED),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            websocket_http_error_kind(StatusCode::TOO_MANY_REQUESTS),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            websocket_http_error_kind(StatusCode::SERVICE_UNAVAILABLE),
            io::ErrorKind::ConnectionReset
        );
    }

    #[test]
    fn unauthenticated_connections_expire() {
        let now = Instant::now();
        let pending = TargetConnection::AwaitingHandshake {
            deadline: now - Duration::from_millis(1),
        };
        assert!(pending.handshake_expired(now));
    }

    #[cfg(not(windows))]
    #[test]
    fn rustls_crypto_provider_is_selected_by_features() {
        let _ = rustls::ClientConfig::builder();
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod connection_tests;
