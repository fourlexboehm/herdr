use super::*;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Default)]
struct Captured(Vec<Message>);
impl futures_util::Sink<Message> for Captured {
    type Error = tokio_tungstenite::tungstenite::Error;
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn start_send(mut self: Pin<&mut Self>, message: Message) -> Result<(), Self::Error> {
        self.0.push(message);
        Ok(())
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

struct StateDirectory {
    previous: Option<std::ffi::OsString>,
    root: PathBuf,
}

impl StateDirectory {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("herdr-relay-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let previous = std::env::var_os("XDG_STATE_HOME");
        std::env::set_var("XDG_STATE_HOME", &root);
        Self { previous, root }
    }
}

impl Drop for StateDirectory {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var("XDG_STATE_HOME", value),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn relay_websocket_confirmation_is_rejected_before_local_access() {
    let _lock = crate::config::test_config_env_lock().lock().unwrap();
    let _directory = StateDirectory::new("confirmation");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut host =
                RelayHostState::create("wss://relay.example", "audit", "default").unwrap();
            let invite = host.create_invitation().unwrap();
            let controller = IdentityKeypair::generate().unwrap();
            host.complete_pairing(&invite.invitation_id, controller.public(), "controller")
                .unwrap();
            let identity = host.identity().unwrap();
            let prologue = handshake_prologue(&host.route_id, identity.public(), &host.session);
            for expired in [false, true] {
                let (initiator, first) =
                    start_reconnect_initiator(&controller, identity.public(), &prologue, b"")
                        .unwrap();
                let (responder, _) = receive_reconnect(&identity, &prologue, &first).unwrap();
                let (secure, response) = responder.finish().unwrap();
                let mut sender = initiator.finish(&response).unwrap();
                let mut connections = HashMap::from([(
                    1,
                    TargetConnection::AwaitingConfirmation(PendingAuthorization {
                        deadline: if expired {
                            Instant::now() - Duration::from_secs(1)
                        } else {
                            Instant::now() + HANDSHAKE_TIMEOUT
                        },
                        secure,
                        pairing: None,
                        device_public_key: controller.public().to_vec(),
                    }),
                )]);
                host.revoke(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(controller.public()),
                );
                host.store_to_path(&super::super::store::host_state_path())
                    .unwrap();
                let frame = encode_secure_frame(SecureFrameKind::ClientConfirm, &[]).unwrap();
                let error = handle_target_envelope(
                    &host,
                    &identity,
                    &prologue,
                    &mut connections,
                    None,
                    None,
                    &mut Captured::default(),
                    RelayEnvelope {
                        kind: RelayEnvelopeKind::Data,
                        connection_id: 1,
                        payload: sender.encrypt(&frame).unwrap(),
                    },
                )
                .await
                .unwrap_err();
                assert_eq!(
                    error.kind(),
                    if expired {
                        io::ErrorKind::TimedOut
                    } else {
                        io::ErrorKind::PermissionDenied
                    }
                );
                if !expired {
                    assert_eq!(
                        error.to_string(),
                        "relay controller did not negotiate peer transport"
                    );
                }
                assert!(connections.is_empty());
            }
        });
}

#[test]
fn relay_peer_confirmation_rechecks_revocation_before_local_access() {
    let _lock = crate::config::test_config_env_lock().lock().unwrap();
    let _directory = StateDirectory::new("peer-confirmation");
    let mut host = RelayHostState::create("wss://relay.example", "audit", "default").unwrap();
    let invite = host.create_invitation().unwrap();
    let controller = IdentityKeypair::generate().unwrap();
    host.complete_pairing(&invite.invitation_id, controller.public(), "controller")
        .unwrap();
    let identity = host.identity().unwrap();
    let prologue = handshake_prologue(&host.route_id, identity.public(), &host.session);
    let (_, first) =
        start_reconnect_initiator(&controller, identity.public(), &prologue, b"").unwrap();
    let (responder, _) = receive_reconnect(&identity, &prologue, &first).unwrap();
    let (secure, _) = responder.finish().unwrap();
    host.revoke(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(controller.public()));
    host.store_to_path(&super::super::store::host_state_path())
        .unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let result = authorize_target_connection(
        &host,
        PendingAuthorization {
            deadline: Instant::now() + HANDSHAKE_TIMEOUT,
            secure,
            pairing: None,
            device_public_key: controller.public().to_vec(),
        },
        1,
        &tx,
        &PathBuf::from("/nonexistent-audit-socket"),
    );
    match result {
        Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
        Ok(_) => panic!("revoked controller reached the local endpoint"),
    }
}

#[tokio::test]
async fn failed_peer_setup_does_not_restore_websocket_transport() {
    let target = IdentityKeypair::generate().unwrap();
    let controller = IdentityKeypair::generate().unwrap();
    let prologue = b"mandatory-peer-transport";
    let (_, first) =
        start_reconnect_initiator(&controller, target.public(), prologue, b"").unwrap();
    let (responder, _) = receive_reconnect(&target, prologue, &first).unwrap();
    let (secure, _) = responder.finish().unwrap();
    let mut connections = HashMap::from([(
        1,
        TargetConnection::AwaitingP2pAnswer(PendingAuthorization {
            deadline: Instant::now() + P2P_HANDSHAKE_TIMEOUT,
            secure,
            pairing: None,
            device_public_key: controller.public().to_vec(),
        }),
    )]);
    let mut early_events = HashMap::new();
    let (setup_tx, _setup_rx) = tokio::sync::mpsc::channel(1);
    let (event_tx, _event_rx) = tokio::sync::mpsc::channel(1);
    let mut sink = Captured::default();
    let error = handle_host_p2p_setup(
        HostP2pSetupEvent::Answer {
            connection_id: 1,
            result: Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peer setup timed out",
            )),
        },
        &mut connections,
        &mut early_events,
        &setup_tx,
        &event_tx,
        &mut sink,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(connections.is_empty());
    assert!(sink.0.is_empty());
}

#[tokio::test]
async fn relay_host_limits_untrusted_opens_and_rejects_duplicate_ids() {
    let host = RelayHostState::create("wss://relay.example", "audit", "default").unwrap();
    let identity = host.identity().unwrap();
    let prologue = handshake_prologue(&host.route_id, identity.public(), &host.session);
    let mut connections = HashMap::new();
    let mut sink = Captured::default();
    for connection_id in 1..=MAX_HOST_CONNECTIONS as u32 {
        handle_target_envelope(
            &host,
            &identity,
            &prologue,
            &mut connections,
            None,
            None,
            &mut sink,
            RelayEnvelope {
                kind: RelayEnvelopeKind::Open,
                connection_id,
                payload: vec![],
            },
        )
        .await
        .unwrap();
    }
    for connection_id in [0, 1, MAX_HOST_CONNECTIONS as u32 + 1] {
        assert!(handle_target_envelope(
            &host,
            &identity,
            &prologue,
            &mut connections,
            None,
            None,
            &mut sink,
            RelayEnvelope {
                kind: RelayEnvelopeKind::Open,
                connection_id,
                payload: vec![]
            }
        )
        .await
        .is_err());
    }
    assert_eq!(connections.len(), MAX_HOST_CONNECTIONS);
    let mut budget = HandshakeBudget::new();
    let now = Instant::now();
    for _ in 0..MAX_HANDSHAKES_PER_MINUTE {
        assert!(budget.admit(now));
    }
    assert!(!budget.admit(now));
    assert!(budget.admit(now + Duration::from_secs(60)));
}

#[test]
fn relay_local_writer_preserves_partial_writes_across_backpressure() {
    struct Writer {
        calls: usize,
        bytes: Vec<u8>,
    }
    impl io::Write for Writer {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            match self.calls {
                2 => Err(io::ErrorKind::WouldBlock.into()),
                3 => Err(io::ErrorKind::Interrupted.into()),
                _ => {
                    let count = data.len().min(3);
                    self.bytes.extend_from_slice(&data[..count]);
                    Ok(count)
                }
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        calls: 0,
        bytes: Vec::new(),
    };
    let payload = b"endpoint snapshot and input must arrive exactly once";
    write_local_with_backpressure(&mut writer, payload, &AtomicBool::new(false)).unwrap();
    assert_eq!(writer.bytes, payload);
    let calls = writer.calls;
    write_local_with_backpressure(&mut writer, b"cancelled", &AtomicBool::new(true)).unwrap();
    assert_eq!(writer.calls, calls);
}

#[test]
fn relay_supervisor_observes_enable_disable_and_reenable_without_restart() {
    let _lock = crate::config::test_config_env_lock().lock().unwrap();
    let _directory = StateDirectory::new("supervisor");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut host = RelayHostState::create(
                &format!("ws://{}", listener.local_addr().unwrap()),
                "audit",
                "default",
            )
            .unwrap();
            let task = tokio::spawn(run_host_reconnect_loop("default".into(), PathBuf::new()));
            // Start from absent configuration, as a server launched before setup does.
            tokio::task::yield_now().await;
            for _ in 0..2 {
                host.enabled = true;
                host.store_to_path(&super::super::store::host_state_path())
                    .unwrap();
                let (tcp, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
                let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                // Let registration and the initial authorization refresh finish.
                tokio::task::yield_now().await;
                host.enabled = false;
                host.store_to_path(&super::super::store::host_state_path())
                    .unwrap();
                let _ = tokio::time::timeout(Duration::from_secs(5), ws.next())
                    .await
                    .unwrap();
            }
            task.abort();
            let _ = task.await;
        });
}
