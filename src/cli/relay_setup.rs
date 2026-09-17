use std::io::{self, BufRead, IsTerminal as _, Read as _, Write};
use std::time::{Duration, Instant};

use crate::client::endpoint::{EndpointCatalog, SavedRelayEndpoint};
use crate::relay::store::{RelayClientStore, RelayHostState, RelayInvitation};

const MAX_PASTE_BYTES: u64 = 16 * 1024;

#[derive(Default, Debug, PartialEq, Eq)]
struct SetupArgs {
    url: Option<String>,
    label: Option<String>,
}

fn parse_args(args: &[String]) -> Result<SetupArgs, String> {
    let args = super::expand_equals_args(args, &["--url", "--label"]);
    let mut parsed = SetupArgs::default();
    for pair in args.chunks(2) {
        let [flag, value] = pair else {
            return Err("expected a value after the option".into());
        };
        let slot = match flag.as_str() {
            "--url" => &mut parsed.url,
            "--label" => &mut parsed.label,
            _ => return Err(format!("unknown add-relay option: {flag}")),
        };
        if slot.is_some() || value.trim().is_empty() {
            return Err(format!("{flag} requires one nonempty value"));
        }
        *slot = Some(value.trim().to_owned());
    }
    Ok(parsed)
}

pub(super) fn run(args: &[String]) -> io::Result<i32> {
    let args = match parse_args(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!(
                "{error}\nusage: herdr machine add-relay [--url <wss-url>] [--label <label>]"
            );
            return Ok(2);
        }
    };
    let interactive = io::stdin().is_terminal();
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let local = if interactive {
        let current = RelayHostState::load().map_err(io::Error::other)?;
        let url = match args
            .url
            .or_else(|| current.as_ref().map(|host| host.relay_url.clone()))
        {
            Some(url) => url,
            None => {
                write!(output, "Relay URL (wss://…): ")?;
                output.flush()?;
                read_paste(&mut input)?
            }
        };
        crate::relay::store::validate_relay_url(&url).map_err(io::Error::other)?;
        let session = current
            .as_ref()
            .map(|host| host.session.clone())
            .or_else(crate::session::active_name)
            .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
        let label = crate::platform::hostname().unwrap_or_else(|| "Herdr device".into());
        let host = RelayHostState::update(|current| {
            let mut host = match current {
                Some(host) => host,
                None => RelayHostState::create(&url, &label, &session)?,
            };
            host.enabled = true;
            host.relay_url = url.trim_end_matches('/').to_owned();
            Ok((Some(host.clone()), host))
        })
        .map_err(io::Error::other)?;
        writeln!(output, "Connecting this device to the relay…")?;
        output.flush()?;
        ensure_host_running(&host)?;
        let invitation = RelayHostState::update(|current| {
            let mut host = current.ok_or("relay host configuration is missing")?;
            let invitation = host.create_invitation()?;
            Ok((Some(host), invitation))
        })
        .map_err(io::Error::other)?;
        write_exchange_prompt(&mut output, &invitation)?;
        Some(host)
    } else {
        if args.url.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--url is for interactive setup; piped invitations already contain the relay URL",
            ));
        }
        None
    };
    let invitation = loop {
        let pasted = read_paste(&mut input)?;
        match RelayInvitation::decode(&pasted).and_then(|invitation| {
            if local
                .as_ref()
                .is_some_and(|host| host.route_id == invitation.route_id)
            {
                Err("that is this device's code; paste the code from the other device".into())
            } else {
                Ok(invitation)
            }
        }) {
            Ok(invitation) => break invitation,
            Err(error) if interactive => {
                writeln!(output, "{error}")?;
                write!(output, "Paste the other device's code, then press Enter: ")?;
                output.flush()?;
            }
            Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
        }
    };
    writeln!(
        output,
        "Checking the encrypted connection to {}…",
        invitation.target_label
    )?;
    output.flush()?;
    let profile = save_invitation(&invitation, args.label)?;
    match verify_connection(&profile) {
        Ok(()) => {
            let mut catalog = EndpointCatalog::load().map_err(io::Error::other)?;
            let saved = catalog
                .relay
                .iter_mut()
                .find(|saved| saved.id == profile.id)
                .ok_or_else(|| io::Error::other("machine was removed while connecting"))?;
            saved.enabled = true;
            saved.connection_revision = saved.connection_revision.saturating_add(1);
            catalog.store_relay_profiles().map_err(io::Error::other)?;
            writeln!(
                output,
                "Connected to {}. It is ready in Herdr.",
                profile.label
            )?;
            if interactive {
                writeln!(
                    output,
                    "Finish pasting this device's code on the other device to connect both ways."
                )?;
            }
            Ok(0)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            writeln!(output, "Could not connect to {}: {error}", profile.label)?;
            writeln!(
                output,
                "Another device completed pairing with that code first. Run `herdr relay devices` on {} and revoke any device you do not recognize before exchanging a new code.",
                profile.label
            )?;
            Ok(1)
        }
        Err(error) => {
            writeln!(output, "Could not connect to {}: {error}", profile.label)?;
            writeln!(output, "The machine is saved for retry. Run this command again and exchange fresh codes on both devices.")?;
            Ok(1)
        }
    }
}

fn read_paste(input: &mut impl BufRead) -> io::Result<String> {
    let mut line = String::new();
    input.take(MAX_PASTE_BYTES + 1).read_line(&mut line)?;
    if line.len() as u64 > MAX_PASTE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pasted value is too long",
        ));
    }
    if line.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no pairing code entered",
        ));
    }
    Ok(line.trim().to_owned())
}

fn write_exchange_prompt(output: &mut impl Write, invitation: &RelayInvitation) -> io::Result<()> {
    writeln!(
        output,
        "\nCopy this code to the other device (private; expires in 15 minutes):\n"
    )?;
    writeln!(
        output,
        "{}\n",
        invitation.encode().map_err(io::Error::other)?.as_str()
    )?;
    write!(
        output,
        "Paste the other device's code here, then press Enter: "
    )?;
    output.flush()
}

pub(super) fn ensure_host_running(host: &RelayHostState) -> io::Result<()> {
    let session = crate::session::parse_target_name(&host.session).map_err(io::Error::other)?;
    let socket = crate::session::client_socket_path_for(session.as_deref());
    let api_socket = crate::session::api_socket_path_for(session.as_deref());
    if crate::api::read_runtime_status_at(&api_socket, Duration::from_millis(500))?.is_none() {
        crate::server::autodetect::spawn_server_daemon_for_session(&host.session)?;
        crate::server::autodetect::wait_for_server_socket(&socket, Duration::from_secs(10))?;
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) =
            crate::api::read_runtime_status_at(&api_socket, Duration::from_millis(500))?
        {
            let relay = status.capabilities.and_then(|caps| caps.relay)
                .ok_or_else(|| io::Error::other("the running Herdr server does not support relay access; update that server first"))?;
            match relay.status {
                crate::api::schema::RelayConnectionStatus::Online
                    if relay.configuration_id.as_deref() == Some(host.configuration_id().as_str()) => return Ok(()),
                crate::api::schema::RelayConnectionStatus::Attention
                    if relay.configuration_id.as_deref() == Some(host.configuration_id().as_str()) => return Err(io::Error::other(
                    "this device cannot register with the relay; check the relay URL and the session's herdr-server.log")),
                _ => {},
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, format!(
                "relay hosting did not become ready for session {}; check its herdr-server.log. A server from an older relay build needs updating before interactive setup", host.session)));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn save_invitation(
    invitation: &RelayInvitation,
    label: Option<String>,
) -> io::Result<SavedRelayEndpoint> {
    let mut catalog = EndpointCatalog::load().map_err(io::Error::other)?;
    if let Some(existing) = catalog.relay.iter_mut().find(|profile| {
        profile.route_id == invitation.route_id && profile.session == invitation.session
    }) {
        if existing.target_public_key != invitation.target_public_key {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the saved machine's identity differs from this code; remove the old machine explicitly before trusting a replacement"));
        }
        let mut profile = existing.clone();
        profile.relay_url = invitation.relay_url.clone();
        if let Some(label) = label {
            profile.label = label;
        }
        // Validate the catalog before changing credentials or persistent metadata.
        *existing = profile.clone();
        catalog.store_relay_profiles().map_err(io::Error::other)?;
        RelayClientStore::update(|store| {
            store.renew_invitation(&profile.credential_id, invitation)
        })
        .map_err(io::Error::other)?;
        return Ok(profile);
    }
    let credential_id = RelayClientStore::update(|store| store.import_invitation(invitation))
        .map_err(io::Error::other)?;
    let result = (|| {
        let mut profile = SavedRelayEndpoint::from_invitation(invitation, &credential_id)
            .map_err(io::Error::other)?;
        if let Some(label) = label {
            profile.label = label;
        }
        profile.enabled = false;
        catalog
            .add_relay(profile.clone())
            .map_err(io::Error::other)?;
        catalog.store_relay_profiles().map_err(io::Error::other)?;
        Ok(profile)
    })();
    if result.is_err() {
        let _ = RelayClientStore::update(|store| {
            store.remove(&credential_id);
            Ok(())
        });
    }
    result
}

fn verify_connection(profile: &SavedRelayEndpoint) -> io::Result<()> {
    let mut connected = crate::relay::transport::connect_controller(profile)?;
    let negotiation = crate::client::probe_endpoint_negotiation(&mut connected.stream)
        .map_err(|error| connected.bridge.reported_failure().unwrap_or(error))?;
    if !negotiation.supports_surface_interest() || !negotiation.supports_health_check() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the remote Herdr server needs updating for multi-machine connections",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_paste_finishes_at_enter_without_waiting_for_eof() {
        let mut input = io::Cursor::new(b"  first-code\r\nsecond-code\n");
        assert_eq!(read_paste(&mut input).unwrap(), "first-code");
        assert_eq!(read_paste(&mut input).unwrap(), "second-code");
        assert!(read_paste(&mut input).is_err());
        assert!(read_paste(&mut io::Cursor::new(vec![
            b'a';
            MAX_PASTE_BYTES as usize + 1
        ]))
        .is_err());
    }

    #[test]
    fn relay_setup_rejects_duplicate_and_missing_options() {
        assert!(parse_args(&["--url".into()]).is_err());
        assert!(parse_args(&["--url=a".into(), "--url=b".into()]).is_err());
        assert_eq!(
            parse_args(&["--url=wss://relay.example".into()])
                .unwrap()
                .url
                .as_deref(),
            Some("wss://relay.example")
        );
    }
}
