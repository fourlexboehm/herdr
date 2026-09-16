use serde::Serialize;
use std::time::Duration;

use crate::relay::store::RelayHostState;

const HELP: &str = "Usage:
  herdr relay enable --url <wss-url> --label <label> [--session <name>]
  herdr relay disable
  herdr relay invite
  herdr relay devices [--json]
  herdr relay revoke <public-key>
  herdr relay status [--json]

Relay hosting is experimental. The target makes only outbound WSS connections.
Invitations are one-use secrets; transfer them through a trusted channel.";

pub(super) fn run_relay_command(args: &[String]) -> std::io::Result<i32> {
    match args.first().map(String::as_str) {
        Some("enable") => enable(&args[1..]),
        Some("disable") if args.len() == 1 => disable(),
        Some("invite") if args.len() == 1 => invite(),
        Some("devices") => devices(&args[1..]),
        Some("revoke") => revoke(&args[1..]),
        Some("status") => status(&args[1..]),
        Some("help" | "--help" | "-h") => {
            println!("{HELP}");
            Ok(0)
        }
        _ => {
            eprintln!("{HELP}");
            Ok(2)
        }
    }
}

fn enable(args: &[String]) -> std::io::Result<i32> {
    let args = super::expand_equals_args(args, &["--url", "--label", "--session"]);
    let mut url = None;
    let mut label = None;
    let mut session = None;
    let mut index = 0;
    while index < args.len() {
        let Some(value) = args.get(index + 1) else {
            eprintln!("missing value for {}", args[index]);
            return Ok(2);
        };
        match args[index].as_str() {
            "--url" if url.is_none() => url = Some(value.clone()),
            "--label" if label.is_none() => label = Some(value.clone()),
            "--session" if session.is_none() => session = Some(value.clone()),
            unknown => {
                eprintln!("unknown or repeated relay enable option: {unknown}");
                return Ok(2);
            }
        }
        index += 2;
    }
    let (Some(url), Some(label)) = (url, label) else {
        eprintln!("usage: herdr relay enable --url <wss-url> --label <label> [--session <name>]");
        return Ok(2);
    };
    let session = session
        .or_else(crate::session::active_name)
        .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
    const SESSION_CHANGE_BLOCKED: &str =
        "revoke paired devices before changing the hosted Herdr session";
    let updated = RelayHostState::update(|current| {
        let mut state = match current {
            Some(state) => {
                if state.session != session && !state.paired_devices.is_empty() {
                    return Err(SESSION_CHANGE_BLOCKED.into());
                }
                state
            }
            None => RelayHostState::create(&url, &label, &session)?,
        };
        state.enabled = true;
        state.relay_url = url.trim_end_matches('/').to_owned();
        state.target_label = label;
        state.session = session;
        Ok((Some(state), ()))
    });
    if let Err(error) = updated {
        if error == SESSION_CHANGE_BLOCKED {
            eprintln!("error: {error}");
            return Ok(2);
        }
        return Err(std::io::Error::other(error));
    }
    println!("Enabled encrypted relay hosting.");
    println!("{}", crate::relay::FEATURE_WARNING);
    let state = RelayHostState::load()
        .map_err(std::io::Error::other)?
        .ok_or_else(|| std::io::Error::other("relay host configuration is missing"))?;
    super::relay_setup::ensure_host_running(&state)?;
    println!(
        "Relay hosting is online. Run `herdr machine add-relay` on both devices to exchange codes."
    );
    Ok(0)
}

fn disable() -> std::io::Result<i32> {
    let changed = RelayHostState::update(|current| {
        let Some(mut state) = current else {
            return Ok((None, false));
        };
        state.enabled = false;
        Ok((Some(state), true))
    })
    .map_err(std::io::Error::other)?;
    if !changed {
        println!("Relay hosting is not configured.");
        return Ok(0);
    }
    println!(
        "Disabled relay hosting. A running relay host closes active sessions within a few seconds."
    );
    Ok(0)
}

fn invite() -> std::io::Result<i32> {
    const NOT_CONFIGURED: &str = "relay hosting is not configured; run `herdr relay enable` first";
    const DISABLED: &str = "relay hosting is disabled";
    let invitation = RelayHostState::update(|current| {
        let Some(mut state) = current else {
            return Err(NOT_CONFIGURED.into());
        };
        if !state.enabled {
            return Err(DISABLED.into());
        }
        let invitation = state.create_invitation()?;
        Ok((Some(state), invitation))
    });
    let invitation = match invitation {
        Ok(invitation) => invitation,
        Err(error) if error == NOT_CONFIGURED || error == DISABLED => {
            eprintln!("error: {error}");
            return Ok(1);
        }
        Err(error) => return Err(std::io::Error::other(error)),
    };
    let encoded = invitation.encode().map_err(std::io::Error::other)?;
    println!("{}", encoded.as_str());
    eprintln!("This one-use invitation expires in 15 minutes. Treat it as a secret.");
    Ok(0)
}

#[derive(Serialize)]
struct DeviceRow<'a> {
    public_key: &'a str,
    label: &'a str,
    role: crate::relay::protocol::RelayRole,
    paired_unix_seconds: u64,
}

fn devices(args: &[String]) -> std::io::Result<i32> {
    let Some(json) = parse_json_flag(args, "usage: herdr relay devices [--json]") else {
        return Ok(2);
    };
    let Some(state) = RelayHostState::load().map_err(std::io::Error::other)? else {
        if json {
            println!("[]");
        } else {
            println!("No paired relay devices.");
        }
        return Ok(0);
    };
    let rows = state
        .paired_devices
        .iter()
        .map(|device| DeviceRow {
            public_key: &device.public_key,
            label: &device.label,
            role: device.role,
            paired_unix_seconds: device.paired_unix_seconds,
        })
        .collect::<Vec<_>>();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(std::io::Error::other)?
        );
    } else if rows.is_empty() {
        println!("No paired relay devices.");
    } else {
        for row in rows {
            println!(
                "{}\t{}\t{:?}\t{}",
                row.public_key, row.label, row.role, row.paired_unix_seconds
            );
        }
    }
    Ok(0)
}

fn revoke(args: &[String]) -> std::io::Result<i32> {
    let [public_key] = args else {
        eprintln!("usage: herdr relay revoke <public-key>");
        return Ok(2);
    };
    const NOT_CONFIGURED: &str = "relay hosting is not configured";
    let revoked = RelayHostState::update(|current| {
        let Some(mut state) = current else {
            return Err(NOT_CONFIGURED.into());
        };
        let revoked = state.revoke(public_key);
        Ok((Some(state), revoked))
    });
    let revoked = match revoked {
        Ok(revoked) => revoked,
        Err(error) if error == NOT_CONFIGURED => {
            eprintln!("error: {error}");
            return Ok(1);
        }
        Err(error) => return Err(std::io::Error::other(error)),
    };
    if !revoked {
        eprintln!("error: paired relay device was not found");
        return Ok(1);
    }
    println!("Revoked relay device.");
    Ok(0)
}

#[derive(Serialize)]
struct RelayStatus<'a> {
    configured: bool,
    enabled: bool,
    relay_url: Option<&'a str>,
    target_label: Option<&'a str>,
    session: Option<&'a str>,
    paired_devices: usize,
    pending_invitations: usize,
    experimental: bool,
    runtime: Option<crate::api::schema::RelayServerStatus>,
}

fn status(args: &[String]) -> std::io::Result<i32> {
    let Some(json) = parse_json_flag(args, "usage: herdr relay status [--json]") else {
        return Ok(2);
    };
    let state = RelayHostState::load().map_err(std::io::Error::other)?;
    let active_session = crate::session::active_name()
        .unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
    let runtime_socket = state
        .as_ref()
        .filter(|state| state.session != active_session)
        .and_then(|state| crate::session::parse_target_name(&state.session).ok())
        .map(|session| crate::session::api_socket_path_for(session.as_deref()))
        .unwrap_or_else(crate::api::socket_path);
    let runtime = crate::api::read_runtime_status_at(&runtime_socket, Duration::from_millis(250))?
        .and_then(|status| status.capabilities)
        .and_then(|capabilities| capabilities.relay);
    let status = RelayStatus {
        configured: state.is_some(),
        enabled: state.as_ref().is_some_and(|state| state.enabled),
        relay_url: state.as_ref().map(|state| state.relay_url.as_str()),
        target_label: state.as_ref().map(|state| state.target_label.as_str()),
        session: state.as_ref().map(|state| state.session.as_str()),
        paired_devices: state.as_ref().map_or(0, |state| state.paired_devices.len()),
        pending_invitations: state.as_ref().map_or(0, |state| state.invitations.len()),
        experimental: true,
        runtime,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status).map_err(std::io::Error::other)?
        );
    } else if let Some(state) = state.as_ref() {
        println!(
            "{}\t{}\t{}\t{}\t{} paired\t{} pending\truntime {}",
            if state.enabled { "enabled" } else { "disabled" },
            state.relay_url,
            state.target_label,
            state.session,
            status.paired_devices,
            status.pending_invitations,
            status
                .runtime
                .as_ref()
                .map_or("not running", |runtime| match runtime.status {
                    crate::api::schema::RelayConnectionStatus::Disabled => "disabled",
                    crate::api::schema::RelayConnectionStatus::Connecting => "connecting",
                    crate::api::schema::RelayConnectionStatus::Online => "online",
                    crate::api::schema::RelayConnectionStatus::Attention => "attention",
                    crate::api::schema::RelayConnectionStatus::Unknown => "unknown",
                })
        );
        println!("{}", crate::relay::FEATURE_WARNING);
    } else {
        println!("Relay hosting is not configured.");
    }
    Ok(0)
}

fn parse_json_flag(args: &[String], usage: &str) -> Option<bool> {
    match args {
        [] => Some(false),
        [flag] if flag == "--json" => Some(true),
        _ => {
            eprintln!("{usage}");
            None
        }
    }
}
