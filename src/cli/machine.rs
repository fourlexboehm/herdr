use serde::Serialize;

use crate::client::endpoint::{ClientEndpointId, EndpointCatalog, ProfileId};

const HELP: &str = "Usage:
  herdr machine list [--json]
  herdr machine add <ssh-target> --label <label> [--remote-session <name>]
  herdr machine add-relay [--url <wss-url>] [--label <label>]
  herdr machine rename <profile-id> --label <label>
  herdr machine remove <profile-id>
  herdr machine enable <profile-id>
  herdr machine disable <profile-id>

Add prepares the remote Herdr installation and starts its server before saving.
Missing or incompatible installations require approval in an interactive terminal.
Changes apply automatically to open local Herdr clients.
Removing or disabling a machine leaves its remote sessions running.
Add-relay prints a pairing code and accepts the other device's code with Enter.
Saved machine catalogs do not contain private keys or enrollment secrets.";

#[derive(Serialize)]
struct MachineListRow {
    id: String,
    label: String,
    transport: &'static str,
    target: String,
    session: String,
    enabled: bool,
    selected: bool,
}

pub(super) fn run_machine_command(args: &[String]) -> std::io::Result<i32> {
    match args.first().map(String::as_str) {
        Some("list") => list(&args[1..]),
        Some("add") => add(&args[1..]),
        Some("add-relay") => add_relay(&args[1..]),
        Some("rename") => rename(&args[1..]),
        Some("remove") => remove(&args[1..]),
        Some("enable") => set_enabled(&args[1..], true),
        Some("disable") => set_enabled(&args[1..], false),
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

fn list(args: &[String]) -> std::io::Result<i32> {
    let json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => {
            eprintln!("usage: herdr machine list [--json]");
            return Ok(2);
        }
    };
    let catalog = load_catalog()?;
    let rows = catalog
        .ssh
        .iter()
        .map(|profile| MachineListRow {
            id: profile.id.to_string(),
            label: profile.label.clone(),
            transport: "ssh",
            target: profile.target.clone(),
            session: profile.session.clone(),
            enabled: profile.enabled,
            selected: catalog.selected_endpoint.as_ref()
                == Some(&ClientEndpointId::Ssh(profile.id.clone())),
        })
        .chain(catalog.relay.iter().map(|profile| MachineListRow {
            id: profile.id.to_string(),
            label: profile.label.clone(),
            transport: "relay",
            target: profile.relay_url.clone(),
            session: profile.session.clone(),
            enabled: profile.enabled,
            selected: catalog.selected_endpoint.as_ref()
                == Some(&ClientEndpointId::Relay(profile.id.clone())),
        }))
        .collect::<Vec<_>>();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(std::io::Error::other)?
        );
        return Ok(0);
    }
    if rows.is_empty() {
        println!("No saved machines.");
        return Ok(0);
    }
    for row in rows {
        let state = if row.enabled { "enabled" } else { "disabled" };
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            row.id, row.label, row.transport, row.target, row.session, state
        );
    }

    Ok(0)
}

fn add_relay(args: &[String]) -> std::io::Result<i32> {
    super::relay_setup::run(args)
}

#[derive(Debug, PartialEq, Eq)]
struct AddArgs {
    target: String,
    label: String,
    session: String,
}

fn parse_add_args(args: &[String]) -> Result<AddArgs, String> {
    let args = super::expand_equals_args(args, &["--label", "--remote-session"]);
    let mut target = None;
    let mut label = None;
    let mut session = None;
    let mut index = 0;
    while index < args.len() {
        let (name, value) = match args[index].as_str() {
            "--label" | "--remote-session" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(format!("missing value for {}", args[index]));
                };
                index += 2;
                (args[index - 2].as_str(), value.clone())
            }
            positional if !positional.starts_with('-') && target.is_none() => {
                target = Some(positional.to_owned());
                index += 1;
                continue;
            }
            unknown => {
                return Err(format!("unknown machine add option: {unknown}"));
            }
        };
        match name {
            "--label" if label.is_none() => label = Some(value),
            "--remote-session" if session.is_none() => session = Some(value),
            "--remote-session" => {
                return Err("--remote-session can only be specified once".into());
            }
            "--label" => {
                return Err("--label can only be specified once".into());
            }
            _ => unreachable!("validated machine add option"),
        }
    }
    let target = target.ok_or_else(|| {
        "usage: herdr machine add <ssh-target> --label <label> [--remote-session <name>]".to_owned()
    })?;
    let label = label.ok_or_else(|| "--label is required".to_owned())?;
    let session = session.unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
    Ok(AddArgs {
        target,
        label,
        session,
    })
}

fn add(args: &[String]) -> std::io::Result<i32> {
    let AddArgs {
        target,
        label,
        session,
    } = match parse_add_args(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    let mut catalog = load_catalog()?;
    match catalog.add_ssh(label.clone(), &target, session.clone()) {
        Ok(_) => {}
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    }
    if let Err(error) = crate::remote::prepare_saved_ssh(&target, &session) {
        eprintln!("error: {error}; machine was not saved");
        crate::remote::print_saved_ssh_error_hint(&error, &target);
        return Ok(1);
    }
    // Setup can wait for human approval. Do not overwrite catalog edits made meanwhile.
    let mut catalog = load_catalog().map_err(|error| {
        std::io::Error::other(format!(
            "remote prepared, but machine was not saved: {error}"
        ))
    })?;
    let id = match catalog.add_ssh(label, target, session) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    store_catalog(&catalog).map_err(|error| {
        std::io::Error::other(format!(
            "remote prepared, but machine was not saved: {error}"
        ))
    })?;
    println!("Saved SSH machine {id}. Remote server is ready.");
    println!("Open Herdr clients connect automatically.");
    Ok(0)
}

fn rename(args: &[String]) -> std::io::Result<i32> {
    let args = super::expand_equals_args(args, &["--label"]);
    let [raw_id, flag, label] = args.as_slice() else {
        eprintln!("usage: herdr machine rename <profile-id> --label <label>");
        return Ok(2);
    };
    if flag != "--label" {
        eprintln!("usage: herdr machine rename <profile-id> --label <label>");
        return Ok(2);
    }
    let id = match ProfileId::parse(raw_id.clone()) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    let mut catalog = load_catalog()?;
    let renamed_ssh = catalog
        .rename_ssh(&id, label.clone())
        .map_err(std::io::Error::other)?;
    let renamed_relay = if renamed_ssh {
        false
    } else {
        catalog
            .rename_relay(&id, label)
            .map_err(std::io::Error::other)?
    };
    match renamed_ssh || renamed_relay {
        true => {}
        false => {
            eprintln!("machine profile {id} was not found");
            return Ok(1);
        }
    }
    store_all_catalogs(&catalog)?;
    println!("Renamed machine {id}.");
    Ok(0)
}

fn remove(args: &[String]) -> std::io::Result<i32> {
    let Some(id) = one_profile_id(args, "usage: herdr machine remove <profile-id>")? else {
        return Ok(2);
    };
    let mut catalog = load_catalog()?;
    let previous_selection = catalog.selected_endpoint.clone();
    let removed_ssh = catalog.remove_ssh(&id);
    let removed_relay = if removed_ssh {
        None
    } else {
        catalog.remove_relay(&id)
    };
    if !removed_ssh && removed_relay.is_none() {
        eprintln!("machine profile {id} was not found");
        return Ok(1);
    }
    if let Some(profile) = removed_relay {
        let credential_still_referenced = catalog
            .relay
            .iter()
            .any(|candidate| candidate.credential_id == profile.credential_id);
        let removed_credential = if credential_still_referenced {
            None
        } else {
            crate::relay::store::RelayClientStore::update(|credentials| {
                let removed = credentials
                    .credentials
                    .iter()
                    .find(|credential| credential.id == profile.credential_id)
                    .cloned();
                credentials.remove(&profile.credential_id);
                Ok(removed)
            })
            .map_err(std::io::Error::other)?
        };
        if let Err(error) = store_all_catalogs(&catalog) {
            if let Some(credential) = removed_credential {
                let _ = crate::relay::store::RelayClientStore::update(|credentials| {
                    if credentials.credential(&credential.id).is_none() {
                        credentials.credentials.push(credential);
                    }
                    Ok(())
                });
            }
            return Err(error);
        }
    } else {
        store_all_catalogs(&catalog)?;
    }
    if catalog.selected_endpoint != previous_selection {
        catalog.store_selection().map_err(std::io::Error::other)?;
    }
    println!("Removed machine {id}.");
    Ok(0)
}

fn set_enabled(args: &[String], enabled: bool) -> std::io::Result<i32> {
    let action = if enabled { "enable" } else { "disable" };
    let usage = format!("usage: herdr machine {action} <profile-id>");
    let Some(id) = one_profile_id(args, &usage)? else {
        return Ok(2);
    };
    let mut catalog = load_catalog()?;
    let previous_selection = catalog.selected_endpoint.clone();
    let changed_ssh = catalog.set_enabled(&id, enabled);
    let changed_relay = !changed_ssh && catalog.set_relay_enabled(&id, enabled);
    if !changed_ssh && !changed_relay {
        eprintln!("machine profile {id} was not found");
        return Ok(1);
    }
    store_all_catalogs(&catalog)?;
    if catalog.selected_endpoint != previous_selection {
        catalog.store_selection().map_err(std::io::Error::other)?;
    }
    println!(
        "{} machine {id}.",
        if enabled { "Enabled" } else { "Disabled" }
    );
    Ok(0)
}

fn one_profile_id(args: &[String], usage: &str) -> std::io::Result<Option<ProfileId>> {
    let [raw] = args else {
        eprintln!("{usage}");
        return Ok(None);
    };
    match ProfileId::parse(raw.clone()) {
        Ok(id) => Ok(Some(id)),
        Err(error) => {
            eprintln!("error: {error}");
            Ok(None)
        }
    }
}

fn load_catalog() -> std::io::Result<EndpointCatalog> {
    EndpointCatalog::load().map_err(std::io::Error::other)
}

fn store_catalog(catalog: &EndpointCatalog) -> std::io::Result<()> {
    catalog.store_profiles().map_err(std::io::Error::other)
}

fn store_all_catalogs(catalog: &EndpointCatalog) -> std::io::Result<()> {
    catalog.store_profiles().map_err(std::io::Error::other)?;
    catalog
        .store_relay_profiles()
        .map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_parser_preserves_values_across_argument_orders() {
        for (args, session) in [
            (vec!["--label", "coder", "workstation.coder"], "default"),
            (vec!["workstation.coder", "--label", "coder"], "default"),
            (
                vec![
                    "--remote-session",
                    "agents",
                    "workstation.coder",
                    "--label",
                    "coder",
                ],
                "agents",
            ),
            (
                vec![
                    "--label=coder",
                    "--remote-session=agents",
                    "workstation.coder",
                ],
                "agents",
            ),
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(
                parse_add_args(&args).unwrap(),
                AddArgs {
                    target: "workstation.coder".into(),
                    label: "coder".into(),
                    session: session.into(),
                },
                "{args:?}"
            );
        }
    }

    #[test]
    fn add_parser_rejects_incomplete_duplicate_and_extra_arguments() {
        for args in [
            vec![],
            vec!["--label", "coder"],
            vec!["workstation.coder"],
            vec!["workstation.coder", "--label"],
            vec!["workstation.coder", "--label", "coder", "--remote-session"],
            vec!["--label", "coder", "--label", "other", "workstation.coder"],
            vec![
                "workstation.coder",
                "--label",
                "coder",
                "--remote-session",
                "a",
                "--remote-session",
                "b",
            ],
            vec!["--label", "coder", "workstation.coder", "other-host"],
            vec!["--unknown", "workstation.coder", "--label", "coder"],
            vec!["--label", "--remote-session", "agents", "workstation.coder"],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(parse_add_args(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn profile_id_parser_rejects_target_text() {
        assert!(one_profile_id(&["build.example".into()], "usage")
            .unwrap()
            .is_none());
    }

    #[test]
    fn list_rows_do_not_have_credential_fields() {
        let encoded = serde_json::to_string(&MachineListRow {
            id: "0123456789abcdef0123456789abcdef".into(),
            label: "Build".into(),
            transport: "ssh",
            target: "dev@build".into(),
            session: "agents".into(),
            enabled: true,
            selected: false,
        })
        .unwrap();
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("key"));
        assert!(encoded.contains(r#""target":"dev@build""#));
    }
}
