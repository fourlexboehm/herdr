use clap::{Arg, Command};

use super::{json_flag, option};

pub(super) fn command() -> Command {
    Command::new("relay")
        .about("Manage experimental encrypted relay access")
        .subcommand(
            Command::new("enable")
                .about("Enable outbound relay hosting for this Herdr server")
                .arg(option("url", "WSS_URL").required(true))
                .arg(option("label", "LABEL").required(true))
                .arg(option("session", "NAME")),
        )
        .subcommand(Command::new("disable").about("Disable relay hosting"))
        .subcommand(Command::new("invite").about("Create a one-use 15-minute invitation"))
        .subcommand(
            Command::new("devices")
                .about("List paired controller devices")
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("revoke")
                .about("Revoke a paired controller public key")
                .arg(
                    Arg::new("public-key")
                        .value_name("PUBLIC_KEY")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("status")
                .about("Show relay host configuration")
                .arg(json_flag()),
        )
}
