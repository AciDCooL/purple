#![cfg_attr(test, allow(clippy::too_many_lines))]

use anyhow::Result;
use clap::Parser;

use purple_ssh::askpass;
use purple_ssh::cli_args::Cli;
use purple_ssh::runtime::launcher;

fn main() -> Result<()> {
    // Askpass mode: when invoked as SSH_ASKPASS, handle the request and exit.
    // Must run before theme init and CLI parse to avoid terminal interference.
    if std::env::var("PURPLE_ASKPASS_MODE").is_ok() {
        return askpass::handle();
    }
    let cli = Cli::parse();
    launcher::run(cli)
}
