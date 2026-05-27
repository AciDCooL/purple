#![cfg_attr(test, allow(clippy::too_many_lines))]

use anyhow::Result;
use clap::Parser;

use purple_ssh::askpass;
use purple_ssh::cli_args::Cli;
use purple_ssh::runtime::env::Env;
use purple_ssh::runtime::launcher;

fn main() -> Result<()> {
    // Single process edge: capture the environment snapshot once and thread
    // it down. Every other module reads env/paths from this `Env`, never from
    // ambient `std::env` / `dirs::home_dir`.
    let env = std::sync::Arc::new(Env::from_process());
    // Askpass mode: when invoked as SSH_ASKPASS, handle the request and exit.
    // Must run before theme init and CLI parse to avoid terminal interference.
    if env.var("PURPLE_ASKPASS_MODE").is_some() {
        return askpass::handle(&env);
    }
    let cli = Cli::parse();
    launcher::run(cli, env)
}
