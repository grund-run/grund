//! `grund up`: runs a project's grund.yaml or compose.yaml on this computer
//! with the separate grund-up runtime. grund links no container code for it:
//! it replaces itself with `grund-up up` and the arguments given (`GRUND_UP`
//! names another binary), and that process speaks for itself.

use std::{ffi::OsString, os::unix::process::CommandExt};

use clap::Args;

use crate::{
    context::{Ctx, Global},
    error::{CliError, Code},
    output::Format,
};

#[derive(Debug, Args)]
pub struct UpArgs {
    #[command(flatten)]
    pub global: Global,
    /// Passed to grund-up up as they are; grund-up up --help lists them.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "ARGS"
    )]
    pub args: Vec<OsString>,
}

/// Replaces this process with grund-up; returns only why it could not.
pub fn exec(ctx: &Ctx, args: UpArgs) -> CliError {
    let program = std::env::var_os("GRUND_UP").unwrap_or_else(|| "grund-up".into());
    let mut command = std::process::Command::new(&program);
    if ctx.format == Format::Json {
        command.arg("--json");
    }
    command.arg("up").args(&args.args);
    let error = command.exec();
    if error.kind() == std::io::ErrorKind::NotFound {
        CliError::new(
            Code::Unavailable,
            "grund up runs projects with the grund-up runtime, which is not installed here; put grund-up on PATH or name it with GRUND_UP",
        )
    } else {
        CliError::from(error)
    }
}
