//! `grund bundle`: one release's files in one file, for a computer that
//! fetches nothing (grund-docs design/cli-redesign.md §10). `--from-bundle`
//! on `grund update`, `join` and `server install|update` reads it.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use serde_json::json;

use crate::{
    commands::{
        Noun,
        system::{AGENT_INSTALLER, release},
    },
    context::Ctx,
    error::{CliError, CliResult, Code},
    output::Output,
};

/// `grund bundle`.
pub type BundleCommand = Noun<BundleAction>;

/// What `grund bundle` does.
#[derive(Debug, Subcommand)]
pub enum BundleAction {
    #[command(
        about = "Write one release's grund files, and the archives a machine install fetches, into one file"
    )]
    Create {
        #[arg(
            long,
            help = "Exact public release tag; default: the newest in the channel"
        )]
        version: Option<String>,
        #[arg(
            long,
            value_enum,
            conflicts_with = "version",
            help = "Release channel; defaults to this CLI's"
        )]
        channel: Option<release::Channel>,
        #[arg(
            long,
            value_enum,
            help = "The machines' architecture; default: this computer's"
        )]
        arch: Option<Arch>,
        #[arg(
            short,
            long,
            value_name = "FILE",
            help = "Where to write it; default: grund-<version>-<arch>.tar"
        )]
        output: Option<PathBuf>,
    },
}

/// A machine architecture grund publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Arch {
    Amd64,
    Arm64,
}

impl Arch {
    fn name(self) -> &'static str {
        match self {
            Arch::Amd64 => "amd64",
            Arch::Arm64 => "arm64",
        }
    }

    fn host() -> CliResult<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Ok(Arch::Amd64),
            "aarch64" => Ok(Arch::Arm64),
            other => {
                Err(CliError::usage(format!("grund publishes no {other} build")).field("arch"))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Pinned {
    name: String,
    url: String,
    sha256: String,
}

fn constant<'a>(script: &'a str, name: &str) -> Vec<&'a str> {
    script
        .lines()
        .filter_map(|line| line.trim().strip_prefix(&format!("{name}=")))
        .map(|value| value.trim().trim_matches('"'))
        .collect()
}

fn pinned(script: &str, arch: Arch) -> CliResult<Vec<Pinned>> {
    let missing = |what: &str| {
        CliError::new(
            Code::Failed,
            format!("the embedded agent installer pins no {what}"),
        )
    };
    let restic = *constant(script, "RESTIC_VERSION")
        .first()
        .ok_or_else(|| missing("restic version"))?;
    let restic_sums = constant(script, "RESTIC_BZ2_SHA256");
    let restic_sum = match arch {
        Arch::Amd64 => restic_sums.first(),
        Arch::Arm64 => restic_sums.get(1),
    }
    .ok_or_else(|| missing("restic checksum for this architecture"))?;
    let mut archives = vec![Pinned {
        name: format!("restic_{restic}_linux_{}.bz2", arch.name()),
        url: format!(
            "https://github.com/restic/restic/releases/download/v{restic}/restic_{restic}_linux_{}.bz2",
            arch.name()
        ),
        sha256: restic_sum.to_string(),
    }];
    if arch == Arch::Amd64 {
        let firecracker = *constant(script, "FIRECRACKER_VERSION")
            .first()
            .ok_or_else(|| missing("Firecracker version"))?;
        let sum = *constant(script, "FIRECRACKER_TGZ_SHA256")
            .first()
            .ok_or_else(|| missing("Firecracker checksum"))?;
        archives.push(Pinned {
            name: format!("firecracker-{firecracker}-x86_64.tgz"),
            url: format!(
                "https://github.com/firecracker-microvm/firecracker/releases/download/{firecracker}/firecracker-{firecracker}-x86_64.tgz"
            ),
            sha256: sum.to_string(),
        });
    }
    Ok(archives)
}

/// Runs `grund bundle create`.
pub async fn run(_ctx: &Ctx, action: BundleAction) -> CliResult<Output> {
    let BundleAction::Create {
        version,
        channel,
        arch,
        output,
    } = action;
    let arch = match arch {
        Some(arch) => arch,
        None => Arch::host()?,
    };
    let release = release::Release::resolve(version.as_deref(), channel, crate::VERSION).await?;
    let output = output
        .unwrap_or_else(|| PathBuf::from(format!("grund-{}-{}.tar", release.tag, arch.name())));
    let staging = tempfile::Builder::new()
        .prefix("grund-bundle-")
        .tempdir()
        .map_err(|e| CliError::new(Code::Failed, format!("could not stage the bundle: {e}")))?;
    let binary = format!("grund-linux-{}", arch.name());
    let client = format!("grund-cli-linux-{}", arch.name());
    let mut names = Vec::new();
    for name in [
        binary.as_str(),
        client.as_str(),
        "compose.yaml",
        "image-digest.txt",
        "release.txt",
        "agent-install.sh",
    ] {
        if release.checksums().contains_key(name) {
            release.download(name, &staging.path().join(name)).await?;
            names.push(name.to_string());
        }
    }
    if !names.contains(&binary) {
        return Err(
            CliError::new(Code::NotFound, format!("{} has no {binary}", release.tag)).field("arch"),
        );
    }
    let sums: String = names
        .iter()
        .map(|name| format!("{}  {name}\n", release.checksums()[name]))
        .collect();
    std::fs::write(staging.path().join("SHA256SUMS"), sums)?;
    std::fs::write(
        staging.path().join(release::BUNDLE_TAG),
        format!("{}\n", release.tag),
    )?;
    for archive in pinned(AGENT_INSTALLER, arch)? {
        release::fetch_pinned(
            &archive.url,
            &archive.sha256,
            &staging.path().join(&archive.name),
        )
        .await?;
        names.push(archive.name);
    }
    let status = std::process::Command::new("tar")
        .arg("-cf")
        .arg(&output)
        .arg("-C")
        .arg(staging.path())
        .arg(".")
        .stdin(std::process::Stdio::null())
        .status()
        .map_err(|e| CliError::new(Code::Failed, format!("could not run tar: {e}")))?;
    if !status.success() {
        return Err(CliError::new(
            Code::Failed,
            format!("tar could not write {}", output.display()),
        ));
    }
    Ok(Output::fields(json!({
        "path": output.display().to_string(),
        "version": release.tag,
        "arch": arch.name(),
        "files": names,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundle_pins_what_the_embedded_installer_pins_for_each_architecture() {
        let amd64 = pinned(AGENT_INSTALLER, Arch::Amd64).unwrap();
        let arm64 = pinned(AGENT_INSTALLER, Arch::Arm64).unwrap();
        assert_eq!(amd64.len(), 2);
        assert_eq!(arm64.len(), 1);
        assert!(amd64[0].name.ends_with("_linux_amd64.bz2"));
        assert!(arm64[0].name.ends_with("_linux_arm64.bz2"));
        assert_ne!(amd64[0].sha256, arm64[0].sha256);
        assert!(amd64[1].name.starts_with("firecracker-v"));
        for archive in amd64.iter().chain(&arm64) {
            assert_eq!(archive.sha256.len(), 64);
            assert!(AGENT_INSTALLER.contains(&archive.sha256));
            assert!(archive.url.ends_with(&archive.name));
        }
    }
}
