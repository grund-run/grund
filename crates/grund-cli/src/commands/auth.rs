//! `grund login`, `grund logout`, `grund whoami` (grund-docs design/cli.md
//! §2).

use std::{io::IsTerminal, time::Duration};

use serde_json::{Value, json};

use crate::{
    api::Api,
    context::{Ctx, Global, Source, set_if},
    credentials::{self, Instance},
    error::{CliError, CliResult, Code},
    output::{self, Format, Output},
};

/// `grund login`.
#[derive(Debug, clap::Args)]
pub struct LoginArgs {
    #[command(flatten)]
    pub global: Global,

    #[arg(
        id = "address",
        value_name = "INSTANCE",
        help = "The instance, such as grund.example.com. Default: --instance, GRUND_INSTANCE, or the current one"
    )]
    pub instance: Option<String>,

    #[arg(
        long,
        help = "Read a personal access token (grund_pat_…) from stdin instead of signing in in the browser"
    )]
    pub with_token: bool,

    #[arg(long, help = "Do not try to open the browser; print the address only")]
    pub no_browser: bool,
}

/// `grund logout`.
#[derive(Debug, clap::Args)]
pub struct LogoutArgs {
    #[command(flatten)]
    pub global: Global,
}

/// `grund whoami`.
#[derive(Debug, clap::Args)]
pub struct WhoamiArgs {
    #[command(flatten)]
    pub global: Global,
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn open_browser(url: &str) {
    for opener in ["xdg-open", "open"] {
        if std::process::Command::new(opener)
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
        {
            return;
        }
    }
}

fn announce(ctx: &Ctx, started: &Value) {
    let uri = started["verificationUriComplete"]
        .as_str()
        .unwrap_or_default();
    let code = started["userCode"].as_str().unwrap_or_default();
    let shown = if code.len() == 8 {
        format!("{}-{}", &code[..4], &code[4..])
    } else {
        code.to_string()
    };
    let line = match ctx.format {
        Format::Text => {
            format!("Open {uri}\nand check that it shows the code {shown}. Waiting for approval…")
        }
        Format::Json | Format::Yaml => json!({
            "event": "approve_in_browser",
            "verificationUri": started["verificationUri"],
            "verificationUriComplete": uri,
            "userCode": shown,
            "expiresInSeconds": started["expiresInSeconds"],
        })
        .to_string(),
    };
    eprintln!("{line}");
}

async fn device_login(
    ctx: &Ctx,
    api: &Api,
    args: &LoginArgs,
    revision: &str,
) -> CliResult<(String, String)> {
    let started = api
        .call(
            "grund.login.v1.DeviceLoginService/StartDeviceLogin",
            json!({"client": crate::client_name(revision), "host": hostname()}),
        )
        .await?;
    let device_code = started["deviceCode"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    announce(ctx, &started);
    if !args.no_browser
        && ctx.format == Format::Text
        && std::io::stderr().is_terminal()
        && let Some(uri) = started["verificationUriComplete"].as_str()
    {
        open_browser(uri);
    }
    let mut interval = started["intervalSeconds"].as_u64().unwrap_or(5).max(1);
    let deadline = std::time::Instant::now()
        + Duration::from_secs(started["expiresInSeconds"].as_u64().unwrap_or(600));
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        if std::time::Instant::now() > deadline {
            return Err(CliError::new(
                Code::Unauthenticated,
                "the login expired before it was approved",
            )
            .hint("run grund login again"));
        }
        let polled = match api
            .call(
                "grund.login.v1.DeviceLoginService/PollDeviceLogin",
                json!({"deviceCode": device_code}),
            )
            .await
        {
            Ok(polled) => polled,
            Err(error) if error.reason == "slow_down" => {
                interval += 5;
                continue;
            }
            Err(error) if error.code == Code::Unavailable => continue,
            Err(error) => return Err(error),
        };
        match polled["state"].as_str().unwrap_or_default() {
            "DEVICE_LOGIN_STATE_APPROVED" => {
                let token = polled["sessionToken"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let username = polled["username"].as_str().unwrap_or_default().to_string();
                return Ok((token, username));
            }
            "DEVICE_LOGIN_STATE_DENIED" => {
                return Err(CliError::new(
                    Code::Unauthenticated,
                    "the login was denied in the browser",
                ));
            }
            "DEVICE_LOGIN_STATE_EXPIRED" => {
                return Err(CliError::new(
                    Code::Unauthenticated,
                    "the login expired or was already used",
                )
                .hint("run grund login again"));
            }
            _ => output::progress(ctx.format, "…"),
        }
    }
}

/// Signs in and writes the credential to the credentials file.
pub async fn login(ctx: &Ctx, args: LoginArgs, revision: &str) -> CliResult<Output> {
    let instance = match args.instance.as_deref().or(ctx.global.instance.as_deref()) {
        Some(text) => credentials::origin(text)?,
        None => ctx.instance().map_err(|_| {
            CliError::usage("name the instance: grund login grund.example.com").field("instance")
        })?,
    };
    let path = ctx.credentials_path()?;
    let mut file = ctx.credentials()?;
    let (credential, username, kind) = if args.with_token {
        let token = ctx.read_stdin("Token")?.trim().to_string();
        if !token.starts_with("grund_pat_") {
            return Err(CliError::usage("stdin holds no grund_pat_ token").field("with-token"));
        }
        let api = Api::new(&instance, Some(token.clone()))?;
        let current = api
            .call("grund.token.v1.TokenService/GetCurrentToken", json!({}))
            .await?;
        let organisation = current["organisation"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        file.put(Instance {
            url: instance.clone(),
            credential: token.clone(),
            username: current["token"]["createdBy"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            organisation,
        });
        (
            token,
            current["token"]["createdBy"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            "token",
        )
    } else {
        let anonymous = Api::new(&instance, None)?;
        let (token, username) = device_login(ctx, &anonymous, &args, revision).await?;
        let keep = file
            .instance(&instance)
            .map(|i| i.organisation.clone())
            .unwrap_or_default();
        file.put(Instance {
            url: instance.clone(),
            credential: token.clone(),
            username: username.clone(),
            organisation: keep,
        });
        (token, username, "session")
    };
    let mut organisation = file
        .instance(&instance)
        .map(|i| i.organisation.clone())
        .unwrap_or_default();
    if organisation.is_empty() && kind == "session" {
        let api = Api::new(&instance, Some(credential))?;
        let viewer = api
            .call("grund.account.v1.AccountService/GetViewer", json!({}))
            .await?;
        if let Some([only]) = viewer["viewer"]["memberships"]
            .as_array()
            .map(Vec::as_slice)
        {
            organisation = only["organisationSlug"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            if let Some(entry) = file.instances.iter_mut().find(|i| i.url == instance) {
                entry.organisation = organisation.clone();
            }
        }
    }
    file.save(&path)?;
    let mut result = json!({
        "instance": instance,
        "credential": kind,
        "credentialsFile": path.display().to_string(),
    });
    set_if(&mut result, "username", username);
    set_if(&mut result, "organisation", organisation);
    Ok(Output::fields(result))
}

/// Ends the CLI session at the instance (a token stays live: revoke it
/// with `grund tokens revoke`) and forgets the credential.
pub async fn logout(ctx: &Ctx, _args: LogoutArgs) -> CliResult<Output> {
    let instance = ctx.instance()?;
    let credential = ctx.credential(&instance)?;
    if credential.source == Source::Environment {
        return Err(
            CliError::usage("the credential comes from GRUND_TOKEN; unset it instead")
                .field("GRUND_TOKEN"),
        );
    }
    let mut revoked = false;
    if credential.kind() == "session" {
        let api = Api::new(&instance, Some(credential.secret.clone()))?;
        match api
            .call("grund.account.v1.AccountService/ListSessions", json!({}))
            .await
        {
            Ok(sessions) => {
                if let Some(id) = sessions["sessions"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|s| s["current"].as_bool() == Some(true))
                    .and_then(|s| s["sessionId"].as_str())
                {
                    api.call(
                        "grund.account.v1.AccountService/RevokeSession",
                        json!({"sessionId": id}),
                    )
                    .await?;
                    revoked = true;
                }
            }
            Err(error) if error.code == Code::Unauthenticated => {}
            Err(error) => return Err(error),
        }
    }
    let path = ctx.credentials_path()?;
    let mut file = ctx.credentials()?;
    file.remove(&instance);
    file.save(&path)?;
    let message = if revoked {
        format!("Signed out of {instance}: the session is revoked and forgotten.")
    } else if credential.kind() == "token" {
        format!("Forgot the token for {instance}. It stays live until it expires or is revoked.")
    } else {
        format!("Forgot the credential for {instance}.")
    };
    Ok(Output::line(json!({"message": message}), "/message"))
}

/// Who the credential is.
pub async fn whoami(ctx: &Ctx, _args: WhoamiArgs) -> CliResult<Output> {
    let instance = ctx.instance()?;
    let credential = ctx.credential(&instance)?;
    let api = Api::new(&instance, Some(credential.secret.clone()))?;
    let mut result = json!({
        "instance": instance,
        "credential": credential.kind(),
        "credentialSource": match credential.source {
            Source::Environment => "GRUND_TOKEN",
            Source::File => "credentials file",
        },
    });
    if credential.kind() == "token" {
        let current = api
            .call("grund.token.v1.TokenService/GetCurrentToken", json!({}))
            .await?;
        result["token"] = current["token"].clone();
        set_if(
            &mut result,
            "username",
            current["token"]["createdBy"].clone(),
        );
    } else {
        let viewer = api
            .call("grund.account.v1.AccountService/GetViewer", json!({}))
            .await?;
        set_if(
            &mut result,
            "username",
            viewer["viewer"]["username"].clone(),
        );
        set_if(&mut result, "email", viewer["viewer"]["email"].clone());
        let organisations = api
            .call(
                "grund.organisation.v1.OrganisationService/ListOrganisations",
                json!({}),
            )
            .await?;
        set_if(
            &mut result,
            "organisations",
            organisations["organisations"].clone(),
        );
    }
    match ctx.org(&api).await {
        Ok(org) => set_if(&mut result, "organisation", org),
        Err(error) if error.code == Code::OrganisationRequired => {}
        Err(error) => return Err(error),
    }
    Ok(Output::fields(result))
}
