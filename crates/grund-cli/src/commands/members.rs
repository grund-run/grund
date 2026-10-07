//! `grund members` and `grund invitations`: who is in the organisation,
//! over `grund.organisation.v1.OrganisationService`. A member is named by
//! username, email or account id; an invitation by email or id.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::{
    api::Api,
    commands::{Noun, done, dry_run},
    context::Ctx,
    error::{CliError, CliResult, Code},
    output::Output,
};

const SERVICE: &str = "grund.organisation.v1.OrganisationService";

/// `grund members`.
pub type MembersCommand = Noun<MembersAction>;

/// `grund invitations`.
pub type InvitationsCommand = Noun<InvitationsAction>;

/// What `grund members` does.
#[derive(Debug, Subcommand)]
pub enum MembersAction {
    #[command(about = "The organisation's members and their roles")]
    List,
    #[command(about = "Invite someone by email. Owners and admins")]
    Invite {
        #[arg(value_name = "EMAIL")]
        email: String,
        #[arg(long, value_parser = ["member", "admin"], default_value = "member")]
        role: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(about = "Change a member's role. Owners")]
    Role {
        #[arg(value_name = "MEMBER", help = "Username, email or account id")]
        member: String,
        #[arg(value_name = "ROLE", value_parser = ["member", "admin", "owner"])]
        role: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(about = "Remove a member from the organisation")]
    Remove {
        #[arg(value_name = "MEMBER", help = "Username, email or account id")]
        member: String,
        #[arg(long, help = "Do not ask; needed when nobody can be asked")]
        yes: bool,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
}

/// What `grund invitations` does.
#[derive(Debug, Subcommand)]
pub enum InvitationsAction {
    #[command(about = "Invitations not accepted yet")]
    List,
    #[command(about = "Revoke an invitation; its link stops working")]
    Revoke {
        #[arg(value_name = "INVITATION", help = "The email it went to, or its id")]
        invitation: String,
        #[arg(long, help = "Do not ask; needed when nobody can be asked")]
        yes: bool,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
}

const MEMBERS: &[(&str, &str)] = &[
    ("USERNAME", "/username"),
    ("EMAIL", "/email"),
    ("ROLE", "/role"),
    ("JOINED", "/joinedAt"),
];

const INVITATIONS: &[(&str, &str)] = &[
    ("EMAIL", "/email"),
    ("ROLE", "/role"),
    ("BY", "/invitedBy"),
    ("EXPIRES", "/expiresAt"),
    ("ID", "/invitationId"),
];

fn role(text: &str) -> &'static str {
    match text {
        "owner" => "ROLE_OWNER",
        "admin" => "ROLE_ADMIN",
        _ => "ROLE_MEMBER",
    }
}

async fn member(api: &Api, org: &str, who: &str) -> CliResult<Value> {
    let answer = api
        .call(&format!("{SERVICE}/ListMembers"), json!({"slug": org}))
        .await?;
    answer["members"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|m| {
            m["username"] == json!(who) || m["email"] == json!(who) || m["accountId"] == json!(who)
        })
        .cloned()
        .ok_or_else(|| {
            CliError::new(Code::NotFound, format!("no member {who} in {org}"))
                .hint("grund members list")
        })
}

/// Runs a `grund members` verb.
pub async fn run_members(ctx: &Ctx, action: MembersAction) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    match action {
        MembersAction::List => {
            let answer = api
                .call(&format!("{SERVICE}/ListMembers"), json!({"slug": org}))
                .await?;
            Ok(Output::table(answer, "/members", MEMBERS))
        }
        MembersAction::Invite {
            email,
            role: r,
            dry_run: preview,
        } => {
            let request = json!({"slug": org, "email": email, "role": role(&r)});
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/InviteMember"), request)],
                    vec![],
                ));
            }
            api.call(&format!("{SERVICE}/InviteMember"), request)
                .await?;
            Ok(done(format!("Invited {email} to {org} as {r}.")))
        }
        MembersAction::Role {
            member: who,
            role: r,
            dry_run: preview,
        } => {
            let found = member(&api, &org, &who).await?;
            let request = json!({"slug": org, "accountId": found["accountId"], "role": role(&r)});
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/ChangeMemberRole"), request)],
                    vec![],
                ));
            }
            api.call(&format!("{SERVICE}/ChangeMemberRole"), request)
                .await?;
            Ok(done(format!("{who} is now {r} in {org}.")))
        }
        MembersAction::Remove {
            member: who,
            yes,
            dry_run: preview,
        } => {
            let found = member(&api, &org, &who).await?;
            let request = json!({"slug": org, "accountId": found["accountId"]});
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/RemoveMember"), request)],
                    vec![],
                ));
            }
            ctx.confirm(yes, &format!("Remove {who} from {org}"))?;
            api.call(&format!("{SERVICE}/RemoveMember"), request)
                .await?;
            Ok(done(format!("Removed {who} from {org}.")))
        }
    }
}

/// Runs a `grund invitations` verb.
pub async fn run_invitations(ctx: &Ctx, action: InvitationsAction) -> CliResult<Output> {
    let api = ctx.api()?;
    let org = ctx.org(&api).await?;
    let list = api
        .call(&format!("{SERVICE}/ListInvitations"), json!({"slug": org}))
        .await?;
    match action {
        InvitationsAction::List => Ok(Output::table(list, "/invitations", INVITATIONS)),
        InvitationsAction::Revoke {
            invitation,
            yes,
            dry_run: preview,
        } => {
            let found = list["invitations"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|i| i["email"] == json!(invitation) || i["invitationId"] == json!(invitation))
                .cloned()
                .ok_or_else(|| {
                    CliError::new(
                        Code::NotFound,
                        format!("no invitation {invitation} in {org}"),
                    )
                    .hint("grund invitations list")
                })?;
            let request = json!({"slug": org, "invitationId": found["invitationId"]});
            if preview {
                return Ok(dry_run(
                    &[(format!("{SERVICE}/RevokeInvitation"), request)],
                    vec![],
                ));
            }
            ctx.confirm(
                yes,
                &format!(
                    "Revoke the invitation to {}",
                    found["email"].as_str().unwrap_or_default()
                ),
            )?;
            api.call(&format!("{SERVICE}/RevokeInvitation"), request)
                .await?;
            Ok(done(format!("Revoked the invitation to {invitation}.")))
        }
    }
}
