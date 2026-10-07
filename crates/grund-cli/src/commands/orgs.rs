//! `grund orgs`: the organisations the account is in, and the default one.

use clap::Subcommand;
use serde_json::json;

use crate::{
    commands::Noun,
    context::Ctx,
    error::{CliError, CliResult, Code},
    output::Output,
};

/// `grund orgs`.
pub type OrgsCommand = Noun<OrgsAction>;

/// What `grund orgs` does.
#[derive(Debug, Subcommand)]
pub enum OrgsAction {
    #[command(about = "The account's organisations, and which is the default")]
    List,
    #[command(about = "One organisation: its slug, when it was made, a pending deletion")]
    Get {
        #[arg(value_name = "SLUG", help = "Default: the default organisation")]
        slug: Option<String>,
    },
    #[command(
        about = "Make SLUG the default organisation on this instance (kept in the credentials file)"
    )]
    Use {
        #[arg(value_name = "SLUG")]
        slug: String,
    },
    #[command(about = "Make an organisation; you become its owner")]
    Create {
        #[arg(value_name = "SLUG", help = "[a-z0-9-], 3 to 32 characters")]
        slug: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(about = "Rename an organisation. Owners only")]
    Rename {
        #[arg(value_name = "SLUG")]
        slug: String,
        #[arg(value_name = "NEW_SLUG")]
        new_slug: String,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
    #[command(about = "Ask to delete an organisation. Owners only; billing may refuse it")]
    Delete {
        #[arg(value_name = "SLUG")]
        slug: String,
        #[arg(long, help = "Do not ask; needed when nobody can be asked")]
        yes: bool,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
}

const ORGS: &[(&str, &str)] = &[
    ("SLUG", "/slug"),
    ("CREATED", "/createdAt"),
    ("DELETION", "/deletionRequestedAt"),
];

/// Runs a `grund orgs` verb.
pub async fn run(ctx: &Ctx, action: OrgsAction) -> CliResult<Output> {
    let api = ctx.api()?;
    let service = "grund.organisation.v1.OrganisationService";
    match action {
        OrgsAction::List => {
            let mut answer = api
                .call(&format!("{service}/ListOrganisations"), json!({}))
                .await?;
            if let Ok(current) = ctx.org(&api).await {
                answer["current"] = json!(current);
            }
            Ok(Output::table(answer, "/organisations", ORGS))
        }
        OrgsAction::Get { slug } => {
            let slug = match slug {
                Some(slug) => slug,
                None => ctx.org(&api).await?,
            };
            let answer = api
                .call(&format!("{service}/GetOrganisation"), json!({"slug": slug}))
                .await?;
            Ok(Output::fields(answer))
        }
        OrgsAction::Use { slug } => {
            let slug = slug.trim().to_ascii_lowercase();
            api.call(&format!("{service}/GetOrganisation"), json!({"slug": slug}))
                .await?;
            let instance = api.origin().to_string();
            let path = ctx.credentials_path()?;
            let mut file = ctx.credentials()?;
            let Some(entry) = file.instances.iter_mut().find(|i| i.url == instance) else {
                return Err(CliError::new(
                    Code::NotSignedIn,
                    format!("{instance} is not in the credentials file"),
                )
                .hint("with GRUND_TOKEN, pass --org or set GRUND_ORG instead"));
            };
            entry.organisation = slug.clone();
            file.save(&path)?;
            Ok(Output::line(
                json!({"message": format!("{slug} is the default organisation on {instance}.")}),
                "/message",
            ))
        }
        OrgsAction::Create { slug, dry_run } => {
            let request = json!({"slug": slug});
            if dry_run {
                return Ok(super::dry_run(
                    &[(format!("{service}/CreateOrganisation"), request)],
                    vec![],
                ));
            }
            let answer = api
                .call(&format!("{service}/CreateOrganisation"), request)
                .await?;
            Ok(Output::fields(answer))
        }
        OrgsAction::Rename {
            slug,
            new_slug,
            dry_run,
        } => {
            let request = json!({"slug": slug, "newSlug": new_slug});
            if dry_run {
                return Ok(super::dry_run(
                    &[(format!("{service}/RenameOrganisation"), request)],
                    vec![],
                ));
            }
            let answer = api
                .call(&format!("{service}/RenameOrganisation"), request)
                .await?;
            Ok(Output::fields(answer))
        }
        OrgsAction::Delete { slug, yes, dry_run } => {
            let request = json!({"slug": slug, "confirmSlug": slug});
            if dry_run {
                return Ok(super::dry_run(
                    &[(format!("{service}/DeleteOrganisation"), request)],
                    vec![],
                ));
            }
            ctx.confirm(
                yes,
                &format!("Delete the organisation {slug} and everything in it"),
            )?;
            api.call(&format!("{service}/DeleteOrganisation"), request)
                .await?;
            Ok(super::done(format!("Asked to delete {slug}.")))
        }
    }
}
