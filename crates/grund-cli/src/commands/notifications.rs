//! Account notifications, over `grund.notification.v1.NotificationService`.

use clap::{Args, Subcommand};
use serde_json::json;

use crate::{
    commands::{done, dry_run},
    context::{Ctx, Global},
    error::CliResult,
    output::Output,
};

const SERVICE: &str = "grund.notification.v1.NotificationService";
const COLUMNS: &[(&str, &str)] = &[
    ("WHEN", "/createdAt"),
    ("FACT", "/text"),
    ("LINK", "/href"),
    ("READ", "/readAt"),
    ("REPEATS", "/repeatCount"),
    ("ID", "/id"),
];

/// `grund notification` lists notifications, with verbs for counting and reading them.
#[derive(Debug, Args)]
pub struct NotificationsCommand {
    #[command(flatten)]
    pub global: Global,
    #[arg(long, help = "Show unread notifications only")]
    pub unread: bool,
    #[arg(long, value_name = "COUNT", value_parser = clap::value_parser!(i32).range(1..=100), default_value_t = 50, help = "Notifications per page (1 to 100)")]
    pub page_size: i32,
    #[arg(
        long,
        value_name = "TOKEN",
        help = "Continue from a previous page's nextPageToken"
    )]
    pub page_token: Option<String>,
    #[command(subcommand)]
    pub action: Option<NotificationsAction>,
}

/// Actions on the account's notifications.
#[derive(Debug, Subcommand)]
pub enum NotificationsAction {
    #[command(about = "Count unread notifications")]
    Count,
    #[command(about = "Mark one notification, or all notifications, as read")]
    Read {
        #[arg(
            value_name = "ID",
            required_unless_present = "all",
            conflicts_with = "all"
        )]
        id: Option<String>,
        #[arg(long, help = "Mark all notifications as read")]
        all: bool,
        #[arg(long, help = "Show the request instead of sending it")]
        dry_run: bool,
    },
}

/// Runs `grund notification` using only the account's Connect service.
pub async fn run(ctx: &Ctx, command: NotificationsCommand) -> CliResult<Output> {
    let api = ctx.api()?;
    match command.action {
        None => {
            let answer = api
                .call(
                    &format!("{SERVICE}/ListNotifications"),
                    json!({
                        "unreadOnly": command.unread,
                        "pageSize": command.page_size,
                        "pageToken": command.page_token.unwrap_or_default(),
                    }),
                )
                .await?;
            Ok(Output::table(answer, "/notifications", COLUMNS))
        }
        Some(NotificationsAction::Count) => {
            let answer = api
                .call(&format!("{SERVICE}/CountUnread"), json!({}))
                .await?;
            Ok(Output::line(answer, "/count"))
        }
        Some(NotificationsAction::Read {
            id,
            all,
            dry_run: preview,
        }) => {
            let (method, request) = if all {
                ("MarkAllRead", json!({}))
            } else {
                (
                    "MarkRead",
                    json!({"id": id.expect("clap requires ID or --all")}),
                )
            };
            let rpc = format!("{SERVICE}/{method}");
            if preview {
                return Ok(dry_run(&[(rpc, request)], vec![]));
            }
            api.call(&rpc, request).await?;
            Ok(done(if all {
                "All notifications marked as read.".to_string()
            } else {
                "Notification marked as read.".to_string()
            }))
        }
    }
}
