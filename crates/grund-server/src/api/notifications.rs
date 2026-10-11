//! Account-scoped Connect inbox reads and read transitions.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use buffa::MessageField;
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use grund_proto::grund::notification::v1::{
    CountUnreadRequest, CountUnreadResponse, ListNotificationsRequest, ListNotificationsResponse,
    MarkAllReadRequest, MarkAllReadResponse, MarkReadRequest, MarkReadResponse, Notification,
    NotificationService,
};
use grund_store::notifications::{self, NotificationRow};
use uuid::Uuid;

use crate::{api::principal, state::State};

/// The account's notification service.
pub struct NotificationsApi {
    state: State,
}

impl NotificationsApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

fn timestamp<P: buffa::ProtoBox<Timestamp>>(at: DateTime<Utc>) -> MessageField<Timestamp, P> {
    Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32).into()
}

fn notification(row: &NotificationRow) -> Notification {
    Notification {
        id: row.id.to_string(),
        kind: row.kind.clone(),
        text: row.text(),
        href: row.href.clone(),
        created_at: timestamp(row.created_at),
        read_at: row.read_at.map(timestamp).unwrap_or_default(),
        repeat_count: row.repeat_count,
        source_id: row.source_id.to_string(),
        ..Default::default()
    }
}

fn store_error(error: sqlx::Error) -> ConnectError {
    tracing::error!(error = %error, "notification store failed");
    ConnectError::internal("grund could not load notifications")
}

fn parse_cursor(
    value: &str,
    account_id: Uuid,
    organisation_scope: Option<Uuid>,
    unread_only: bool,
) -> Result<Option<(DateTime<Utc>, Uuid)>, ConnectError> {
    if value.is_empty() {
        return Ok(None);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ConnectError::invalid_argument("invalid page token"))?;
    let decoded = std::str::from_utf8(&decoded)
        .map_err(|_| ConnectError::invalid_argument("invalid page token"))?;
    let mut fields = decoded.split('|');
    let (Some("v1"), Some(account), Some(scope), Some(unread), Some(at), Some(id), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(ConnectError::invalid_argument("invalid page token"));
    };
    if account != account_id.to_string()
        || scope != organisation_scope.map_or_else(String::new, |id| id.to_string())
        || unread != if unread_only { "1" } else { "0" }
    {
        return Err(ConnectError::invalid_argument(
            "page token belongs to another audience",
        ));
    }
    let at = DateTime::parse_from_rfc3339(at)
        .map_err(|_| ConnectError::invalid_argument("invalid page token"))?
        .with_timezone(&Utc);
    let id =
        Uuid::parse_str(id).map_err(|_| ConnectError::invalid_argument("invalid page token"))?;
    Ok(Some((at, id)))
}

fn next_cursor(
    row: &NotificationRow,
    account_id: Uuid,
    organisation_scope: Option<Uuid>,
    unread_only: bool,
) -> String {
    URL_SAFE_NO_PAD.encode(format!(
        "v1|{account_id}|{}|{}|{}|{}",
        organisation_scope.map_or_else(String::new, |id| id.to_string()),
        if unread_only { "1" } else { "0" },
        row.created_at
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        row.id,
    ))
}

#[allow(refining_impl_trait)]
impl NotificationService for NotificationsApi {
    async fn list_notifications(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListNotificationsRequest>,
    ) -> ServiceResult<ListNotificationsResponse> {
        let caller = principal(&ctx)?;
        let page_size = match request.page_size {
            0 => 50,
            1..=100 => request.page_size,
            _ => {
                return Err(ConnectError::invalid_argument(
                    "page_size must be between 1 and 100",
                ));
            }
        };
        let cursor = parse_cursor(
            request.page_token,
            caller.account_id,
            caller.organisation_id,
            request.unread_only,
        )?;
        let mut rows = notifications::list(
            &self.state.pool,
            caller.account_id,
            request.unread_only,
            i64::from(page_size) + 1,
            cursor,
            caller.organisation_id,
        )
        .await
        .map_err(store_error)?;
        let has_next = rows.len() > page_size as usize;
        rows.truncate(page_size as usize);
        let next_page_token = if has_next {
            rows.last()
                .map(|row| {
                    next_cursor(
                        row,
                        caller.account_id,
                        caller.organisation_id,
                        request.unread_only,
                    )
                })
                .unwrap_or_default()
        } else {
            String::new()
        };
        Response::ok(ListNotificationsResponse {
            notifications: rows.iter().map(notification).collect(),
            next_page_token,
            ..Default::default()
        })
    }

    async fn count_unread(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, CountUnreadRequest>,
    ) -> ServiceResult<CountUnreadResponse> {
        let caller = principal(&ctx)?;
        let count =
            notifications::count(&self.state.pool, caller.account_id, caller.organisation_id)
                .await
                .map_err(store_error)?;
        Response::ok(CountUnreadResponse {
            count,
            ..Default::default()
        })
    }

    async fn mark_read(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, MarkReadRequest>,
    ) -> ServiceResult<MarkReadResponse> {
        let caller = principal(&ctx)?;
        let id = Uuid::parse_str(request.id)
            .map_err(|_| ConnectError::invalid_argument("id must be a UUID"))?;
        if !notifications::mark_read(
            &self.state.pool,
            caller.account_id,
            id,
            caller.organisation_id,
        )
        .await
        .map_err(store_error)?
        {
            return Err(ConnectError::not_found("no such notification"));
        }
        Response::ok(MarkReadResponse::default())
    }

    async fn mark_all_read(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, MarkAllReadRequest>,
    ) -> ServiceResult<MarkAllReadResponse> {
        let caller = principal(&ctx)?;
        notifications::mark_all(&self.state.pool, caller.account_id, caller.organisation_id)
            .await
            .map_err(store_error)?;
        Response::ok(MarkAllReadResponse::default())
    }
}
