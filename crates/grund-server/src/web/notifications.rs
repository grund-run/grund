use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::{StatusCode, Uri},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    state::State,
    web::{
        browser::Browser,
        pages::{PageResult, forged, message, redirect, require_session, signed_in_typed},
        time,
    },
};

const PAGE_SIZE: usize = 50;

pub struct NotificationView {
    pub id: String,
    pub text: String,
    pub href: String,
    pub when: String,
    pub unread: bool,
    pub repeats: i32,
}

pub struct NotificationsPage<'a> {
    pub csrf: &'a str,
    pub viewer: &'a super::pages::TypedViewer,
    pub items: &'a [NotificationView],
    pub unread_only: bool,
    pub next: &'a str,
}

#[derive(Default, Deserialize)]
pub struct ListQuery {
    unread: Option<String>,
    cursor: Option<String>,
}

fn encode_cursor(at: DateTime<Utc>, id: Uuid, account: Uuid, unread: bool) -> String {
    let mut bytes = [0u8; 41];
    bytes[..8].copy_from_slice(&at.timestamp_micros().to_be_bytes());
    bytes[8..24].copy_from_slice(id.as_bytes());
    bytes[24..40].copy_from_slice(account.as_bytes());
    bytes[40] = u8::from(unread);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_cursor(token: &str, account: Uuid, unread: bool) -> Option<(DateTime<Utc>, Uuid)> {
    let mut bytes = [0u8; 42];
    if URL_SAFE_NO_PAD.decode_slice(token, &mut bytes).ok()? != 41
        || bytes[24..40] != account.as_bytes()[..]
        || bytes[40] != u8::from(unread)
    {
        return None;
    }
    let micros = i64::from_be_bytes(bytes[..8].try_into().ok()?);
    Some((
        DateTime::from_timestamp_micros(micros)?,
        Uuid::from_bytes(bytes[8..24].try_into().ok()?),
    ))
}

/// `GET /notifications`: account-owned, keyset-paged facts.
pub async fn page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Query(query): Query<ListQuery>,
) -> PageResult {
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(response) => return Ok(*response),
    };
    let unread_only = matches!(query.unread.as_deref(), Some("1" | "true"));
    let cursor = match query.cursor.as_deref() {
        None => None,
        Some(token) => match decode_cursor(token, session.account_id, unread_only) {
            Some(cursor) => Some(cursor),
            None => {
                return message(
                    &state,
                    &browser,
                    StatusCode::BAD_REQUEST,
                    "Invalid page",
                    "That page link is invalid.",
                    Some(("/notifications", "Notifications")),
                );
            }
        },
    };
    let mut records = grund_store::notifications::list(
        &state.pool,
        session.account_id,
        unread_only,
        (PAGE_SIZE + 1) as i64,
        cursor,
        None,
    )
    .await?;
    let next = if records.len() > PAGE_SIZE {
        records.truncate(PAGE_SIZE);
        let last = records.last().expect("page contains 50 rows");
        let cursor = encode_cursor(last.created_at, last.id, session.account_id, unread_only);
        if unread_only {
            format!("/notifications?unread=1&cursor={cursor}")
        } else {
            format!("/notifications?cursor={cursor}")
        }
    } else {
        String::new()
    };
    let now = Utc::now();
    let items = records
        .into_iter()
        .map(|row| NotificationView {
            id: row.id.to_string(),
            text: row.text(),
            href: row.href,
            when: time::ago(row.created_at, now),
            unread: row.read_at.is_none(),
            repeats: row.repeat_count,
        })
        .collect::<Vec<_>>();
    signed_in_typed(
        &state,
        &browser,
        &session,
        None,
        StatusCode::OK,
        "Notifications",
        "notifications",
        None,
        None,
        Some(false),
        |viewer, csrf| {
            crate::templates::compiled::pages::notifications::render(&NotificationsPage {
                csrf,
                viewer,
                items: &items,
                unread_only,
                next: &next,
            })
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct ReadForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /notifications/{id}/read`: only the signed-in recipient can mark a row.
pub async fn mark_read(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(id): Path<Uuid>,
    Form(form): Form<ReadForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(response) => return Ok(*response),
    };
    if !grund_store::notifications::mark_read(&state.pool, session.account_id, id, None).await? {
        return super::pages::not_found_page(&state, &browser);
    }
    Ok(redirect("/notifications"))
}

/// `POST /notifications/read-all`: mark only the signed-in recipient's rows.
pub async fn mark_all(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Form(form): Form<ReadForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(response) => return Ok(*response),
    };
    grund_store::notifications::mark_all(&state.pool, session.account_id, None).await?;
    Ok(redirect("/notifications"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_cursor_cannot_be_reused_for_another_account_or_unread_filter() {
        let account = Uuid::now_v7();
        let id = Uuid::now_v7();
        let at = DateTime::<Utc>::from_timestamp_micros(1_760_000_000_123_456).unwrap();
        let cursor = encode_cursor(at, id, account, true);
        assert_eq!(decode_cursor(&cursor, account, true), Some((at, id)));
        assert_eq!(decode_cursor(&cursor, Uuid::now_v7(), true), None);
        assert_eq!(decode_cursor(&cursor, account, false), None);
        assert_eq!(decode_cursor("not-a-page-token", account, true), None);
    }
}
