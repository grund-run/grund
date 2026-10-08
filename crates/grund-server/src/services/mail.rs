//! Sending mail over SMTP (lettre), rendered from the embedded templates.
//! Only the outbox drain sends; nothing on a request path does.

use crate::{config::ServeConfig, templates::compiled::mail};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart},
};

/// The mails grund sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mail {
    VerifyEmail,
    PasswordReset,
    SignupExisting,
    Invitation,
}

impl Mail {
    fn bodies(self, context: &serde_json::Value) -> Result<(String, String), MailError> {
        let pair = match self {
            Self::VerifyEmail => {
                let props = AccountLinkMail {
                    username: field(context, "username")?,
                    link: field(context, "link")?,
                };
                (
                    mail::verify_email_txt::render(&props),
                    mail::verify_email::render(&props),
                )
            }
            Self::PasswordReset => {
                let props = AccountLinkMail {
                    username: field(context, "username")?,
                    link: field(context, "link")?,
                };
                (
                    mail::password_reset_txt::render(&props),
                    mail::password_reset::render(&props),
                )
            }
            Self::SignupExisting => {
                let props = ExistingAccountMail {
                    login_link: field(context, "login_link")?,
                    reset_link: field(context, "reset_link")?,
                };
                (
                    mail::signup_existing_txt::render(&props),
                    mail::signup_existing::render(&props),
                )
            }
            Self::Invitation => {
                let props = InvitationMail {
                    invited_by: field(context, "invited_by")?,
                    organisation: field(context, "organisation")?,
                    role_article: field(context, "role_article")?,
                    role: field(context, "role")?,
                    link: field(context, "link")?,
                };
                (
                    mail::invitation_txt::render(&props),
                    mail::invitation::render(&props),
                )
            }
        };
        let (mut plain, html) = pair;
        if plain.ends_with('\n') {
            plain.pop();
        }
        Ok((plain, html))
    }

    fn subject(self, context: &serde_json::Value) -> String {
        match self {
            Mail::VerifyEmail => "Confirm your email for grund".into(),
            Mail::PasswordReset => "Reset your grund password".into(),
            Mail::SignupExisting => "You already have a grund account".into(),
            Mail::Invitation => format!(
                "Join {} on grund",
                context["organisation"]
                    .as_str()
                    .unwrap_or("an organisation")
            ),
        }
    }
}

fn field<'a>(context: &'a serde_json::Value, name: &str) -> Result<&'a str, MailError> {
    context
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or(MailError::Permanent)
}

pub struct AccountLinkMail<'a> {
    pub username: &'a str,
    pub link: &'a str,
}

pub struct ExistingAccountMail<'a> {
    pub login_link: &'a str,
    pub reset_link: &'a str,
}

pub struct InvitationMail<'a> {
    pub invited_by: &'a str,
    pub organisation: &'a str,
    pub role_article: &'a str,
    pub role: &'a str,
    pub link: &'a str,
}

/// Why a mail was not sent.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// GRUND_SMTP_URL is not set; the mail waits in the outbox.
    #[error("mail is not configured")]
    NotConfigured,
    /// The address or message can never be sent; retrying will not help.
    #[error("undeliverable")]
    Permanent,
    /// The server refused or was unreachable this time.
    #[error("delivery failed; will retry")]
    Transient,
}

/// Sends rendered mail, or reports that it cannot.
#[derive(Clone)]
pub struct Mailer {
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    from: Mailbox,
}

impl Mailer {
    /// Builds the transport from GRUND_SMTP_URL. Nothing connects until the
    /// first mail.
    pub fn new(config: &ServeConfig) -> anyhow::Result<Self> {
        let transport = match &config.smtp_url {
            Some(url) => Some(
                AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
                    .map_err(|_| anyhow::anyhow!("GRUND_SMTP_URL is not a valid SMTP URL"))?
                    .timeout(Some(std::time::Duration::from_secs(15)))
                    .build(),
            ),
            None => {
                tracing::warn!("GRUND_SMTP_URL not set; mail waits in the outbox until it is");
                None
            }
        };
        let from = config
            .mail_from
            .parse::<Mailbox>()
            .map_err(|_| anyhow::anyhow!("GRUND_MAIL_FROM is not a valid mail address"))?;
        Ok(Self { transport, from })
    }

    /// Whether mail can be sent at all.
    pub fn configured(&self) -> bool {
        self.transport.is_some()
    }

    /// Renders and sends one mail to `to`.
    pub async fn send(
        &self,
        mail: Mail,
        to: &str,
        context: &serde_json::Value,
    ) -> Result<(), MailError> {
        let Some(transport) = &self.transport else {
            return Err(MailError::NotConfigured);
        };
        let to: Mailbox = to.parse().map_err(|_| MailError::Permanent)?;
        let subject = mail.subject(context);
        let (plain, html) = mail.bodies(context)?;
        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(subject)
            .multipart(MultiPart::alternative_plain_html(plain, html))
            .map_err(|_| MailError::Permanent)?;
        transport.send(message).await.map(|_| ()).map_err(|error| {
            if error.is_permanent() {
                MailError::Permanent
            } else {
                let code = error.status().map(|code| code.to_string());
                tracing::warn!(smtp_code = ?code, "smtp delivery failed; will retry");
                MailError::Transient
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Mail, MailError};

    #[test]
    fn mail_html_escapes_people_and_urls_without_changing_plain_text() {
        let payload = serde_json::json!({
            "invited_by": "<Ada & Ben>",
            "organisation": "A \"quoted\" org",
            "role_article": "an",
            "role": "admin",
            "link": "https://grund.example/invite?token=a&source=\"mail\"",
        });

        let (plain, html) = Mail::Invitation.bodies(&payload).unwrap();
        assert!(plain.contains("<Ada & Ben> invited you to join A \"quoted\" org"));
        assert!(plain.contains("https://grund.example/invite?token=a&source=\"mail\""));
        assert!(
            html.contains("&lt;Ada &amp; Ben&gt; invited you to join A &quot;quoted&quot; org")
        );
        assert!(
            html.contains(
                "href=\"https://grund.example/invite?token=a&amp;source=&quot;mail&quot;\""
            )
        );
        assert!(!html.contains("<Ada & Ben>"));
    }

    #[test]
    fn mail_links_reject_executable_schemes_and_missing_data() {
        let payload = serde_json::json!({
            "login_link": "javascript:alert(1)",
            "reset_link": "https://grund.example/reset",
        });
        let (plain, html) = Mail::SignupExisting.bodies(&payload).unwrap();
        assert!(plain.contains("javascript:alert(1)"));
        assert!(html.contains("href=\"about:invalid#sedge-unsafe-url\""));
        assert!(html.contains("href=\"https://grund.example/reset\""));
        assert!(!html.contains("href=\"javascript:"));
        assert!(matches!(
            Mail::SignupExisting.bodies(&serde_json::json!({"login_link": "/login"})),
            Err(MailError::Permanent)
        ));
    }
}
