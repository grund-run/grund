//! Sending mail over SMTP (lettre), rendered from the embedded templates.
//! Only the outbox drain sends; nothing on a request path does.

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart},
};
use minijinja::Value;

use crate::{config::ServeConfig, templates::Templates};

/// The mails grund sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mail {
    VerifyEmail,
    PasswordReset,
    SignupExisting,
}

impl Mail {
    fn template(self) -> &'static str {
        match self {
            Mail::VerifyEmail => "verify_email",
            Mail::PasswordReset => "password_reset",
            Mail::SignupExisting => "signup_existing",
        }
    }

    fn subject(self) -> &'static str {
        match self {
            Mail::VerifyEmail => "Confirm your email for grund",
            Mail::PasswordReset => "Reset your grund password",
            Mail::SignupExisting => "You already have a grund account",
        }
    }
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
    templates: Templates,
}

impl Mailer {
    /// Builds the transport from GRUND_SMTP_URL. Nothing connects until the
    /// first mail.
    pub fn new(config: &ServeConfig, templates: Templates) -> anyhow::Result<Self> {
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
        Ok(Self {
            transport,
            from,
            templates,
        })
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
        let context = Value::from_serialize(context);
        let render = |ext: &str| {
            self.templates
                .render(
                    &format!("mail/{}.{ext}.jinja", mail.template()),
                    context.clone(),
                )
                .map_err(|error| {
                    tracing::error!(error = %error, "mail template failed");
                    MailError::Permanent
                })
        };
        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(mail.subject())
            .multipart(MultiPart::alternative_plain_html(
                render("txt")?,
                render("html")?,
            ))
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
