//! Organisations: where a new account lives, creating organisations, and
//! membership (invitations, roles, removal). The rules themselves are the
//! aggregate's (grund-domain `organisation`); this decides what to ask it
//! and writes the rows that go with its events.

use chrono::{DateTime, Utc};
use grund_domain::{
    names::{EmailAddress, Username},
    organisation::{
        INVITATION_TTL, OrganisationCommand, OrganisationError, OrganisationKind, Role,
    },
};
use grund_store::{
    accounts,
    organisations::{self, InvitationView, MemberRow, Membership, NewInvitation, PendingRow},
    outbox::{self, Kind},
    work::{Work, WorkError},
};
use uuid::Uuid;

use crate::{
    config::OrganisationMode,
    crypto,
    services::{
        accounts::{RequestMeta, sentence},
        limits::{Limits, LimitsState},
        outbox::wake,
    },
    state::State,
};

/// Where a new account will live, decided before its unit of work opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Home {
    /// A new organisation named after the account (`multi`).
    Personal(Uuid),
    /// The instance's organisation, created now with the account as its
    /// owner (`single`, first account).
    NewInstance(Uuid),
    /// Sign-up without an invitation is closed (`single`, after the first
    /// account).
    Closed,
}

impl Home {
    /// The organisation the account's `Registered` event names.
    pub fn organisation_id(self) -> Option<Uuid> {
        match self {
            Home::Personal(id) | Home::NewInstance(id) => Some(id),
            Home::Closed => None,
        }
    }
}

/// Decides where an account that signs up without an invitation lives.
pub async fn plan_home(state: &State) -> Result<Home, sqlx::Error> {
    Ok(match state.config.organisations {
        OrganisationMode::Multi => Home::Personal(Uuid::now_v7()),
        OrganisationMode::Single => match organisations::instance(&state.pool).await? {
            Some(_) => Home::Closed,
            None => Home::NewInstance(Uuid::now_v7()),
        },
    })
}

/// Creates the home `plan_home` chose, inside the account's unit of work. In
/// `single` mode it also claims the instance's row, so of two racing first
/// sign-ups one fails with a unique violation on `grund_instance_pkey`
/// ([`is_instance_taken`]).
pub async fn create_home(
    work: &mut Work<'_>,
    home: Home,
    account_id: Uuid,
    username: &Username,
    at: DateTime<Utc>,
) -> Result<(), WorkError> {
    let (organisation_id, kind) = match home {
        Home::Personal(id) => (id, OrganisationKind::Personal),
        Home::NewInstance(id) => (id, OrganisationKind::Instance),
        Home::Closed => return Ok(()),
    };
    work.organisation(
        organisation_id,
        OrganisationCommand::Create {
            slug: username.clone(),
            kind,
            owner: account_id,
            at,
        },
    )
    .await?;
    if kind == OrganisationKind::Instance {
        organisations::claim_instance(work.sql(), organisation_id).await?;
    }
    Ok(())
}

/// Whether a unit of work failed because another first sign-up already
/// created the instance's organisation.
pub fn is_instance_taken(error: &WorkError) -> bool {
    error.unique_violation().as_deref() == Some("grund_instance_pkey")
}

/// How creating an organisation ended.
#[derive(Debug, PartialEq, Eq)]
pub enum CreateOutcome {
    Created(String),
    Invalid(String),
    /// This instance does not create organisations (`single`).
    NotAvailable,
}

/// How an invitation request ended. `Sent` also when the address has no
/// account: inviting says nothing about who uses grund.
#[derive(Debug, PartialEq, Eq)]
pub enum InviteOutcome {
    Sent(String),
    AlreadyMember,
    Invalid(String),
    NotAllowed,
    TooMany,
    RateLimited,
}

/// How a membership change ended.
#[derive(Debug, PartialEq, Eq)]
pub enum ChangeOutcome {
    Done,
    NotAllowed,
    LastOwner,
    NotFound,
}

/// How accepting an invitation ended.
#[derive(Debug, PartialEq, Eq)]
pub enum AcceptOutcome {
    Joined(String),
    AlreadyMember(String),
    /// The signed-in account's address is not the invited one.
    WrongAccount,
    Expired,
}

/// Organisation flows.
#[derive(Clone)]
pub struct Organisations {
    state: State,
    limits: Limits,
}

impl Organisations {
    /// The organisation `slug` if the account is a member, and remembers it
    /// as the one `/` opens next. `None` for "no such organisation" and "not
    /// a member" alike.
    pub async fn open(&self, slug: &str, account_id: Uuid) -> anyhow::Result<Option<Membership>> {
        let membership = organisations::membership(&self.state.pool, slug, account_id).await?;
        if let Some(membership) = &membership {
            organisations::remember_last(&self.state.pool, account_id, membership.organisation_id)
                .await?;
        }
        Ok(membership)
    }

    /// Where `/` sends the account.
    pub async fn landing(&self, account_id: Uuid) -> anyhow::Result<Option<String>> {
        Ok(organisations::landing(&self.state.pool, account_id).await?)
    }

    pub async fn memberships_of(&self, account_id: Uuid) -> anyhow::Result<Vec<Membership>> {
        Ok(organisations::memberships_of(&self.state.pool, account_id).await?)
    }

    pub async fn members(&self, organisation_id: Uuid) -> anyhow::Result<Vec<MemberRow>> {
        Ok(organisations::members(&self.state.pool, organisation_id).await?)
    }

    pub async fn pending(&self, organisation_id: Uuid) -> anyhow::Result<Vec<PendingRow>> {
        Ok(organisations::pending_invitations(&self.state.pool, organisation_id).await?)
    }

    /// Whether this instance lets people create organisations.
    pub fn can_create(&self) -> bool {
        self.state.config.organisations == OrganisationMode::Multi
    }

    /// Creates a shared organisation owned by `owner`.
    pub async fn create(
        &self,
        owner: Uuid,
        slug: &str,
        meta: &RequestMeta,
    ) -> anyhow::Result<CreateOutcome> {
        if !self.can_create() {
            return Ok(CreateOutcome::NotAvailable);
        }
        let slug = match Username::parse(slug) {
            Ok(slug) => slug,
            Err(error) => return Ok(CreateOutcome::Invalid(sentence(error))),
        };
        if organisations::slug_taken(&self.state.pool, slug.as_str()).await? {
            return Ok(CreateOutcome::Invalid(TAKEN.into()));
        }
        let organisation_id = Uuid::now_v7();
        let mut work =
            Work::begin(&self.state.events, meta.request_id, "create-organisation").await?;
        let created = work
            .organisation(
                organisation_id,
                OrganisationCommand::Create {
                    slug: slug.clone(),
                    kind: OrganisationKind::Shared,
                    owner,
                    at: Utc::now(),
                },
            )
            .await;
        match created {
            Ok(_) => {}
            Err(error) if error.unique_violation().is_some() => {
                return Ok(CreateOutcome::Invalid(TAKEN.into()));
            }
            Err(error) => return Err(error.into()),
        }
        match work.commit().await {
            Ok(()) => {}
            Err(error) if error.unique_violation().is_some() => {
                return Ok(CreateOutcome::Invalid(TAKEN.into()));
            }
            Err(error) => return Err(error.into()),
        }
        tracing::info!(%organisation_id, %owner, "organisation created");
        Ok(CreateOutcome::Created(slug.as_str().to_string()))
    }

    /// Invites `email` to the organisation as `role`, and mails the link.
    pub async fn invite(
        &self,
        actor: Uuid,
        actor_name: &str,
        organisation: &Membership,
        email: &str,
        role: &str,
        meta: &RequestMeta,
    ) -> anyhow::Result<InviteOutcome> {
        let email = match EmailAddress::parse(email) {
            Ok(email) => email,
            Err(error) => return Ok(InviteOutcome::Invalid(sentence(error))),
        };
        let Some(role) = Role::parse(role).filter(|r| *r != Role::Owner) else {
            return Ok(InviteOutcome::Invalid("Choose member or admin.".into()));
        };
        if organisations::has_member_with_email(
            &self.state.pool,
            organisation.organisation_id,
            email.normalized(),
        )
        .await?
        {
            return Ok(InviteOutcome::AlreadyMember);
        }
        if !self.limits.admit_mail_to(email.normalized()).await? {
            return Ok(InviteOutcome::RateLimited);
        }
        let invitation_id = Uuid::now_v7();
        let now = Utc::now();
        let token = crypto::random_token();
        let mut work = Work::begin(&self.state.events, meta.request_id, "invite").await?;
        let issued = work
            .organisation(
                organisation.organisation_id,
                OrganisationCommand::Invite {
                    actor,
                    invitation_id,
                    email_digest: crypto::email_digest(email.normalized()),
                    role,
                    at: now,
                },
            )
            .await;
        match issued {
            Ok(_) => {}
            Err(WorkError::Organisation(OrganisationError::NotAllowed)) => {
                return Ok(InviteOutcome::NotAllowed);
            }
            Err(WorkError::Organisation(OrganisationError::TooManyInvitations)) => {
                return Ok(InviteOutcome::TooMany);
            }
            Err(error) => return Err(error.into()),
        }
        organisations::insert_invitation(
            work.sql(),
            &NewInvitation {
                invitation_id,
                organisation_id: organisation.organisation_id,
                token_digest: &crypto::digest(&token),
                email: email.as_str(),
                email_normalized: email.normalized(),
                role: role.as_str(),
                invited_by: actor,
                expires_at: now + INVITATION_TTL,
            },
        )
        .await?;
        let payload = serde_json::json!({
            "organisation": organisation.slug,
            "invited_by": actor_name,
            "role": role.as_str(),
            "role_article": if role == Role::Admin { "an" } else { "a" },
            "link": format!("{}/invite?token={token}", self.state.config.public_origin().serialized),
        });
        outbox::enqueue(
            work.sql(),
            Uuid::now_v7(),
            Kind::InvitationMail,
            email.as_str(),
            &payload,
        )
        .await?;
        work.commit().await?;
        tracing::info!(organisation_id = %organisation.organisation_id, %invitation_id, "invitation sent");
        wake(&self.state).await;
        Ok(InviteOutcome::Sent(email.as_str().to_string()))
    }

    /// Withdraws a pending invitation.
    pub async fn revoke(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        invitation_id: Uuid,
        meta: &RequestMeta,
    ) -> anyhow::Result<ChangeOutcome> {
        let mut work =
            Work::begin(&self.state.events, meta.request_id, "revoke-invitation").await?;
        let result = work
            .organisation(
                organisation_id,
                OrganisationCommand::RevokeInvitation {
                    actor,
                    invitation_id,
                    at: Utc::now(),
                },
            )
            .await;
        if let Some(outcome) = refused(&result) {
            return Ok(outcome);
        }
        result?;
        organisations::mark_withdrawn(work.sql(), invitation_id).await?;
        work.commit().await?;
        Ok(ChangeOutcome::Done)
    }

    /// Changes a member's role.
    pub async fn change_role(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        account_id: Uuid,
        role: &str,
        meta: &RequestMeta,
    ) -> anyhow::Result<ChangeOutcome> {
        let Some(role) = Role::parse(role) else {
            return Ok(ChangeOutcome::NotFound);
        };
        let mut work = Work::begin(&self.state.events, meta.request_id, "change-role").await?;
        let result = work
            .organisation(
                organisation_id,
                OrganisationCommand::ChangeRole {
                    actor,
                    account_id,
                    role,
                    at: Utc::now(),
                },
            )
            .await;
        if let Some(outcome) = refused(&result) {
            return Ok(outcome);
        }
        result?;
        work.commit().await?;
        Ok(ChangeOutcome::Done)
    }

    /// Removes a member, or lets `actor` leave when it is them.
    pub async fn remove(
        &self,
        actor: Uuid,
        organisation_id: Uuid,
        account_id: Uuid,
        meta: &RequestMeta,
    ) -> anyhow::Result<ChangeOutcome> {
        let mut work = Work::begin(&self.state.events, meta.request_id, "remove-member").await?;
        let result = work
            .organisation(
                organisation_id,
                OrganisationCommand::RemoveMember {
                    actor,
                    account_id,
                    at: Utc::now(),
                },
            )
            .await;
        if let Some(outcome) = refused(&result) {
            return Ok(outcome);
        }
        result?;
        work.commit().await?;
        Ok(ChangeOutcome::Done)
    }

    /// The invitation behind a link, if it is still usable.
    pub async fn invitation(&self, token: &str) -> anyhow::Result<Option<InvitationView>> {
        Ok(organisations::open_invitation(&self.state.pool, &crypto::digest(token)).await?)
    }

    /// Joins the signed-in account to the organisation that invited its
    /// address.
    pub async fn accept(
        &self,
        account_id: Uuid,
        token: &str,
        meta: &RequestMeta,
    ) -> anyhow::Result<AcceptOutcome> {
        let Some(invitation) = self.invitation(token).await? else {
            return Ok(AcceptOutcome::Expired);
        };
        let Some(account) = accounts::login_record_by_id(&self.state.pool, account_id).await?
        else {
            return Ok(AcceptOutcome::Expired);
        };
        if !account.email_verified || account.email_normalized != invitation.email_normalized {
            return Ok(AcceptOutcome::WrongAccount);
        }
        let mut work =
            Work::begin(&self.state.events, meta.request_id, "accept-invitation").await?;
        let result = accept_in(&mut work, &invitation, account_id, Utc::now()).await;
        match result {
            Ok(()) => {}
            Err(WorkError::Organisation(OrganisationError::AlreadyMember)) => {
                return Ok(AcceptOutcome::AlreadyMember(invitation.slug));
            }
            Err(WorkError::Organisation(
                OrganisationError::NoSuchInvitation | OrganisationError::WrongAddress,
            )) => return Ok(AcceptOutcome::Expired),
            Err(error) => return Err(error.into()),
        }
        work.commit().await?;
        tracing::info!(organisation_id = %invitation.organisation_id, %account_id, "invitation accepted");
        Ok(AcceptOutcome::Joined(invitation.slug))
    }
}

/// Uses `invitation` for `account_id` inside a unit of work: the event, and
/// the row marked accepted.
pub async fn accept_in(
    work: &mut Work<'_>,
    invitation: &InvitationView,
    account_id: Uuid,
    at: DateTime<Utc>,
) -> Result<(), WorkError> {
    work.organisation(
        invitation.organisation_id,
        OrganisationCommand::AcceptInvitation {
            invitation_id: invitation.invitation_id,
            account_id,
            email_digest: crypto::email_digest(&invitation.email_normalized),
            at,
        },
    )
    .await?;
    organisations::mark_accepted(work.sql(), invitation.invitation_id).await?;
    Ok(())
}

fn refused<T>(result: &Result<T, WorkError>) -> Option<ChangeOutcome> {
    match result {
        Err(WorkError::Organisation(error)) => Some(match error {
            OrganisationError::NotAllowed => ChangeOutcome::NotAllowed,
            OrganisationError::LastOwner => ChangeOutcome::LastOwner,
            _ => ChangeOutcome::NotFound,
        }),
        _ => None,
    }
}

const TAKEN: &str = "That name is taken.";

pub trait OrganisationsState {
    fn organisations(&self) -> Organisations;
}

impl OrganisationsState for State {
    fn organisations(&self) -> Organisations {
        Organisations {
            state: self.clone(),
            limits: self.limits(),
        }
    }
}
