//! `grund.organisation.v1.OrganisationService`: the caller's organisations,
//! their members and invitations. The same services and rules as the pages
//! (web/orgs.rs): an organisation the caller is not a member of is not_found.

use buffa::{EnumValue, MessageField};
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use grund_proto::grund::organisation::v1::{
    ChangeMemberRoleRequest, ChangeMemberRoleResponse, CreateOrganisationRequest,
    CreateOrganisationResponse, DeleteOrganisationRequest, DeleteOrganisationResponse,
    GetOrganisationRequest, GetOrganisationResponse, Invitation, InviteMemberRequest,
    InviteMemberResponse, ListInvitationsRequest, ListInvitationsResponse, ListMembersRequest,
    ListMembersResponse, ListOrganisationsRequest, ListOrganisationsResponse, Member, Organisation,
    OrganisationService, RemoveMemberRequest, RemoveMemberResponse, RenameOrganisationRequest,
    RenameOrganisationResponse, RevokeInvitationRequest, RevokeInvitationResponse, Role,
};
use grund_store::organisations::Membership;
use uuid::Uuid;

use crate::{
    api::{Caller, caller},
    services::{
        accounts::{AccountsState, RequestMeta},
        organisations::{
            ChangeOutcome, CreateOutcome, DeleteOutcome, InviteOutcome, Organisations,
            OrganisationsState, RenameOutcome,
        },
    },
    state::State,
};

/// The service implementation.
pub struct OrganisationApi {
    state: State,
}

impl OrganisationApi {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    fn organisations(&self) -> Organisations {
        self.state.organisations()
    }

    async fn member(&self, caller: &Caller, slug: &str) -> Result<Membership, ConnectError> {
        self.organisations()
            .membership(slug, caller.account_id)
            .await
            .map_err(internal)?
            .ok_or_else(|| ConnectError::not_found("no such organisation"))
    }
}

fn meta() -> RequestMeta {
    RequestMeta {
        request_id: Uuid::now_v7(),
        address: String::new(),
    }
}

fn timestamp<P: buffa::ProtoBox<Timestamp>>(at: DateTime<Utc>) -> MessageField<Timestamp, P> {
    Timestamp::from_unix(at.timestamp(), at.timestamp_subsec_nanos() as i32).into()
}

fn role(role: &str) -> EnumValue<Role> {
    match role {
        "owner" => Role::ROLE_OWNER,
        "admin" => Role::ROLE_ADMIN,
        "member" => Role::ROLE_MEMBER,
        _ => Role::ROLE_UNSPECIFIED,
    }
    .into()
}

fn role_name(role: EnumValue<Role>) -> Result<&'static str, ConnectError> {
    match role.as_known() {
        Some(Role::ROLE_OWNER) => Ok("owner"),
        Some(Role::ROLE_ADMIN) => Ok("admin"),
        Some(Role::ROLE_MEMBER) => Ok("member"),
        _ => Err(ConnectError::invalid_argument(
            "role must be owner, admin or member",
        )),
    }
}

fn organisation(m: &Membership) -> Organisation {
    Organisation {
        organisation_id: m.organisation_id.to_string(),
        slug: m.slug.clone(),
        role: role(&m.role),
        created_at: timestamp(m.created_at),
        deletion_requested_at: m.deletion_requested_at.map(timestamp).unwrap_or_default(),
        deletion_refusal: m.deletion_refusal.clone().unwrap_or_default(),
        ..Default::default()
    }
}

fn uuid(value: &str, field: &str) -> Result<Uuid, ConnectError> {
    Uuid::parse_str(value)
        .map_err(|_| ConnectError::invalid_argument(format!("{field} must be a UUID")))
}

fn changed(outcome: ChangeOutcome) -> Result<(), ConnectError> {
    match outcome {
        ChangeOutcome::Done => Ok(()),
        ChangeOutcome::NotAllowed => Err(ConnectError::permission_denied(
            "your role does not allow that",
        )),
        ChangeOutcome::LastOwner => Err(ConnectError::failed_precondition(
            "an organisation needs at least one owner",
        )),
        ChangeOutcome::NotFound => Err(ConnectError::not_found("no such member or invitation")),
    }
}

fn internal(error: impl std::fmt::Display) -> ConnectError {
    tracing::error!(error = %error, "organisation API call failed");
    ConnectError::internal("grund could not finish that")
}

#[allow(refining_impl_trait)]
impl OrganisationService for OrganisationApi {
    async fn list_organisations(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListOrganisationsRequest>,
    ) -> ServiceResult<ListOrganisationsResponse> {
        let caller = caller(&ctx)?;
        let memberships = self
            .organisations()
            .memberships_of(caller.account_id)
            .await
            .map_err(internal)?;
        Response::ok(ListOrganisationsResponse {
            organisations: memberships.iter().map(organisation).collect(),
            ..Default::default()
        })
    }

    async fn get_organisation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetOrganisationRequest>,
    ) -> ServiceResult<GetOrganisationResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.slug).await?;
        Response::ok(GetOrganisationResponse {
            organisation: MessageField::from(organisation(&membership)),
            ..Default::default()
        })
    }

    async fn create_organisation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateOrganisationRequest>,
    ) -> ServiceResult<CreateOrganisationResponse> {
        let caller = caller(&ctx)?;
        let slug = match self
            .organisations()
            .create(caller.account_id, request.slug, &meta())
            .await
            .map_err(internal)?
        {
            CreateOutcome::Created(slug) => slug,
            CreateOutcome::Invalid(message) => return Err(ConnectError::invalid_argument(message)),
            CreateOutcome::NotAvailable => {
                return Err(ConnectError::unimplemented(
                    "this instance has one organisation and does not create more",
                ));
            }
        };
        let membership = self.member(&caller, &slug).await?;
        Response::ok(CreateOrganisationResponse {
            organisation: MessageField::from(organisation(&membership)),
            ..Default::default()
        })
    }

    async fn rename_organisation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RenameOrganisationRequest>,
    ) -> ServiceResult<RenameOrganisationResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.slug).await?;
        let slug = match self
            .organisations()
            .rename(caller.account_id, &membership, request.new_slug, &meta())
            .await
            .map_err(internal)?
        {
            RenameOutcome::Renamed(slug) => slug,
            RenameOutcome::Invalid(message) => return Err(ConnectError::invalid_argument(message)),
            RenameOutcome::NotAllowed => {
                return Err(ConnectError::permission_denied(
                    "only owners rename an organisation",
                ));
            }
        };
        let membership = self.member(&caller, &slug).await?;
        Response::ok(RenameOrganisationResponse {
            organisation: MessageField::from(organisation(&membership)),
            ..Default::default()
        })
    }

    async fn delete_organisation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteOrganisationRequest>,
    ) -> ServiceResult<DeleteOrganisationResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.slug).await?;
        match self
            .organisations()
            .request_deletion(
                caller.account_id,
                &membership,
                request.confirm_slug,
                &meta(),
            )
            .await
            .map_err(internal)?
        {
            DeleteOutcome::Requested => Response::ok(DeleteOrganisationResponse::default()),
            DeleteOutcome::Unconfirmed => Err(ConnectError::invalid_argument(
                "confirm_slug must repeat the organisation's slug",
            )),
            DeleteOutcome::NotAllowed => Err(ConnectError::permission_denied(
                "only owners delete an organisation",
            )),
            DeleteOutcome::Instance => Err(ConnectError::failed_precondition(
                "this is the instance's own organisation, and an instance needs it",
            )),
        }
    }

    async fn list_members(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListMembersRequest>,
    ) -> ServiceResult<ListMembersResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.slug).await?;
        let members = self
            .organisations()
            .members(membership.organisation_id)
            .await
            .map_err(internal)?;
        Response::ok(ListMembersResponse {
            members: members
                .into_iter()
                .map(|m| Member {
                    account_id: m.account_id.to_string(),
                    username: m.username,
                    email: m.email,
                    role: role(&m.role),
                    joined_at: m.joined_at.map(timestamp).unwrap_or_default(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn change_member_role(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ChangeMemberRoleRequest>,
    ) -> ServiceResult<ChangeMemberRoleResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.slug).await?;
        let account_id = uuid(request.account_id, "account_id")?;
        let new_role = role_name(request.role)?;
        let outcome = self
            .organisations()
            .change_role(
                caller.account_id,
                membership.organisation_id,
                account_id,
                new_role,
                &meta(),
            )
            .await
            .map_err(internal)?;
        changed(outcome)?;
        Response::ok(ChangeMemberRoleResponse::default())
    }

    async fn remove_member(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RemoveMemberRequest>,
    ) -> ServiceResult<RemoveMemberResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.slug).await?;
        let account_id = uuid(request.account_id, "account_id")?;
        let outcome = self
            .organisations()
            .remove(
                caller.account_id,
                membership.organisation_id,
                account_id,
                &meta(),
            )
            .await
            .map_err(internal)?;
        changed(outcome)?;
        Response::ok(RemoveMemberResponse::default())
    }

    async fn list_invitations(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListInvitationsRequest>,
    ) -> ServiceResult<ListInvitationsResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.slug).await?;
        let pending = self
            .organisations()
            .pending(membership.organisation_id)
            .await
            .map_err(internal)?;
        Response::ok(ListInvitationsResponse {
            invitations: pending
                .into_iter()
                .map(|i| Invitation {
                    invitation_id: i.invitation_id.to_string(),
                    email: i.email,
                    role: role(&i.role),
                    invited_by: i.invited_by,
                    expires_at: timestamp(i.expires_at),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn invite_member(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, InviteMemberRequest>,
    ) -> ServiceResult<InviteMemberResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.slug).await?;
        let invited_role = role_name(request.role)?;
        let actor_name = self
            .state
            .accounts()
            .viewer(caller.account_id)
            .await
            .map_err(internal)?
            .map(|v| v.username)
            .unwrap_or_default();
        match self
            .organisations()
            .invite(
                caller.account_id,
                &actor_name,
                &membership,
                request.email,
                invited_role,
                &meta(),
            )
            .await
            .map_err(internal)?
        {
            InviteOutcome::Sent(_) => Response::ok(InviteMemberResponse::default()),
            InviteOutcome::AlreadyMember => Err(ConnectError::already_exists(
                "that address already belongs to a member",
            )),
            InviteOutcome::Invalid(message) => Err(ConnectError::invalid_argument(message)),
            InviteOutcome::NotAllowed => Err(ConnectError::permission_denied(
                "your role does not allow inviting",
            )),
            InviteOutcome::TooMany => Err(ConnectError::resource_exhausted(
                "this organisation has 50 pending invitations",
            )),
            InviteOutcome::RateLimited => Err(ConnectError::resource_exhausted(
                "too many mails to that address lately; try again in an hour",
            )),
        }
    }

    async fn revoke_invitation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeInvitationRequest>,
    ) -> ServiceResult<RevokeInvitationResponse> {
        let caller = caller(&ctx)?;
        let membership = self.member(&caller, request.slug).await?;
        let invitation_id = uuid(request.invitation_id, "invitation_id")?;
        let outcome = self
            .organisations()
            .revoke(
                caller.account_id,
                membership.organisation_id,
                invitation_id,
                &meta(),
            )
            .await
            .map_err(internal)?;
        changed(outcome)?;
        Response::ok(RevokeInvitationResponse::default())
    }
}
