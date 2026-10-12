//! What clap cannot say about client and Connect-backed operator commands:
//! their protobuf JSON output, procedures, mutations, and examples.
//! Every runnable client leaf has one entry; the binary checks operator
//! leaves against its complete command tree too.

/// One Connect-backed command.
#[derive(Debug, Clone, Copy)]
pub struct Leaf {
    /// The words after `grund`, such as `apps set image`.
    pub path: &'static str,
    /// The protobuf message its `--output json` is.
    pub output: &'static str,
    /// The procedures it may call, `package.Service/Method`.
    pub rpcs: &'static [&'static str],
    /// It changes something on the instance or on this computer.
    pub mutates: bool,
    /// It removes or revokes something; it needs --yes when nobody can be
    /// asked.
    pub destructive: bool,
    /// What it reads from stdin, if anything.
    pub stdin: &'static str,
    pub examples: &'static [&'static str],
}

const fn read(
    path: &'static str,
    output: &'static str,
    rpcs: &'static [&'static str],
    examples: &'static [&'static str],
) -> Leaf {
    Leaf {
        path,
        output,
        rpcs,
        mutates: false,
        destructive: false,
        stdin: "",
        examples,
    }
}

const fn write(
    path: &'static str,
    output: &'static str,
    rpcs: &'static [&'static str],
    examples: &'static [&'static str],
) -> Leaf {
    Leaf {
        path,
        output,
        rpcs,
        mutates: true,
        destructive: false,
        stdin: "",
        examples,
    }
}

const fn destroy(
    path: &'static str,
    rpcs: &'static [&'static str],
    examples: &'static [&'static str],
) -> Leaf {
    Leaf {
        path,
        output: "grund.cli.v1.Done",
        rpcs,
        mutates: true,
        destructive: true,
        stdin: "",
        examples,
    }
}

const fn with_stdin(leaf: Leaf, stdin: &'static str) -> Leaf {
    Leaf { stdin, ..leaf }
}

/// Every client and Connect-backed operator command.
pub const LEAVES: &[Leaf] = &[
    with_stdin(
        write(
            "login",
            "grund.cli.v1.LoginResult",
            &[
                "grund.login.v1.DeviceLoginService/StartDeviceLogin",
                "grund.login.v1.DeviceLoginService/PollDeviceLogin",
                "grund.account.v1.AccountService/GetViewer",
                "grund.token.v1.TokenService/GetCurrentToken",
            ],
            &[
                "grund login grund.example.com",
                "grund login grund.example.com --json   # prints the approval link as a JSON line on stderr",
                "printf %s \"$TOKEN\" | grund login grund.example.com --with-token",
            ],
        ),
        "with --with-token: a personal access token",
    ),
    write(
        "logout",
        "grund.cli.v1.Done",
        &[
            "grund.account.v1.AccountService/ListSessions",
            "grund.account.v1.AccountService/RevokeSession",
        ],
        &["grund logout"],
    ),
    read(
        "whoami",
        "grund.cli.v1.Whoami",
        &[
            "grund.account.v1.AccountService/GetViewer",
            "grund.organisation.v1.OrganisationService/ListOrganisations",
            "grund.token.v1.TokenService/GetCurrentToken",
        ],
        &["grund whoami --json"],
    ),
    read(
        "orgs list",
        "grund.cli.v1.OrganisationList",
        &["grund.organisation.v1.OrganisationService/ListOrganisations"],
        &["grund orgs list --json"],
    ),
    read(
        "orgs get",
        "grund.organisation.v1.GetOrganisationResponse",
        &["grund.organisation.v1.OrganisationService/GetOrganisation"],
        &["grund orgs get acme"],
    ),
    write(
        "orgs use",
        "grund.cli.v1.Done",
        &["grund.organisation.v1.OrganisationService/GetOrganisation"],
        &["grund orgs use acme"],
    ),
    write(
        "orgs create",
        "grund.organisation.v1.CreateOrganisationResponse",
        &["grund.organisation.v1.OrganisationService/CreateOrganisation"],
        &["grund orgs create acme-staging"],
    ),
    write(
        "orgs rename",
        "grund.organisation.v1.RenameOrganisationResponse",
        &["grund.organisation.v1.OrganisationService/RenameOrganisation"],
        &["grund orgs rename acme acme-inc"],
    ),
    destroy(
        "orgs delete",
        &["grund.organisation.v1.OrganisationService/DeleteOrganisation"],
        &["grund orgs delete acme-staging --yes"],
    ),
    read(
        "apps list",
        "grund.app.v1.ListAppsResponse",
        &["grund.app.v1.AppService/ListApps"],
        &["grund apps list --json"],
    ),
    read(
        "apps get",
        "grund.app.v1.GetAppResponse",
        &["grund.app.v1.AppService/GetApp"],
        &["grund apps get web --json"],
    ),
    read(
        "apps status",
        "grund.cli.v1.AppStatus",
        &["grund.app.v1.AppService/GetApp"],
        &["grund apps status web --json | jq -r .health"],
    ),
    read(
        "apps history",
        "grund.app.v1.ListReleasesResponse",
        &["grund.app.v1.AppService/ListReleases"],
        &["grund apps history web"],
    ),
    write(
        "apps create",
        "grund.app.v1.CreateAppResponse",
        &["grund.app.v1.AppService/CreateApp"],
        &["grund apps create web --copies 2"],
    ),
    write(
        "apps deploy",
        "grund.cli.v1.DeployResult",
        &[
            "grund.app.v1.AppService/GetApp",
            "grund.app.v1.AppService/ListApps",
            "grund.app.v1.AppService/CreateApp",
            "grund.app.v1.AppService/Scale",
            "grund.app.v1.AppService/Deploy",
            "grund.app.v1.AppService/ListReleases",
        ],
        &[
            "grund apps deploy -f grund.yaml --wait --json",
            "grund apps deploy web --image nginx:1.27 --port http=80 --public http --wait",
            "grund apps deploy web -f grund.yaml --dry-run --json",
        ],
    ),
    write(
        "apps set image",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund apps set web image nginx:1.27 --wait"],
    ),
    write(
        "apps set env",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund apps set web env LOG_LEVEL=debug --unset OLD_FLAG"],
    ),
    write(
        "apps set secret-env",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund apps set web secret-env DATABASE_URL=database-url"],
    ),
    write(
        "apps set ports",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund apps set web ports http=8080 metrics=9090/http --public http"],
    ),
    write(
        "apps set check",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund apps set web check --http /healthz"],
    ),
    write(
        "apps set resources",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund apps set web resources --memory-mib 1024 --cpu 0.5"],
    ),
    write(
        "apps set command",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund apps set web command -- ./server --port 8080"],
    ),
    write(
        "apps set copies",
        "grund.app.v1.ScaleResponse",
        &[
            "grund.app.v1.AppService/GetApp",
            "grund.app.v1.AppService/Scale",
        ],
        &["grund apps set web copies 3"],
    ),
    write(
        "apps set placement",
        "grund.app.v1.ConfigureAppResponse",
        &[
            "grund.app.v1.AppService/GetApp",
            "grund.app.v1.AppService/ConfigureApp",
        ],
        &["grund apps set web placement --label zone=eu --spread-by zone"],
    ),
    write(
        "apps set auto-rollback",
        "grund.app.v1.ConfigureAppResponse",
        &[
            "grund.app.v1.AppService/GetApp",
            "grund.app.v1.AppService/ConfigureApp",
        ],
        &["grund apps set web auto-rollback off"],
    ),
    write(
        "apps rollback",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/Rollback",
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/GetApp",
        ],
        &["grund apps rollback web 3 --wait --json"],
    ),
    destroy(
        "apps delete",
        &["grund.app.v1.AppService/DeleteApp"],
        &["grund apps delete web --yes"],
    ),
    read(
        "apps secrets list",
        "grund.cli.v1.SecretList",
        &["grund.app.v1.AppService/GetApp"],
        &["grund apps secrets list web"],
    ),
    with_stdin(
        write(
            "apps secrets set",
            "grund.app.v1.SetSecretResponse",
            &["grund.app.v1.AppService/SetSecret"],
            &["printf %s \"$DATABASE_URL\" | grund apps secrets set web database-url"],
        ),
        "the secret's value; one final newline is dropped",
    ),
    read(
        "volumes list",
        "grund.volume.v1.ListVolumesResponse",
        &["grund.volume.v1.VolumeService/ListVolumes"],
        &["grund volumes list photos"],
    ),
    read(
        "volumes show",
        "grund.volume.v1.GetVolumeStatusResponse",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/GetVolumeStatus",
        ],
        &["grund volumes show photos data"],
    ),
    write(
        "volumes create",
        "grund.volume.v1.CreateVolumeResponse",
        &["grund.volume.v1.VolumeService/CreateVolume"],
        &["grund volumes create photos data --path /data --backup"],
    ),
    write(
        "volumes attach",
        "grund.volume.v1.AttachVolumeResponse",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/AttachVolume",
        ],
        &["grund volumes attach photos data 00000000-0000-0000-0000-000000000000"],
    ),
    write(
        "volumes detach",
        "grund.volume.v1.DetachVolumeResponse",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/DetachVolume",
        ],
        &["grund volumes detach photos data"],
    ),
    destroy(
        "volumes delete",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/DeleteVolume",
        ],
        &["grund volumes delete photos data --yes"],
    ),
    read(
        "volumes backups status",
        "grund.volume.v1.GetBackupDestinationResponse",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/GetBackupDestination",
        ],
        &["grund volumes backups photos data status"],
    ),
    with_stdin(
        write(
            "volumes backups set",
            "grund.volume.v1.SetBackupDestinationResponse",
            &[
                "grund.volume.v1.VolumeService/ListVolumes",
                "grund.volume.v1.VolumeService/GetBackupDestination",
                "grund.volume.v1.VolumeService/SetBackupDestination",
            ],
            &[
                "grund volumes backups photos data set --endpoint https://s3.example.com --bucket photos-backup --access-key-id KEY",
            ],
        ),
        "the S3 secret access key; one final newline is dropped",
    ),
    read(
        "volumes backups points",
        "grund.volume.v1.ListRecoveryPointsResponse",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/ListRecoveryPoints",
        ],
        &["grund volumes backups photos data points"],
    ),
    destroy(
        "volumes backups export-key",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/ExportBackupKey",
        ],
        &["grund volumes backups photos data export-key --file ./photos-backup-key --yes"],
    ),
    Leaf {
        destructive: true,
        ..write(
            "volumes restore",
            "grund.volume.v1.RestoreRecoveryPointResponse",
            &[
                "grund.volume.v1.VolumeService/ListVolumes",
                "grund.volume.v1.VolumeService/RestoreRecoveryPoint",
            ],
            &[
                "grund volumes restore photos data SNAPSHOT --name recovered --path /recovered --machine MACHINE --yes",
            ],
        )
    },
    read(
        "machines list",
        "grund.machine.v1.ListMachinesResponse",
        &["grund.machine.v1.MachineService/ListMachines"],
        &["grund machines list --json"],
    ),
    read(
        "machines offers",
        "grund.machine.v1.ListHostedOffersResponse",
        &["grund.machine.v1.MachineService/ListHostedOffers"],
        &["grund machines offers --json"],
    ),
    write(
        "machines create",
        "grund.machine.v1.CreateHostedMachineResponse",
        &["grund.machine.v1.MachineService/CreateHostedMachine"],
        &["grund machines create --size small --region eu --json"],
    ),
    read(
        "machines get",
        "grund.machine.v1.GetMachineResponse",
        &[
            "grund.machine.v1.MachineService/ListMachines",
            "grund.machine.v1.MachineService/GetMachine",
        ],
        &["grund machines get web-1"],
    ),
    write(
        "machines add",
        "grund.cli.v1.MachineAdded",
        &["grund.machine.v1.MachineService/CreateJoinToken"],
        &["grund machines add web-2   # prints the command to run on the new machine"],
    ),
    write(
        "machines labels",
        "grund.machine.v1.SetMachineLabelsResponse",
        &[
            "grund.machine.v1.MachineService/ListMachines",
            "grund.machine.v1.MachineService/SetMachineLabels",
        ],
        &[
            "grund machines labels web-1 zone=eu disk=ssd",
            "grund machines labels web-1",
        ],
    ),
    write(
        "machines out-of-service",
        "grund.machine.v1.SetMachineInServiceResponse",
        &[
            "grund.machine.v1.MachineService/ListMachines",
            "grund.machine.v1.MachineService/SetMachineInService",
        ],
        &["grund machines out-of-service web-1"],
    ),
    write(
        "machines in-service",
        "grund.machine.v1.SetMachineInServiceResponse",
        &[
            "grund.machine.v1.MachineService/ListMachines",
            "grund.machine.v1.MachineService/SetMachineInService",
        ],
        &["grund machines in-service web-1"],
    ),
    destroy(
        "machines remove",
        &[
            "grund.machine.v1.MachineService/ListMachines",
            "grund.machine.v1.MachineService/RevokeMachine",
            "grund.machine.v1.MachineService/RemoveHostedMachine",
        ],
        &["grund machines remove web-1 --yes"],
    ),
    read(
        "domains list",
        "grund.domain.v1.ListDomainsResponse",
        &["grund.domain.v1.DomainService/ListDomains"],
        &["grund domains list"],
    ),
    read(
        "domains get",
        "grund.domain.v1.GetDomainResponse",
        &["grund.domain.v1.DomainService/GetDomain"],
        &["grund domains get shop.example.com --json"],
    ),
    write(
        "domains add",
        "grund.domain.v1.AddDomainResponse",
        &["grund.domain.v1.DomainService/AddDomain"],
        &["grund domains add shop.example.com --json | jq -r .domain.verificationRecordValue"],
    ),
    write(
        "domains verify",
        "grund.domain.v1.VerifyDomainResponse",
        &["grund.domain.v1.DomainService/VerifyDomain"],
        &["grund domains verify shop.example.com"],
    ),
    write(
        "domains bind",
        "grund.domain.v1.BindDomainResponse",
        &["grund.domain.v1.DomainService/BindDomain"],
        &["grund domains bind shop.example.com web"],
    ),
    write(
        "domains unbind",
        "grund.domain.v1.UnbindDomainResponse",
        &["grund.domain.v1.DomainService/UnbindDomain"],
        &["grund domains unbind shop.example.com"],
    ),
    destroy(
        "domains remove",
        &["grund.domain.v1.DomainService/RemoveDomain"],
        &["grund domains remove shop.example.com --yes"],
    ),
    read(
        "members list",
        "grund.organisation.v1.ListMembersResponse",
        &["grund.organisation.v1.OrganisationService/ListMembers"],
        &["grund members list"],
    ),
    write(
        "members invite",
        "grund.cli.v1.Done",
        &["grund.organisation.v1.OrganisationService/InviteMember"],
        &["grund members invite ana@example.com --role admin"],
    ),
    write(
        "members role",
        "grund.cli.v1.Done",
        &[
            "grund.organisation.v1.OrganisationService/ListMembers",
            "grund.organisation.v1.OrganisationService/ChangeMemberRole",
        ],
        &["grund members role ana admin"],
    ),
    destroy(
        "members remove",
        &[
            "grund.organisation.v1.OrganisationService/ListMembers",
            "grund.organisation.v1.OrganisationService/RemoveMember",
        ],
        &["grund members remove ana --yes"],
    ),
    read(
        "invitations list",
        "grund.organisation.v1.ListInvitationsResponse",
        &["grund.organisation.v1.OrganisationService/ListInvitations"],
        &["grund invitations list"],
    ),
    destroy(
        "invitations revoke",
        &[
            "grund.organisation.v1.OrganisationService/ListInvitations",
            "grund.organisation.v1.OrganisationService/RevokeInvitation",
        ],
        &["grund invitations revoke ana@example.com --yes"],
    ),
    read(
        "notifications",
        "grund.notification.v1.ListNotificationsResponse",
        &["grund.notification.v1.NotificationService/ListNotifications"],
        &[
            "grund notifications --json",
            "grund notifications --unread --page-size 100",
        ],
    ),
    read(
        "notifications count",
        "grund.notification.v1.CountUnreadResponse",
        &["grund.notification.v1.NotificationService/CountUnread"],
        &["grund notifications count"],
    ),
    write(
        "notifications read",
        "grund.cli.v1.Done",
        &[
            "grund.notification.v1.NotificationService/MarkRead",
            "grund.notification.v1.NotificationService/MarkAllRead",
        ],
        &[
            "grund notifications read 0199a9b5-bcdf-7338-9a92-b6f536b9ca9b",
            "grund notifications read --all",
        ],
    ),
    read(
        "tokens list",
        "grund.token.v1.ListTokensResponse",
        &["grund.token.v1.TokenService/ListTokens"],
        &["grund tokens list"],
    ),
    write(
        "tokens create",
        "grund.token.v1.CreateTokenResponse",
        &["grund.token.v1.TokenService/CreateToken"],
        &[
            "grund tokens create --name ci-deploy --days 90",
            "grund tokens create --name agent --scope full --json | jq -r .secret",
        ],
    ),
    destroy(
        "tokens revoke",
        &[
            "grund.token.v1.TokenService/ListTokens",
            "grund.token.v1.TokenService/RevokeToken",
        ],
        &["grund tokens revoke ci-deploy --yes"],
    ),
    read(
        "registries list",
        "grund.registry.v1.ListRegistryLoginsResponse",
        &["grund.registry.v1.RegistryService/ListRegistryLogins"],
        &["grund registries list"],
    ),
    with_stdin(
        write(
            "registries set",
            "grund.registry.v1.SetRegistryLoginResponse",
            &["grund.registry.v1.RegistryService/SetRegistryLogin"],
            &["printf %s \"$GHCR_TOKEN\" | grund registries set ghcr.io --username acme-bot"],
        ),
        "the password or access token",
    ),
    destroy(
        "registries remove",
        &["grund.registry.v1.RegistryService/RemoveRegistryLogin"],
        &["grund registries remove ghcr.io --yes"],
    ),
    read(
        "operator hosts list",
        "grund.operator.v1.ListHostsResponse",
        &["grund.operator.v1.OperatorService/ListHosts"],
        &["grund operator hosts list --json"],
    ),
    read(
        "operator hosts machines",
        "grund.operator.v1.ListFleetMachinesResponse",
        &["grund.operator.v1.OperatorService/ListFleetMachines"],
        &["grund operator hosts machines --host HOST"],
    ),
    read(
        "operator hosts failures",
        "grund.operator.v1.ListFailuresResponse",
        &["grund.operator.v1.OperatorService/ListFailures"],
        &["grund operator hosts failures"],
    ),
    write(
        "operator hosts cordon",
        "grund.operator.v1.CordonHostResponse",
        &["grund.operator.v1.OperatorService/CordonHost"],
        &["grund operator hosts cordon HOST --reason maintenance"],
    ),
    write(
        "operator hosts uncordon",
        "grund.operator.v1.UncordonHostResponse",
        &["grund.operator.v1.OperatorService/UncordonHost"],
        &["grund operator hosts uncordon HOST"],
    ),
    Leaf {
        output: "grund.operator.v1.DrainHostResponse",
        ..destroy(
            "operator hosts drain",
            &["grund.operator.v1.OperatorService/DrainHost"],
            &["grund operator hosts drain HOST --yes"],
        )
    },
    read(
        "operator pool list",
        "grund.operator.v1.ListPoolsResponse",
        &["grund.operator.v1.OperatorService/ListPools"],
        &["grund operator pool list"],
    ),
    read(
        "operator pool machines",
        "grund.machine.v1.ListPoolMachinesResponse",
        &["grund.machine.v1.ManagementPoolService/ListPoolMachines"],
        &["grund operator pool machines"],
    ),
    read(
        "operator pool get",
        "grund.machine.v1.GetPoolMachineResponse",
        &["grund.machine.v1.ManagementPoolService/GetPoolMachine"],
        &["grund operator pool get MACHINE"],
    ),
    write(
        "operator pool provision",
        "grund.machine.v1.ProvisionPoolMachineResponse",
        &["grund.machine.v1.ManagementPoolService/ProvisionPoolMachine"],
        &["grund operator pool provision --size small"],
    ),
    write(
        "operator pool lease",
        "grund.machine.v1.LeaseMachineResponse",
        &["grund.machine.v1.ManagementPoolService/LeaseMachine"],
        &["grund operator pool lease MACHINE ORGANISATION"],
    ),
    Leaf {
        output: "grund.machine.v1.EndLeaseResponse",
        ..destroy(
            "operator pool end",
            &["grund.machine.v1.ManagementPoolService/EndLease"],
            &["grund operator pool end MACHINE --yes"],
        )
    },
    Leaf {
        output: "grund.machine.v1.RevokePoolMachineResponse",
        ..destroy(
            "operator pool revoke",
            &["grund.machine.v1.ManagementPoolService/RevokePoolMachine"],
            &["grund operator pool revoke MACHINE --yes"],
        )
    },
    Leaf {
        output: "grund.machine.v1.RebuildPoolMachineResponse",
        ..destroy(
            "operator pool rebuild",
            &["grund.machine.v1.ManagementPoolService/RebuildPoolMachine"],
            &["grund operator pool rebuild MACHINE --yes"],
        )
    },
    write(
        "operator pool register",
        "grund.machine.v1.CreateRegistrationTokenResponse",
        &["grund.machine.v1.ManagementPoolService/CreateRegistrationToken"],
        &["grund operator pool register --name node-1"],
    ),
    write(
        "operator pool reregister",
        "grund.machine.v1.CreateReregistrationTokenResponse",
        &["grund.machine.v1.ManagementPoolService/CreateReregistrationToken"],
        &["grund operator pool reregister MACHINE"],
    ),
    read(
        "operator leases list",
        "grund.machine.v1.ListPoolMachinesResponse",
        &["grund.machine.v1.ManagementPoolService/ListPoolMachines"],
        &["grund operator leases list"],
    ),
    Leaf {
        output: "grund.machine.v1.EndLeaseResponse",
        ..destroy(
            "operator leases end",
            &["grund.machine.v1.ManagementPoolService/EndLease"],
            &["grund operator leases end MACHINE --yes"],
        )
    },
    read(
        "operator entitlements list",
        "grund.operator.v1.ListEntitlementsResponse",
        &["grund.operator.v1.OperatorService/ListEntitlements"],
        &["grund operator entitlements list"],
    ),
    write(
        "operator entitlements grant",
        "grund.operator.v1.SetHostedEntitlementResponse",
        &["grund.operator.v1.OperatorService/SetHostedEntitlement"],
        &["grund operator entitlements grant acme"],
    ),
    Leaf {
        output: "grund.operator.v1.SetHostedEntitlementResponse",
        ..destroy(
            "operator entitlements revoke",
            &["grund.operator.v1.OperatorService/SetHostedEntitlement"],
            &["grund operator entitlements revoke acme --yes"],
        )
    },
    read(
        "operator billing get",
        "grund.operator.v1.GetBillingAccountResponse",
        &["grund.operator.v1.OperatorService/GetBillingAccount"],
        &["grund operator billing get acme"],
    ),
    write(
        "operator billing grant",
        "grund.operator.v1.SetComplimentaryResponse",
        &["grund.operator.v1.OperatorService/SetComplimentary"],
        &[
            "grund operator billing grant acme --plan Pro --reason internal --expires-at 2027-01-01T00:00:00Z",
        ],
    ),
    Leaf {
        output: "grund.operator.v1.SetComplimentaryResponse",
        ..destroy(
            "operator billing revoke",
            &["grund.operator.v1.OperatorService/SetComplimentary"],
            &["grund operator billing revoke acme --reason expired --yes"],
        )
    },
    read(
        "describe",
        "",
        &[],
        &["grund describe --json", "grund describe apps deploy --json"],
    ),
    read(
        "schema",
        "",
        &[],
        &[
            "grund schema grund.yaml",
            "grund schema output apps status",
            "grund schema error",
        ],
    ),
    read("skill print", "", &[], &["grund skill print"]),
    write(
        "skill install",
        "grund.cli.v1.SkillInstalled",
        &[],
        &[
            "grund skill install",
            "grund skill install --dir .claude/skills",
        ],
    ),
    read("mcp", "", &[], &["claude mcp add grund -- grund mcp"]),
];

/// Procedures a user can reach through the dashboard's API that the CLI
/// deliberately does not call, each with why. The parity test fails on a
/// procedure that is in neither list.
pub const NOT_IN_CLI: &[(&str, &str)] = &[
    (
        "grund.volume.v1.VolumeService/GetVolume",
        "volumes show calls GetVolumeStatus, which includes the same volume fields and restore state",
    ),
    (
        "grund.machine.v1.MachineService/DeclareMachinePorts",
        "private-network ports are not in the dashboard either; later with network.md",
    ),
    (
        "grund.machine.v1.MachineService/GetOrganisationKey",
        "for machines and tooling, not people",
    ),
    (
        "grund.machine.v1.MachineService/RunVm",
        "VMs on machines: the dashboard's Run a virtual machine; a CLI noun when VMs leave preview",
    ),
    ("grund.machine.v1.MachineService/StopVm", "as RunVm"),
    ("grund.machine.v1.MachineService/ListVms", "as RunVm"),
];

/// The entry for a path.
pub fn leaf(path: &str) -> Option<&'static Leaf> {
    LEAVES.iter().find(|l| l.path == path)
}

/// Whether some client command calls `rpc`.
pub fn uses(rpc: &str) -> bool {
    LEAVES.iter().any(|l| l.rpcs.contains(&rpc))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn the_client_commands_are_a_consistent_clap_definition() {
        crate::Standalone::command().debug_assert();
    }

    #[test]
    fn every_client_command_has_one_entry() {
        let paths: Vec<String> = crate::describe::leaves(&crate::Standalone::command())
            .into_iter()
            .map(|(path, _, _)| path)
            .collect();
        for path in &paths {
            assert_eq!(
                LEAVES.iter().filter(|l| l.path == path).count(),
                1,
                "grund {path} needs exactly one entry in meta::LEAVES"
            );
        }
        for leaf in LEAVES {
            assert!(
                leaf.path.starts_with("operator ") || paths.iter().any(|p| p == leaf.path),
                "meta::LEAVES has {} which is no command",
                leaf.path
            );
            assert!(
                !leaf.examples.is_empty(),
                "grund {} has no example",
                leaf.path
            );
            assert!(!leaf.destructive || leaf.mutates, "{}", leaf.path);
        }
    }

    #[test]
    fn a_destructive_command_takes_yes_and_every_mutating_one_against_the_instance_takes_dry_run() {
        for (path, _, args) in crate::describe::leaves(&crate::Standalone::command()) {
            let leaf = leaf(&path).expect("checked above");
            let has = |id: &str| args.iter().any(|a| a.get_id() == id);
            if leaf.destructive {
                assert!(has("yes"), "grund {path} is destructive and takes no --yes");
            }
            if leaf.mutates
                && !leaf.rpcs.is_empty()
                && !matches!(
                    path.as_str(),
                    "login" | "logout" | "orgs use" | "domains verify"
                )
            {
                assert!(
                    has("dry_run"),
                    "grund {path} changes the instance and takes no --dry-run"
                );
            }
        }
    }
}
