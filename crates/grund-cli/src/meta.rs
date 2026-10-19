//! What clap cannot say about client commands: their protobuf JSON output,
//! procedures, mutations, and examples. Every runnable client leaf has one entry.

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

/// Every client command.
pub const LEAVES: &[Leaf] = &[
    with_stdin(
        write(
            "stack deploy",
            "grund.stack.v1.DeployStackResponse",
            &[
                "grund.stack.v1.StackService/PreviewStack",
                "grund.stack.v1.StackService/DeployStack",
                "grund.stack.v1.StackService/GetStack",
            ],
            &[
                "grund stack deploy -f grund.yaml --wait",
                "grund stack deploy -f grund.yaml --service web --dry-run",
                "grund stack deploy --secrets-stdin < protected-secrets.json",
            ],
        ),
        "with --secrets-stdin: a protected JSON object {service:{name:value}}; otherwise --secret SERVICE/NAME prompts without echo",
    ),
    read(
        "stack list",
        "grund.stack.v1.ListStacksResponse",
        &["grund.stack.v1.StackService/ListStacks"],
        &["grund stack list --page-size 50 --json"],
    ),
    read(
        "stack status",
        "grund.stack.v1.GetStackResponse",
        &["grund.stack.v1.StackService/GetStack"],
        &["grund stack status shop --json"],
    ),
    read(
        "stack logs",
        "grund.app.v1.ListAppLogsResponse",
        &[
            "grund.stack.v1.StackService/GetStack",
            "grund.app.v1.AppTelemetryService/ListAppLogs",
        ],
        &[
            "grund stack logs shop --service web --follow",
            "grund stack logs shop --service web --since 1h --instance-id INSTANCE --release 3 --search timeout --json",
        ],
    ),
    read(
        "stack metrics",
        "grund.app.v1.GetAppMetricsResponse",
        &[
            "grund.stack.v1.StackService/GetStack",
            "grund.app.v1.AppTelemetryService/GetAppMetrics",
        ],
        &["grund stack metrics shop --service postgres --range day"],
    ),
    write(
        "stack restart",
        "grund.stack.v1.RestartStackResponse",
        &[
            "grund.stack.v1.StackService/GetStack",
            "grund.stack.v1.StackService/RestartStack",
        ],
        &["grund stack restart shop --service web --wait"],
    ),
    write(
        "stack rollback",
        "grund.stack.v1.RollbackStackResponse",
        &[
            "grund.stack.v1.StackService/GetStack",
            "grund.stack.v1.StackService/RollbackStack",
        ],
        &["grund stack rollback shop --revision 2 --wait"],
    ),
    Leaf {
        output: "grund.stack.v1.DeleteStackResponse",
        ..destroy(
            "stack delete",
            &[
                "grund.stack.v1.StackService/GetStack",
                "grund.stack.v1.StackService/DeleteStack",
            ],
            &["grund stack delete shop --yes --wait"],
        )
    },
    write(
        "stack restore",
        "grund.stack.v1.RestoreStackResponse",
        &[
            "grund.stack.v1.StackService/GetStack",
            "grund.stack.v1.StackService/RestoreStack",
        ],
        &["grund stack restore shop --wait"],
    ),
    write(
        "join",
        "grund.cli.v1.HostInstallation",
        &[],
        &[
            "sudo grund join https://grund.example.com --code CODE",
            "sudo grund join https://grund.example.com --dry-run",
        ],
    ),
    Leaf {
        output: "grund.cli.v1.HostUninstallation",
        ..destroy(
            "leave",
            &[],
            &["sudo grund leave --dry-run", "sudo grund leave --yes"],
        )
    },
    Leaf {
        destructive: true,
        ..write(
            "update",
            "grund.cli.v1.HostUpdate",
            &[],
            &[
                "grund update --dry-run",
                "grund update --channel alpha --yes",
            ],
        )
    },
    read(
        "status",
        "grund.cli.v1.LocalStatus",
        &[],
        &["grund status", "sudo grund status --json"],
    ),
    read(
        "doctor",
        "grund.cli.v1.DoctorReport",
        &["grund.account.v1.AccountService/GetViewer"],
        &["grund doctor", "sudo grund doctor --json"],
    ),
    write(
        "server install",
        "grund.cli.v1.HostInstallation",
        &[],
        &[
            "sudo grund server install --domain grund.example.com",
            "sudo grund server install --dry-run",
        ],
    ),
    Leaf {
        destructive: true,
        ..write(
            "server update",
            "grund.cli.v1.HostUpdate",
            &[],
            &[
                "sudo grund server update --dry-run",
                "sudo grund server update --channel alpha --yes",
            ],
        )
    },
    Leaf {
        output: "grund.cli.v1.HostUninstallation",
        ..destroy(
            "server uninstall",
            &[],
            &[
                "sudo grund server uninstall --dry-run",
                "sudo grund server uninstall --yes",
            ],
        )
    },
    with_stdin(
        write(
            "auth login",
            "grund.cli.v1.LoginResult",
            &[
                "grund.login.v1.DeviceLoginService/StartDeviceLogin",
                "grund.login.v1.DeviceLoginService/PollDeviceLogin",
                "grund.account.v1.AccountService/GetViewer",
                "grund.token.v1.TokenService/GetCurrentToken",
            ],
            &[
                "grund auth login grund.example.com",
                "grund auth login grund.example.com --json   # prints the approval link as a JSON line on stderr",
                "printf %s \"$TOKEN\" | grund auth login grund.example.com --with-token",
            ],
        ),
        "with --with-token: a personal access token",
    ),
    write(
        "auth logout",
        "grund.cli.v1.Done",
        &[
            "grund.account.v1.AccountService/ListSessions",
            "grund.account.v1.AccountService/RevokeSession",
        ],
        &["grund auth logout"],
    ),
    read(
        "auth status",
        "grund.cli.v1.Whoami",
        &[
            "grund.account.v1.AccountService/GetViewer",
            "grund.organisation.v1.OrganisationService/ListOrganisations",
            "grund.token.v1.TokenService/GetCurrentToken",
        ],
        &["grund auth status --json"],
    ),
    read(
        "context list",
        "grund.cli.v1.ContextList",
        &[],
        &["grund context list", "grund context list --json"],
    ),
    write(
        "context use",
        "grund.cli.v1.Done",
        &[],
        &["grund context use hosted"],
    ),
    read(
        "context show",
        "grund.cli.v1.Context",
        &[],
        &["grund context show", "grund context show hosted --json"],
    ),
    write(
        "context rename",
        "grund.cli.v1.Done",
        &[],
        &["grund context rename grund.example.com home-lab"],
    ),
    destroy(
        "context remove",
        &[
            "grund.account.v1.AccountService/ListSessions",
            "grund.account.v1.AccountService/RevokeSession",
        ],
        &["grund context remove hosted --yes"],
    ),
    read(
        "org list",
        "grund.cli.v1.OrganisationList",
        &["grund.organisation.v1.OrganisationService/ListOrganisations"],
        &["grund org list --json"],
    ),
    read(
        "org show",
        "grund.organisation.v1.GetOrganisationResponse",
        &["grund.organisation.v1.OrganisationService/GetOrganisation"],
        &["grund org show acme"],
    ),
    write(
        "org use",
        "grund.cli.v1.Done",
        &["grund.organisation.v1.OrganisationService/GetOrganisation"],
        &["grund org use acme"],
    ),
    write(
        "org create",
        "grund.organisation.v1.CreateOrganisationResponse",
        &["grund.organisation.v1.OrganisationService/CreateOrganisation"],
        &["grund org create acme-staging"],
    ),
    write(
        "org rename",
        "grund.organisation.v1.RenameOrganisationResponse",
        &["grund.organisation.v1.OrganisationService/RenameOrganisation"],
        &["grund org rename acme acme-inc"],
    ),
    destroy(
        "org delete",
        &["grund.organisation.v1.OrganisationService/DeleteOrganisation"],
        &["grund org delete acme-staging --yes"],
    ),
    read(
        "app list",
        "grund.app.v1.ListAppsResponse",
        &["grund.app.v1.AppService/ListApps"],
        &["grund app list --json"],
    ),
    read(
        "app deleted",
        "grund.app.v1.ListRestorableAppsResponse",
        &["grund.app.v1.AppService/ListRestorableApps"],
        &["grund app deleted"],
    ),
    write(
        "app restore",
        "grund.app.v1.RestoreAppResponse",
        &["grund.app.v1.AppService/RestoreApp"],
        &["grund app restore web"],
    ),
    read(
        "app show",
        "grund.app.v1.GetAppResponse",
        &["grund.app.v1.AppService/GetApp"],
        &["grund app show web --json"],
    ),
    read(
        "app status",
        "grund.cli.v1.AppStatus",
        &["grund.app.v1.AppService/GetApp"],
        &["grund app status web --json | jq -r .health"],
    ),
    read(
        "app logs",
        "grund.app.v1.ListAppLogsResponse",
        &["grund.app.v1.AppTelemetryService/ListAppLogs"],
        &[
            "grund app logs web --since 1h --limit 200",
            "grund app logs web --follow --stream stderr",
            "grund app logs web --instance-id INSTANCE --release 3 --search timeout --json",
        ],
    ),
    read(
        "app metrics",
        "grund.app.v1.GetAppMetricsResponse",
        &["grund.app.v1.AppTelemetryService/GetAppMetrics"],
        &[
            "grund app metrics web --range hour",
            "grund app metrics web --range week --release 3 --json",
        ],
    ),
    write(
        "app updates",
        "grund.app.v1.GetAppUpdateResponse",
        &[
            "grund.app.v1.AppService/GetApp",
            "grund.app.v1.AppService/GetAppUpdate",
            "grund.app.v1.AppService/CheckAppUpdate",
        ],
        &[
            "grund app updates web",
            "grund app updates web --check --json",
        ],
    ),
    write(
        "app update",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/GetApp",
            "grund.app.v1.AppService/GetAppUpdate",
            "grund.app.v1.AppService/ApplyAppUpdate",
        ],
        &[
            "grund app update web --wait",
            "grund app update web --candidate nginx:1.27 --dry-run --json",
        ],
    ),
    read(
        "app history",
        "grund.app.v1.ListReleasesResponse",
        &["grund.app.v1.AppService/ListReleases"],
        &["grund app history web"],
    ),
    write(
        "app create",
        "grund.app.v1.CreateAppResponse",
        &["grund.app.v1.AppService/CreateApp"],
        &["grund app create web --copies 2"],
    ),
    write(
        "app deploy",
        "grund.cli.v1.DeployResult",
        &[
            "grund.app.v1.AppService/GetApp",
            "grund.app.v1.AppService/ListApps",
            "grund.app.v1.AppService/CreateApp",
            "grund.app.v1.AppService/Scale",
            "grund.app.v1.AppService/Deploy",
            "grund.app.v1.AppService/PreviewDeploy",
            "grund.app.v1.AppService/ListReleases",
        ],
        &[
            "grund app deploy -f grund.yaml --wait --json",
            "grund app deploy web --image nginx:1.27 --port http=80 --public http --wait",
            "grund app deploy web -f grund.yaml --dry-run --json",
        ],
    ),
    write(
        "app set image",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund app set web image nginx:1.27 --wait"],
    ),
    write(
        "app set env",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund app set web env LOG_LEVEL=debug --unset OLD_FLAG"],
    ),
    write(
        "app set secret-env",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund app set web secret-env DATABASE_URL=database-url"],
    ),
    write(
        "app set ports",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund app set web ports http=8080 metrics=9090/http --public http"],
    ),
    write(
        "app set check",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund app set web check --http /healthz"],
    ),
    write(
        "app set resources",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund app set web resources --memory-mib 1024 --cpu 0.5"],
    ),
    write(
        "app set command",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/Deploy",
        ],
        &["grund app set web command -- ./server --port 8080"],
    ),
    write(
        "app set copies",
        "grund.app.v1.ScaleResponse",
        &[
            "grund.app.v1.AppService/GetApp",
            "grund.app.v1.AppService/Scale",
        ],
        &["grund app set web copies 3"],
    ),
    write(
        "app set placement",
        "grund.app.v1.ConfigureAppResponse",
        &[
            "grund.app.v1.AppService/GetApp",
            "grund.app.v1.AppService/ConfigureApp",
        ],
        &["grund app set web placement --label zone=eu --spread-by zone"],
    ),
    write(
        "app set auto-rollback",
        "grund.app.v1.ConfigureAppResponse",
        &[
            "grund.app.v1.AppService/GetApp",
            "grund.app.v1.AppService/ConfigureApp",
        ],
        &["grund app set web auto-rollback off"],
    ),
    write(
        "app rollback",
        "grund.cli.v1.AppDeploy",
        &[
            "grund.app.v1.AppService/Rollback",
            "grund.app.v1.AppService/ListReleases",
            "grund.app.v1.AppService/GetApp",
        ],
        &["grund app rollback web 3 --wait --json"],
    ),
    destroy(
        "app delete",
        &["grund.app.v1.AppService/DeleteApp"],
        &["grund app delete web --yes"],
    ),
    read(
        "app secret list",
        "grund.cli.v1.SecretList",
        &["grund.app.v1.AppService/GetApp"],
        &["grund app secret list web"],
    ),
    with_stdin(
        write(
            "app secret set",
            "grund.app.v1.SetSecretResponse",
            &["grund.app.v1.AppService/SetSecret"],
            &["printf %s \"$DATABASE_URL\" | grund app secret set web database-url"],
        ),
        "the secret's value; one final newline is dropped",
    ),
    read(
        "volume list",
        "grund.volume.v1.ListVolumesResponse",
        &["grund.volume.v1.VolumeService/ListVolumes"],
        &["grund volume list photos"],
    ),
    read(
        "volume show",
        "grund.volume.v1.GetVolumeStatusResponse",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/GetVolumeStatus",
        ],
        &["grund volume show photos data"],
    ),
    write(
        "volume create",
        "grund.volume.v1.CreateVolumeResponse",
        &["grund.volume.v1.VolumeService/CreateVolume"],
        &["grund volume create photos data --path /data --backup"],
    ),
    write(
        "volume attach",
        "grund.volume.v1.AttachVolumeResponse",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/AttachVolume",
        ],
        &["grund volume attach photos data 00000000-0000-0000-0000-000000000000"],
    ),
    write(
        "volume detach",
        "grund.volume.v1.DetachVolumeResponse",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/DetachVolume",
        ],
        &["grund volume detach photos data"],
    ),
    Leaf {
        destructive: true,
        ..write(
            "volume delete",
            "grund.volume.v1.Volume",
            &[
                "grund.volume.v1.VolumeService/ListVolumes",
                "grund.volume.v1.VolumeService/DeleteVolume",
            ],
            &["grund volume delete photos data --yes"],
        )
    },
    Leaf {
        destructive: true,
        ..write(
            "volume accept-empty",
            "grund.volume.v1.Volume",
            &[
                "grund.volume.v1.VolumeService/ListVolumes",
                "grund.volume.v1.VolumeService/AcceptEmptyLostVolume",
            ],
            &["grund volume accept-empty photos data --yes"],
        )
    },
    write(
        "volume undelete",
        "grund.volume.v1.Volume",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/RestoreVolume",
        ],
        &["grund volume undelete photos data"],
    ),
    Leaf {
        destructive: true,
        ..write(
            "volume purge",
            "grund.volume.v1.Volume",
            &[
                "grund.volume.v1.VolumeService/ListVolumes",
                "grund.volume.v1.VolumeService/PurgeVolumeNow",
            ],
            &["grund volume purge photos data --reason 'owned synthetic app cleanup' --yes"],
        )
    },
    read(
        "volume backups status",
        "grund.volume.v1.GetBackupDestinationResponse",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/GetBackupDestination",
        ],
        &["grund volume backups photos data status"],
    ),
    with_stdin(
        write(
            "volume backups set",
            "grund.volume.v1.SetBackupDestinationResponse",
            &[
                "grund.volume.v1.VolumeService/ListVolumes",
                "grund.volume.v1.VolumeService/GetBackupDestination",
                "grund.volume.v1.VolumeService/SetBackupDestination",
            ],
            &[
                "grund volume backups photos data set --endpoint https://s3.example.com --bucket photos-backup --access-key-id KEY",
            ],
        ),
        "the S3 secret access key; one final newline is dropped",
    ),
    read(
        "volume backups points",
        "grund.volume.v1.ListRecoveryPointsResponse",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/ListRecoveryPoints",
        ],
        &["grund volume backups photos data points"],
    ),
    destroy(
        "volume backups export-key",
        &[
            "grund.volume.v1.VolumeService/ListVolumes",
            "grund.volume.v1.VolumeService/ExportBackupKey",
        ],
        &["grund volume backups photos data export-key --file ./photos-backup-key --yes"],
    ),
    Leaf {
        destructive: true,
        ..write(
            "volume restore",
            "grund.volume.v1.RestoreRecoveryPointResponse",
            &[
                "grund.volume.v1.VolumeService/ListVolumes",
                "grund.volume.v1.VolumeService/RestoreRecoveryPoint",
            ],
            &[
                "grund volume restore photos data SNAPSHOT --name recovered --path /recovered --machine MACHINE --yes",
            ],
        )
    },
    read(
        "machine list",
        "grund.machine.v1.ListMachinesResponse",
        &["grund.machine.v1.MachineService/ListMachines"],
        &["grund machine list --json"],
    ),
    read(
        "machine offers",
        "grund.machine.v1.ListHostedOffersResponse",
        &["grund.machine.v1.HostedMachineService/ListHostedOffers"],
        &["grund machine offers"],
    ),
    read(
        "machine show",
        "grund.machine.v1.GetMachineResponse",
        &[
            "grund.machine.v1.MachineService/ListMachines",
            "grund.machine.v1.MachineService/GetMachine",
        ],
        &["grund machine show web-1"],
    ),
    write(
        "machine add",
        "grund.cli.v1.MachineAdded",
        &[
            "grund.machine.v1.MachineService/CreateJoinToken",
            "grund.machine.v1.HostedMachineService/CreateHostedMachine",
        ],
        &[
            "grund machine add web-2",
            "grund machine add web-2 --hosted --size small",
        ],
    ),
    write(
        "machine label",
        "grund.machine.v1.SetMachineLabelsResponse",
        &[
            "grund.machine.v1.MachineService/ListMachines",
            "grund.machine.v1.MachineService/SetMachineLabels",
        ],
        &[
            "grund machine label web-1 zone=eu disk=ssd",
            "grund machine label web-1",
        ],
    ),
    write(
        "machine drain",
        "grund.machine.v1.SetMachineInServiceResponse",
        &[
            "grund.machine.v1.MachineService/ListMachines",
            "grund.machine.v1.MachineService/SetMachineInService",
        ],
        &["grund machine drain web-1"],
    ),
    write(
        "machine undrain",
        "grund.machine.v1.SetMachineInServiceResponse",
        &[
            "grund.machine.v1.MachineService/ListMachines",
            "grund.machine.v1.MachineService/SetMachineInService",
        ],
        &["grund machine undrain web-1"],
    ),
    destroy(
        "machine remove",
        &[
            "grund.machine.v1.MachineService/ListMachines",
            "grund.machine.v1.MachineService/RevokeMachine",
            "grund.machine.v1.HostedMachineService/RemoveHostedMachine",
        ],
        &["grund machine remove web-1 --yes"],
    ),
    read(
        "domain",
        "grund.domain.v1.ListDomainsResponse",
        &["grund.domain.v1.DomainService/ListDomains"],
        &["grund domain", "grund domain --details"],
    ),
    read(
        "domain list",
        "grund.domain.v1.ListDomainsResponse",
        &["grund.domain.v1.DomainService/ListDomains"],
        &["grund domain list", "grund domain list --details"],
    ),
    read(
        "domain show",
        "grund.domain.v1.GetDomainResponse",
        &["grund.domain.v1.DomainService/GetDomain"],
        &[
            "grund domain show shop.example.com --json",
            "grund domain show shop.example.com --details",
        ],
    ),
    write(
        "domain add",
        "grund.domain.v1.AddDomainResponse",
        &["grund.domain.v1.DomainService/AddDomain"],
        &["grund domain add shop.example.com --json | jq -r .domain.verificationRecordValue"],
    ),
    write(
        "domain verify",
        "grund.domain.v1.VerifyDomainResponse",
        &["grund.domain.v1.DomainService/VerifyDomain"],
        &["grund domain verify shop.example.com"],
    ),
    write(
        "domain check",
        "grund.domain.v1.CheckDomainResponse",
        &["grund.domain.v1.DomainService/CheckDomain"],
        &["grund domain check shop.example.com"],
    ),
    write(
        "domain bind",
        "grund.domain.v1.BindDomainResponse",
        &["grund.domain.v1.DomainService/BindDomain"],
        &["grund domain bind shop.example.com web"],
    ),
    write(
        "domain unbind",
        "grund.domain.v1.UnbindDomainResponse",
        &["grund.domain.v1.DomainService/UnbindDomain"],
        &["grund domain unbind shop.example.com"],
    ),
    write(
        "domain app-domain",
        "grund.domain.v1.ConfigureAppDomainResponse",
        &["grund.domain.v1.DomainService/ConfigureAppDomain"],
        &["grund domain app-domain example.com"],
    ),
    write(
        "domain subdomain",
        "grund.domain.v1.SetAppSubdomainResponse",
        &["grund.domain.v1.DomainService/SetAppSubdomain"],
        &[
            "grund domain subdomain web www",
            "grund domain subdomain web",
        ],
    ),
    destroy(
        "domain remove",
        &["grund.domain.v1.DomainService/RemoveDomain"],
        &["grund domain remove shop.example.com --yes"],
    ),
    read(
        "member list",
        "grund.organisation.v1.ListMembersResponse",
        &["grund.organisation.v1.OrganisationService/ListMembers"],
        &["grund member list"],
    ),
    write(
        "member invite",
        "grund.cli.v1.Done",
        &["grund.organisation.v1.OrganisationService/InviteMember"],
        &["grund member invite ana@example.com --role admin"],
    ),
    write(
        "member role",
        "grund.cli.v1.Done",
        &[
            "grund.organisation.v1.OrganisationService/ListMembers",
            "grund.organisation.v1.OrganisationService/ChangeMemberRole",
        ],
        &["grund member role ana admin"],
    ),
    destroy(
        "member remove",
        &[
            "grund.organisation.v1.OrganisationService/ListMembers",
            "grund.organisation.v1.OrganisationService/RemoveMember",
        ],
        &["grund member remove ana --yes"],
    ),
    read(
        "member invitations",
        "grund.organisation.v1.ListInvitationsResponse",
        &["grund.organisation.v1.OrganisationService/ListInvitations"],
        &["grund member invitations"],
    ),
    destroy(
        "member revoke",
        &[
            "grund.organisation.v1.OrganisationService/ListInvitations",
            "grund.organisation.v1.OrganisationService/RevokeInvitation",
        ],
        &["grund member revoke ana@example.com --yes"],
    ),
    read(
        "notification",
        "grund.notification.v1.ListNotificationsResponse",
        &["grund.notification.v1.NotificationService/ListNotifications"],
        &[
            "grund notification --json",
            "grund notification --unread --page-size 100",
        ],
    ),
    read(
        "notification count",
        "grund.notification.v1.CountUnreadResponse",
        &["grund.notification.v1.NotificationService/CountUnread"],
        &["grund notification count"],
    ),
    write(
        "notification read",
        "grund.cli.v1.Done",
        &[
            "grund.notification.v1.NotificationService/MarkRead",
            "grund.notification.v1.NotificationService/MarkAllRead",
        ],
        &[
            "grund notification read 0199a9b5-bcdf-7338-9a92-b6f536b9ca9b",
            "grund notification read --all",
        ],
    ),
    read(
        "auth token list",
        "grund.token.v1.ListTokensResponse",
        &["grund.token.v1.TokenService/ListTokens"],
        &["grund auth token list"],
    ),
    write(
        "auth token create",
        "grund.token.v1.CreateTokenResponse",
        &["grund.token.v1.TokenService/CreateToken"],
        &[
            "grund auth token create --name ci-deploy --apps shop,worker --days 90",
            "grund auth token create --name agent --scope full --json | jq -r .secret",
        ],
    ),
    destroy(
        "auth token revoke",
        &[
            "grund.token.v1.TokenService/ListTokens",
            "grund.token.v1.TokenService/RevokeToken",
        ],
        &["grund auth token revoke ci-deploy --yes"],
    ),
    read(
        "registry list",
        "grund.registry.v1.ListRegistryLoginsResponse",
        &["grund.registry.v1.RegistryService/ListRegistryLogins"],
        &["grund registry list"],
    ),
    with_stdin(
        write(
            "registry set",
            "grund.registry.v1.SetRegistryLoginResponse",
            &["grund.registry.v1.RegistryService/SetRegistryLogin"],
            &["printf %s \"$GHCR_TOKEN\" | grund registry set ghcr.io --username acme-bot"],
        ),
        "the password or access token",
    ),
    destroy(
        "registry remove",
        &["grund.registry.v1.RegistryService/RemoveRegistryLogin"],
        &["grund registry remove ghcr.io --yes"],
    ),
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
                paths.iter().any(|p| p == leaf.path),
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
                    "auth login"
                        | "auth logout"
                        | "context remove"
                        | "org use"
                        | "domain verify"
                        | "domain check"
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
